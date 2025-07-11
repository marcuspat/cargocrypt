//! Git repository management for CargoCrypt
//! 
//! This module provides the GitRepo struct which handles all git repository
//! operations including initialization, file staging, and CargoCrypt configuration.

use super::{GitError, GitResult};
use git2::{Repository, Index, IndexAddOption, Status, StatusOptions, Signature, Oid, ObjectType};
use std::path::{Path, PathBuf};
use tokio::fs;
use thiserror::Error;

/// Errors specific to GitRepo operations
#[derive(Error, Debug)]
pub enum GitRepoError {
    #[error("Repository operation failed: {0}")]
    Operation(#[from] git2::Error),
    
    #[error("File system operation failed: {0}")]
    FileSystem(#[from] std::io::Error),
    
    #[error("Path does not exist: {}", .0.display())]
    PathNotFound(PathBuf),
    
    #[error("Invalid repository state: {0}")]
    InvalidState(String),
}

pub type GitRepoResult<T> = Result<T, GitRepoError>;

/// Git repository wrapper with CargoCrypt-specific functionality
#[derive(Debug)]
pub struct GitRepo {
    repo: Repository,
    workdir: PathBuf,
}

impl GitRepo {
    /// Open an existing git repository
    pub fn open<P: AsRef<Path>>(path: P) -> GitRepoResult<Self> {
        let repo = Repository::open(path)?;
        let workdir = repo.workdir()
            .ok_or_else(|| GitRepoError::InvalidState("Bare repository not supported".to_string()))?
            .to_path_buf();
        
        Ok(Self { repo, workdir })
    }
    
    /// Create a new git repository
    pub fn init<P: AsRef<Path>>(path: P) -> GitRepoResult<Self> {
        let repo = Repository::init(path)?;
        let workdir = repo.workdir()
            .ok_or_else(|| GitRepoError::InvalidState("Failed to get workdir".to_string()))?
            .to_path_buf();
        
        Ok(Self { repo, workdir })
    }
    
    /// Find existing repository or create a new one
    pub async fn find_or_create() -> GitRepoResult<Self> {
        Self::find_or_create_in(".").await
    }
    
    /// Find existing repository or create a new one in the specified directory
    pub async fn find_or_create_in<P: AsRef<Path>>(path: P) -> GitRepoResult<Self> {
        let path = path.as_ref();
        
        // Try to discover existing repository
        match Repository::discover(path) {
            Ok(repo) => {
                let workdir = repo.workdir()
                    .ok_or_else(|| GitRepoError::InvalidState("Bare repository not supported".to_string()))?
                    .to_path_buf();
                Ok(Self { repo, workdir })
            }
            Err(_) => {
                // Create new repository
                Self::init(path)
            }
        }
    }
    
    /// Open existing repository or create new one
    pub async fn open_or_create<P: AsRef<Path>>(path: P) -> GitRepoResult<Self> {
        let path = path.as_ref();
        
        match Self::open(path) {
            Ok(repo) => Ok(repo),
            Err(_) => Self::init(path),
        }
    }
    
    /// Get the repository path
    pub fn path(&self) -> &Path {
        self.repo.path()
    }
    
    /// Get the working directory path
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }
    
    /// Get the .git directory path
    pub fn git_dir(&self) -> &Path {
        self.repo.path()
    }
    
    /// Check if CargoCrypt configuration exists
    pub fn has_cargocrypt_config(&self) -> bool {
        self.workdir.join(".cargocrypt").exists() ||
        self.workdir.join("Cargo.toml").exists() // Check if it's a Rust project
    }
    
    /// Stage a file for commit
    pub async fn stage_file<P: AsRef<Path>>(&self, path: P) -> GitRepoResult<()> {
        let path = path.as_ref();
        let relative_path = self.make_relative_path(path)?;
        
        let mut index = self.repo.index()?;
        index.add_path(&relative_path)?;
        index.write()?;
        
        Ok(())
    }
    
    /// Unstage a file
    pub async fn unstage_file<P: AsRef<Path>>(&self, path: P) -> GitRepoResult<()> {
        let path = path.as_ref();
        let relative_path = self.make_relative_path(path)?;
        
        // Reset the file to HEAD
        let head = self.repo.head()?.target().unwrap();
        let head_commit = self.repo.find_commit(head)?;
        let head_tree = head_commit.tree()?;
        
        let mut index = self.repo.index()?;
        
        // Check if file exists in HEAD
        match head_tree.get_path(&relative_path) {
            Ok(entry) => {
                // File exists in HEAD, reset to that version
                let object = self.repo.find_object(entry.id(), Some(ObjectType::Blob))?;
                index.add_frombuffer(&relative_path, object.as_blob().unwrap().content())?;
            }
            Err(_) => {
                // File doesn't exist in HEAD, remove from index
                index.remove_path(&relative_path)?;
            }
        }
        
        index.write()?;
        Ok(())
    }
    
    /// Check if a file is staged
    pub async fn is_staged<P: AsRef<Path>>(&self, path: P) -> GitRepoResult<bool> {
        let path = path.as_ref();
        let relative_path = self.make_relative_path(path)?;
        
        let statuses = self.repo.statuses(None)?;
        
        for entry in statuses.iter() {
            if entry.path() == Some(relative_path.to_str().unwrap()) {
                return Ok(entry.status().intersects(
                    Status::INDEX_NEW | Status::INDEX_MODIFIED | Status::INDEX_DELETED
                ));
            }
        }
        
        Ok(false)
    }
    
    /// Get file status
    pub async fn file_status<P: AsRef<Path>>(&self, path: P) -> GitRepoResult<Status> {
        let path = path.as_ref();
        let relative_path = self.make_relative_path(path)?;
        
        Ok(self.repo.status_file(&relative_path)?)
    }
    
    /// Check if the repository is clean (no uncommitted changes)
    pub fn is_clean(&self) -> GitRepoResult<bool> {
        let statuses = self.repo.statuses(None)?;
        Ok(statuses.is_empty())
    }
    
    /// Get list of modified files
    pub fn get_modified_files(&self) -> GitRepoResult<Vec<PathBuf>> {
        let mut modified = Vec::new();
        let statuses = self.repo.statuses(None)?;
        
        for entry in statuses.iter() {
            if let Some(path) = entry.path() {
                if entry.status().intersects(
                    Status::WT_MODIFIED | Status::WT_NEW | Status::WT_DELETED |
                    Status::INDEX_MODIFIED | Status::INDEX_NEW | Status::INDEX_DELETED
                ) {
                    modified.push(PathBuf::from(path));
                }
            }
        }
        
        Ok(modified)
    }
    
    /// Create a commit with the staged changes
    pub async fn commit(&self, message: &str) -> GitRepoResult<Oid> {
        let signature = self.get_signature()?;
        let mut index = self.repo.index()?;
        let tree_id = index.write_tree()?;
        let tree = self.repo.find_tree(tree_id)?;
        
        // Get parent commit if it exists
        let parent_commit = match self.repo.head() {
            Ok(head) => Some(self.repo.find_commit(head.target().unwrap())?),
            Err(_) => None, // First commit
        };
        
        let parents: Vec<&git2::Commit> = parent_commit.iter().collect();
        
        let commit_id = self.repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            message,
            &tree,
            &parents,
        )?;
        
        Ok(commit_id)
    }
    
    /// Add all CargoCrypt-related files and commit
    pub async fn commit_cargocrypt_setup(&self) -> GitRepoResult<Oid> {
        // Stage CargoCrypt configuration files
        let config_files = [
            ".gitignore",
            ".gitattributes",
            ".cargocrypt/config.toml",
            ".githooks/pre-commit",
            ".githooks/pre-push",
        ];
        
        for file in &config_files {
            let path = self.workdir.join(file);
            if path.exists() {
                self.stage_file(&path).await?;
            }
        }
        
        self.commit("feat: Initialize CargoCrypt git integration\n\n- Add .gitignore patterns for encrypted files\n- Configure git attributes for automatic encryption\n- Install git hooks for secret detection\n- Set up encrypted storage and team key sharing").await
    }
    
    /// Get git signature for commits
    fn get_signature(&self) -> GitRepoResult<Signature> {
        // Try to get from git config first
        self.repo.signature()
            .or_else(|_| {
                // Fallback to CargoCrypt defaults
                Signature::now("CargoCrypt", "cargocrypt@localhost")
            })
            .map_err(GitRepoError::Operation)
    }
    
    /// Convert absolute path to relative path from repository root
    fn make_relative_path<P: AsRef<Path>>(&self, path: P) -> GitRepoResult<PathBuf> {
        let path = path.as_ref();
        
        if path.is_absolute() {
            path.strip_prefix(&self.workdir)
                .map(|p| p.to_path_buf())
                .map_err(|_| GitRepoError::InvalidState(
                    format!("Path {} is not within repository", path.display())
                ))
        } else {
            Ok(path.to_path_buf())
        }
    }
    
    /// Create a branch for CargoCrypt operations
    pub async fn create_cargocrypt_branch(&self, branch_name: &str) -> GitRepoResult<()> {
        let head = self.repo.head()?;
        let head_commit = self.repo.find_commit(head.target().unwrap())?;
        
        self.repo.branch(branch_name, &head_commit, false)?;
        Ok(())
    }
    
    /// Switch to a branch
    pub async fn checkout_branch(&self, branch_name: &str) -> GitRepoResult<()> {
        let (object, reference) = self.repo.revparse_ext(branch_name)?;
        
        self.repo.checkout_tree(&object, None)?;
        
        match reference {
            Some(gref) => self.repo.set_head(gref.name().unwrap()),
            None => self.repo.set_head_detached(object.id()),
        }?;
        
        Ok(())
    }
    
    /// Get current branch name
    pub fn current_branch(&self) -> GitRepoResult<String> {
        let head = self.repo.head()?;
        
        if let Some(name) = head.shorthand() {
            Ok(name.to_string())
        } else {
            Ok("HEAD".to_string()) // Detached HEAD
        }
    }
    
    /// Check if working directory is dirty
    pub fn is_dirty(&self) -> GitRepoResult<bool> {
        let mut opts = StatusOptions::new();
        opts.include_untracked(true);
        
        let statuses = self.repo.statuses(Some(&mut opts))?;
        Ok(!statuses.is_empty())
    }
    
    /// Get the underlying git2::Repository
    pub fn inner(&self) -> &Repository {
        &self.repo
    }
    
    /// Initialize .cargocrypt directory structure
    pub async fn init_cargocrypt_structure(&self) -> GitRepoResult<()> {
        let base_dir = self.workdir.join(".cargocrypt");
        
        // Create directory structure
        fs::create_dir_all(&base_dir).await?;
        fs::create_dir_all(base_dir.join("keys")).await?;
        fs::create_dir_all(base_dir.join("team")).await?;
        fs::create_dir_all(base_dir.join("hooks")).await?;
        
        // Create basic config file
        let config_content = r#"# CargoCrypt Configuration
[encryption]
algorithm = "ChaCha20-Poly1305"
key_derivation = "Argon2id"

[git]
auto_encrypt_patterns = ["*.secret", "*.key", "secrets/*"]
ignore_patterns = ["*.cargocrypt", "*.enc"]

[team]
key_sharing_enabled = true
require_signature = true

[hooks]
pre_commit_secret_detection = true
pre_push_validation = true
"#;
        
        fs::write(base_dir.join("config.toml"), config_content).await?;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_git_repo_creation() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        
        assert!(repo.path().exists());
        assert!(repo.workdir().exists());
    }
    
    #[tokio::test]
    async fn test_find_or_create() {
        let temp_dir = TempDir::new().unwrap();
        
        // Should create new repo
        let repo1 = GitRepo::find_or_create_in(temp_dir.path()).await.unwrap();
        assert!(repo1.path().exists());
        
        // Should find existing repo
        let repo2 = GitRepo::find_or_create_in(temp_dir.path()).await.unwrap();
        assert_eq!(repo1.path(), repo2.path());
    }
    
    #[tokio::test]
    async fn test_file_staging() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        
        // Create a test file
        let test_file = temp_dir.path().join("test.txt");
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "test content").unwrap();
        
        // Stage the file
        repo.stage_file(&test_file).await.unwrap();
        
        // Check if staged
        assert!(repo.is_staged(&test_file).await.unwrap());
    }
    
    #[tokio::test]
    async fn test_cargocrypt_structure_init() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        
        repo.init_cargocrypt_structure().await.unwrap();
        
        let cargocrypt_dir = temp_dir.path().join(".cargocrypt");
        assert!(cargocrypt_dir.exists());
        assert!(cargocrypt_dir.join("config.toml").exists());
        assert!(cargocrypt_dir.join("keys").exists());
        assert!(cargocrypt_dir.join("team").exists());
    }
    
    #[tokio::test]
    async fn test_commit_creation() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        
        // Create and stage a file
        let test_file = temp_dir.path().join("test.txt");
        let mut file = File::create(&test_file).unwrap();
        writeln!(file, "test content").unwrap();
        
        repo.stage_file(&test_file).await.unwrap();
        
        // Create commit
        let commit_id = repo.commit("Initial commit").await.unwrap();
        assert!(!commit_id.is_zero());
    }
}