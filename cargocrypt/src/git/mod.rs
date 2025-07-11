//! Git-native integration for CargoCrypt
//! 
//! This module provides seamless integration with Git repositories, enabling:
//! - Automatic .gitignore management for encrypted files
//! - Encrypted blob storage within Git repositories
//! - Team key sharing via Git refs
//! - Git hooks for automatic secret detection
//! - Git attributes for automatic encryption patterns
//! 
//! The design follows git-native patterns that feel natural to developers.

pub mod repo;
pub mod hooks;
pub mod attributes;
pub mod storage;
pub mod team;
pub mod ignore;
pub mod config;

pub use repo::{GitRepo, GitRepoError, GitRepoResult};
pub use hooks::{GitHooks, HookType, HookConfig, SecretDetectionHook};
pub use attributes::{GitAttributes, EncryptionPattern, AttributeConfig};
pub use storage::{EncryptedStorage, GitObjectStorage, StorageRef};
pub use team::{TeamKeySharing, TeamMember, KeyShareConfig};
pub use ignore::{GitIgnoreManager, IgnorePattern, IgnoreConfig};
pub use config::{GitCryptConfig, RepositorySetup, IntegrationMode};

use crate::crypto::{CryptoEngine, CryptoResult, EncryptedSecret};
use crate::error::CargoCryptError;
use git2::{Repository, Signature, ObjectType, Oid};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors specific to Git operations
#[derive(Error, Debug)]
pub enum GitError {
    #[error("Git repository error: {0}")]
    Repository(#[from] git2::Error),
    
    #[error("Not a git repository or no git repository found in parent directories")]
    NotGitRepository,
    
    #[error("Failed to initialize git repository: {0}")]
    InitializationFailed(String),
    
    #[error("Git hook operation failed: {0}")]
    HookFailed(String),
    
    #[error("Git attributes configuration failed: {0}")]
    AttributesFailed(String),
    
    #[error("Team key sharing failed: {0}")]
    TeamSharingFailed(String),
    
    #[error("Encrypted storage operation failed: {0}")]
    StorageFailed(String),
    
    #[error("Invalid git object: {0}")]
    InvalidObject(String),
    
    #[error("Crypto operation failed: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),
    
    #[error("IO operation failed: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    
    #[error("Git repo operation failed: {0}")]
    Repo(#[from] GitRepoError),
}

pub type GitResult<T> = Result<T, GitError>;

/// Git integration manager - the main entry point for all git-native operations
pub struct GitIntegration {
    repo: GitRepo,
    crypto: CryptoEngine,
    config: GitCryptConfig,
}

impl GitIntegration {
    /// Initialize git integration in the current directory
    pub async fn new() -> GitResult<Self> {
        let repo = GitRepo::find_or_create().await?;
        let crypto = CryptoEngine::new();
        let config = GitCryptConfig::load_or_default(&repo).await?;
        
        Ok(Self {
            repo,
            crypto,
            config,
        })
    }
    
    /// Initialize git integration in a specific directory
    pub async fn new_in_dir<P: AsRef<Path>>(path: P) -> GitResult<Self> {
        let repo = GitRepo::open_or_create(path).await?;
        let crypto = CryptoEngine::new();
        let config = GitCryptConfig::load_or_default(&repo).await?;
        
        Ok(Self {
            repo,
            crypto,
            config,
        })
    }
    
    /// Set up CargoCrypt integration in the repository
    /// This is the equivalent of `cargo crypt init --git`
    pub async fn setup_repository(&mut self) -> GitResult<()> {
        // 1. Configure .gitignore for encrypted files
        self.setup_gitignore().await?;
        
        // 2. Set up git attributes for automatic encryption
        self.setup_attributes().await?;
        
        // 3. Install git hooks for secret detection
        self.setup_hooks().await?;
        
        // 4. Initialize encrypted storage
        self.setup_storage().await?;
        
        // 5. Configure team key sharing
        self.setup_team_sharing().await?;
        
        Ok(())
    }
    
    /// Configure .gitignore to exclude encrypted files and include necessary patterns
    async fn setup_gitignore(&self) -> GitResult<()> {
        let mut ignore_manager = GitIgnoreManager::new(&self.repo)?;
        
        // Add CargoCrypt patterns
        ignore_manager.add_pattern("*.cargocrypt").await?;
        ignore_manager.add_pattern("*.enc").await?;
        ignore_manager.add_pattern(".cargocrypt/").await?;
        ignore_manager.add_pattern("!.cargocrypt/config.toml").await?; // Include config
        ignore_manager.add_pattern("!.cargocrypt/team/").await?; // Include team keys
        
        ignore_manager.save().await?;
        Ok(())
    }
    
    /// Set up git attributes for automatic encryption patterns
    async fn setup_attributes(&self) -> GitResult<()> {
        let mut attributes = GitAttributes::new(&self.repo)?;
        
        // Add default encryption patterns
        attributes.add_pattern("*.secret", "cargocrypt-encrypt").await?;
        attributes.add_pattern("*.key", "cargocrypt-encrypt").await?;
        attributes.add_pattern("secrets/*", "cargocrypt-encrypt").await?;
        attributes.add_pattern("config/secrets.*", "cargocrypt-encrypt").await?;
        
        // Add clean/smudge filters for automatic encryption/decryption
        attributes.configure_filters(&self.config).await?;
        
        attributes.save().await?;
        Ok(())
    }
    
    /// Install git hooks for automatic secret detection
    async fn setup_hooks(&self) -> GitResult<()> {
        let hooks = GitHooks::new(&self.repo)?;
        
        // Pre-commit hook for secret detection
        let detection_hook = SecretDetectionHook::new(&self.crypto)?;
        hooks.install_hook(HookType::PreCommit, Box::new(detection_hook)).await?;
        
        // Pre-push hook for encrypted file validation
        hooks.install_encryption_validation_hook().await?;
        
        Ok(())
    }
    
    /// Initialize encrypted storage system in git
    async fn setup_storage(&self) -> GitResult<()> {
        let storage = EncryptedStorage::new(&self.repo, &self.crypto)?;
        storage.initialize().await?;
        
        Ok(())
    }
    
    /// Set up team key sharing via git refs
    async fn setup_team_sharing(&self) -> GitResult<()> {
        let team_sharing = TeamKeySharing::new(&self.repo, &self.crypto)?;
        team_sharing.initialize().await?;
        
        Ok(())
    }
    
    /// Check if the repository is properly configured for CargoCrypt
    pub async fn is_configured(&self) -> bool {
        self.repo.has_cargocrypt_config() &&
        self.has_gitignore_patterns().await &&
        self.has_git_attributes().await &&
        self.has_git_hooks().await
    }
    
    async fn has_gitignore_patterns(&self) -> bool {
        GitIgnoreManager::new(&self.repo)
            .map(|manager| manager.has_cargocrypt_patterns())
            .unwrap_or(false)
    }
    
    async fn has_git_attributes(&self) -> bool {
        GitAttributes::new(&self.repo)
            .map(|attrs| attrs.has_cargocrypt_patterns())
            .unwrap_or(false)
    }
    
    async fn has_git_hooks(&self) -> bool {
        GitHooks::new(&self.repo)
            .map(|hooks| hooks.are_installed())
            .unwrap_or(false)
    }
    
    /// Encrypt a file and store it in git with proper patterns
    pub async fn encrypt_and_stage<P: AsRef<Path>>(&self, path: P, password: &str) -> GitResult<PathBuf> {
        let path = path.as_ref();
        
        // Read the file content
        let content = tokio::fs::read(path).await
            .map_err(|e| GitError::Io(e))?;
        
        // Encrypt the data
        let encrypted = self.crypto.encrypt_data(&content, password)
            .map_err(GitError::Crypto)?;
        
        // Create encrypted file path
        let encrypted_path = path.with_extension(format!("{}.enc", 
            path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("")
        ));
        
        // Write encrypted data to file
        let encrypted_bytes = bincode::serialize(&encrypted)
            .map_err(|e| GitError::SerializationFailed(format!("Failed to serialize: {}", e)))?;
        tokio::fs::write(&encrypted_path, encrypted_bytes).await
            .map_err(|e| GitError::Io(e))?;
        
        // Stage the encrypted file
        self.repo.stage_file(&encrypted_path).await?;
        
        // Remove original from staging if it was staged
        if self.repo.is_staged(path).await? {
            self.repo.unstage_file(path).await?;
        }
        
        Ok(encrypted_path)
    }
    
    /// Decrypt a file from git storage
    pub async fn decrypt_from_git<P: AsRef<Path>>(&self, encrypted_path: P, password: &str) -> GitResult<PathBuf> {
        let encrypted_path = encrypted_path.as_ref();
        
        // Read encrypted file
        let encrypted_data = tokio::fs::read(encrypted_path).await
            .map_err(|e| GitError::Io(e))?;
        
        // Deserialize encrypted data
        let encrypted: EncryptedSecret = bincode::deserialize(&encrypted_data)
            .map_err(|e| GitError::SerializationFailed(format!("Failed to deserialize: {}", e)))?;
        
        // Decrypt the data
        let decrypted_data = self.crypto.decrypt_data(&encrypted, password)
            .map_err(GitError::Crypto)?;
        
        // Create decrypted file path (remove .enc extension)
        let decrypted_path = if let Some(stem) = encrypted_path.file_stem() {
            encrypted_path.with_file_name(stem)
        } else {
            encrypted_path.with_extension("decrypted")
        };
        
        // Write decrypted data to file
        tokio::fs::write(&decrypted_path, decrypted_data).await
            .map_err(|e| GitError::Io(e))?;
        
        Ok(decrypted_path)
    }
    
    /// Add a team member for key sharing
    pub async fn add_team_member(&self, member: TeamMember) -> GitResult<()> {
        let team_sharing = TeamKeySharing::new(&self.repo, &self.crypto)?;
        team_sharing.add_member(member).await?;
        
        Ok(())
    }
    
    /// Rotate team keys and update all encrypted files
    pub async fn rotate_team_keys(&self) -> GitResult<()> {
        let team_sharing = TeamKeySharing::new(&self.repo, &self.crypto)?;
        team_sharing.rotate_keys().await?;
        
        Ok(())
    }
    
    /// Get repository reference for lower-level operations
    pub fn repo(&self) -> &GitRepo {
        &self.repo
    }
    
    /// Get crypto engine reference
    pub fn crypto(&self) -> &CryptoEngine {
        &self.crypto
    }
    
    /// Get git integration configuration
    pub fn config(&self) -> &GitCryptConfig {
        &self.config
    }
}

/// Utility functions for git-native patterns
pub mod utils {
    use super::*;
    
    /// Check if we're in a git repository
    pub fn is_git_repository() -> bool {
        Repository::discover(".").is_ok()
    }
    
    /// Find the root of the current git repository
    pub fn find_git_root() -> GitResult<PathBuf> {
        Repository::discover(".")
            .map(|repo| repo.workdir().unwrap_or(repo.path()).to_path_buf())
            .map_err(|_| GitError::NotGitRepository)
    }
    
    /// Check if a file should be encrypted based on git attributes
    pub fn should_encrypt<P: AsRef<Path>>(repo_path: P, file_path: P) -> GitResult<bool> {
        let repo = Repository::open(repo_path)?;
        // TODO: Check git attributes for encryption patterns
        Ok(false) // Placeholder
    }
    
    /// Get the git signature for commits
    pub fn get_signature(repo: &Repository) -> GitResult<Signature> {
        // Try to get from config, fallback to defaults
        repo.signature()
            .or_else(|_| {
                Signature::now("CargoCrypt", "cargocrypt@localhost")
            })
            .map_err(GitError::Repository)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_git_integration_creation() {
        let temp_dir = TempDir::new().unwrap();
        let git_integration = GitIntegration::new_in_dir(temp_dir.path()).await;
        
        // Should create a new git repo if none exists
        assert!(git_integration.is_ok());
    }
    
    #[test]
    fn test_utils_git_detection() {
        // Test utility functions
        let is_git = utils::is_git_repository();
        println!("Is git repository: {}", is_git);
        
        if is_git {
            let root = utils::find_git_root();
            assert!(root.is_ok());
        }
    }
}