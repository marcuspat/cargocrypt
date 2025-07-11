//! GitIgnore management for CargoCrypt
//! 
//! This module handles automatic .gitignore file management, ensuring that
//! encrypted files are properly excluded from git tracking while maintaining
//! necessary configuration files.

use super::{GitRepo, GitError, GitResult};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tokio::fs;
use serde::{Deserialize, Serialize};

/// Configuration for gitignore patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IgnoreConfig {
    /// Patterns to automatically add
    pub auto_patterns: Vec<String>,
    /// Patterns to never add (blacklist)
    pub never_ignore: Vec<String>,
    /// Whether to backup existing .gitignore
    pub backup_existing: bool,
    /// Custom section header
    pub section_header: String,
}

impl Default for IgnoreConfig {
    fn default() -> Self {
        Self {
            auto_patterns: vec![
                "*.cargocrypt".to_string(),
                "*.enc".to_string(),
                ".cargocrypt/keys/".to_string(),
                ".cargocrypt/cache/".to_string(),
                "# CargoCrypt temporary files".to_string(),
                "*.tmp.cargocrypt".to_string(),
            ],
            never_ignore: vec![
                ".cargocrypt/config.toml".to_string(),
                ".cargocrypt/team/".to_string(),
                ".gitattributes".to_string(),
            ],
            backup_existing: true,
            section_header: "# CargoCrypt - Encrypted files and directories".to_string(),
        }
    }
}

/// Represents a gitignore pattern
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IgnorePattern {
    /// Ignore pattern (e.g., "*.enc")
    Ignore(String),
    /// Include pattern (e.g., "!config.toml")
    Include(String),
    /// Comment pattern (e.g., "# Comment")
    Comment(String),
    /// Empty line
    Empty,
}

impl IgnorePattern {
    /// Create from a string line
    pub fn from_line(line: &str) -> Self {
        let trimmed = line.trim();
        
        if trimmed.is_empty() {
            Self::Empty
        } else if trimmed.starts_with('#') {
            Self::Comment(trimmed.to_string())
        } else if trimmed.starts_with('!') {
            Self::Include(trimmed[1..].to_string())
        } else {
            Self::Ignore(trimmed.to_string())
        }
    }
    
    /// Convert to string
    pub fn to_string(&self) -> String {
        match self {
            Self::Ignore(pattern) => pattern.clone(),
            Self::Include(pattern) => format!("!{}", pattern),
            Self::Comment(comment) => comment.clone(),
            Self::Empty => String::new(),
        }
    }
    
    /// Check if this is a CargoCrypt-related pattern
    pub fn is_cargocrypt_pattern(&self) -> bool {
        match self {
            Self::Ignore(pattern) | Self::Include(pattern) => {
                pattern.contains("cargocrypt") || 
                pattern.contains(".enc") ||
                pattern.contains("*.secret") ||
                pattern.contains("*.key")
            }
            Self::Comment(comment) => comment.to_lowercase().contains("cargocrypt"),
            Self::Empty => false,
        }
    }
}

/// Manages .gitignore file for CargoCrypt integration
pub struct GitIgnoreManager {
    repo: GitRepo,
    gitignore_path: PathBuf,
    patterns: Vec<IgnorePattern>,
    config: IgnoreConfig,
}

impl GitIgnoreManager {
    /// Create a new GitIgnoreManager
    pub fn new(repo: &GitRepo) -> GitResult<Self> {
        let gitignore_path = repo.workdir().join(".gitignore");
        let config = IgnoreConfig::default();
        
        Ok(Self {
            repo: repo.clone(),
            gitignore_path,
            patterns: Vec::new(),
            config,
        })
    }
    
    /// Create with custom configuration
    pub fn with_config(repo: &GitRepo, config: IgnoreConfig) -> GitResult<Self> {
        let gitignore_path = repo.workdir().join(".gitignore");
        
        Ok(Self {
            repo: repo.clone(),
            gitignore_path,
            patterns: Vec::new(),
            config,
        })
    }
    
    /// Load existing .gitignore file
    pub async fn load(&mut self) -> GitResult<()> {
        if self.gitignore_path.exists() {
            let content = fs::read_to_string(&self.gitignore_path).await
                .map_err(|e| GitError::StorageFailed(format!("Failed to read .gitignore: {}", e)))?;
            
            self.patterns = content
                .lines()
                .map(IgnorePattern::from_line)
                .collect();
        }
        
        Ok(())
    }
    
    /// Save .gitignore file
    pub async fn save(&self) -> GitResult<()> {
        // Backup existing file if configured
        if self.config.backup_existing && self.gitignore_path.exists() {
            let backup_path = self.gitignore_path.with_extension("gitignore.bak");
            fs::copy(&self.gitignore_path, backup_path).await
                .map_err(|e| GitError::StorageFailed(format!("Failed to backup .gitignore: {}", e)))?;
        }
        
        let content = self.patterns
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        
        fs::write(&self.gitignore_path, content).await
            .map_err(|e| GitError::StorageFailed(format!("Failed to write .gitignore: {}", e)))?;
        
        Ok(())
    }
    
    /// Add a pattern to ignore
    pub async fn add_pattern(&mut self, pattern: &str) -> GitResult<()> {
        if !self.has_pattern(pattern) {
            self.patterns.push(IgnorePattern::Ignore(pattern.to_string()));
        }
        Ok(())
    }
    
    /// Add an include pattern (negation)
    pub async fn add_include_pattern(&mut self, pattern: &str) -> GitResult<()> {
        let include_pattern = IgnorePattern::Include(pattern.to_string());
        if !self.patterns.contains(&include_pattern) {
            self.patterns.push(include_pattern);
        }
        Ok(())
    }
    
    /// Add a comment
    pub async fn add_comment(&mut self, comment: &str) -> GitResult<()> {
        self.patterns.push(IgnorePattern::Comment(format!("# {}", comment)));
        Ok(())
    }
    
    /// Add an empty line
    pub async fn add_empty_line(&mut self) -> GitResult<()> {
        self.patterns.push(IgnorePattern::Empty);
        Ok(())
    }
    
    /// Check if a pattern already exists
    pub fn has_pattern(&self, pattern: &str) -> bool {
        self.patterns.iter().any(|p| match p {
            IgnorePattern::Ignore(existing) => existing == pattern,
            IgnorePattern::Include(existing) => existing == pattern,
            _ => false,
        })
    }
    
    /// Check if CargoCrypt patterns are present
    pub fn has_cargocrypt_patterns(&self) -> bool {
        self.patterns.iter().any(|p| p.is_cargocrypt_pattern())
    }
    
    /// Add all default CargoCrypt patterns
    pub async fn add_cargocrypt_patterns(&mut self) -> GitResult<()> {
        // Load existing patterns first
        self.load().await?;
        
        // Add section header if not present
        if !self.has_cargocrypt_patterns() {
            self.add_empty_line().await?;
            self.patterns.push(IgnorePattern::Comment(self.config.section_header.clone()));
        }
        
        // Add ignore patterns
        let auto_patterns = self.config.auto_patterns.clone();
        for pattern in auto_patterns {
            if pattern.starts_with('#') {
                self.patterns.push(IgnorePattern::Comment(pattern));
            } else {
                self.add_pattern(&pattern).await?;
            }
        }
        
        // Add include patterns for files that should be tracked
        let never_ignore = self.config.never_ignore.clone();
        for pattern in never_ignore {
            self.add_include_pattern(&pattern).await?;
        }
        
        Ok(())
    }
    
    /// Remove CargoCrypt patterns
    pub async fn remove_cargocrypt_patterns(&mut self) -> GitResult<()> {
        self.load().await?;
        self.patterns.retain(|p| !p.is_cargocrypt_pattern());
        Ok(())
    }
    
    /// Update patterns based on project structure
    pub async fn update_smart_patterns(&mut self) -> GitResult<()> {
        let workdir = self.repo.workdir().to_path_buf();
        
        // Check for common secret directories
        let secret_dirs = ["secrets", "config/secrets", "keys", ".env", "credentials"];
        
        for dir in &secret_dirs {
            let dir_path = workdir.join(dir);
            if dir_path.exists() && dir_path.is_dir() {
                self.add_pattern(&format!("{}/*", dir)).await?;
                self.add_comment(&format!("Auto-detected secret directory: {}", dir)).await?;
            }
        }
        
        // Check for common secret file patterns
        let secret_patterns = ["*.pem", "*.p12", "*.pfx", "*.jks", "*.keystore"];
        
        for pattern in &secret_patterns {
            // Check if files with this pattern exist
            if self.has_files_matching_pattern(pattern).await? {
                self.add_pattern(pattern).await?;
            }
        }
        
        Ok(())
    }
    
    /// Check if files matching a pattern exist in the repository
    async fn has_files_matching_pattern(&self, pattern: &str) -> GitResult<bool> {
        // Simple implementation - check for common extensions
        let workdir = self.repo.workdir();
        
        if pattern.starts_with("*.") {
            let extension = &pattern[2..];
            let mut entries = fs::read_dir(workdir).await
                .map_err(|e| GitError::StorageFailed(format!("Failed to read directory: {}", e)))?;
            
            while let Some(entry) = entries.next_entry().await
                .map_err(|e| GitError::StorageFailed(format!("Failed to read entry: {}", e)))? {
                
                if let Some(ext) = entry.path().extension() {
                    if ext == extension {
                        return Ok(true);
                    }
                }
            }
        }
        
        Ok(false)
    }
    
    /// Get all ignore patterns
    pub fn get_patterns(&self) -> &[IgnorePattern] {
        &self.patterns
    }
    
    /// Get only ignore patterns (not comments or includes)
    pub fn get_ignore_patterns(&self) -> Vec<String> {
        self.patterns
            .iter()
            .filter_map(|p| match p {
                IgnorePattern::Ignore(pattern) => Some(pattern.clone()),
                _ => None,
            })
            .collect()
    }
    
    /// Get only include patterns
    pub fn get_include_patterns(&self) -> Vec<String> {
        self.patterns
            .iter()
            .filter_map(|p| match p {
                IgnorePattern::Include(pattern) => Some(pattern.clone()),
                _ => None,
            })
            .collect()
    }
    
    /// Validate that essential files are not ignored
    pub fn validate_patterns(&self) -> GitResult<Vec<String>> {
        let mut warnings = Vec::new();
        
        // Check for patterns that might ignore important files
        let important_files = [
            "Cargo.toml",
            "package.json",
            "requirements.txt",
            "Gemfile",
            "build.gradle",
            "pom.xml",
        ];
        
        let ignore_patterns = self.get_ignore_patterns();
        
        for file in &important_files {
            for pattern in &ignore_patterns {
                if self.pattern_matches_file(pattern, file) {
                    warnings.push(format!("Pattern '{}' may ignore important file '{}'", pattern, file));
                }
            }
        }
        
        Ok(warnings)
    }
    
    /// Simple pattern matching (basic implementation)
    fn pattern_matches_file(&self, pattern: &str, file: &str) -> bool {
        if pattern == file {
            return true;
        }
        
        if pattern.ends_with("*") {
            let prefix = &pattern[..pattern.len() - 1];
            return file.starts_with(prefix);
        }
        
        if pattern.starts_with("*.") {
            let extension = &pattern[2..];
            return file.ends_with(&format!(".{}", extension));
        }
        
        false
    }
    
    /// Clean up duplicate or conflicting patterns
    pub fn cleanup_patterns(&mut self) {
        let mut seen = HashSet::new();
        let mut cleaned = Vec::new();
        
        for pattern in &self.patterns {
            match pattern {
                IgnorePattern::Empty => {
                    // Only keep empty lines if not consecutive
                    if !matches!(cleaned.last(), Some(IgnorePattern::Empty)) {
                        cleaned.push(pattern.clone());
                    }
                }
                _ => {
                    let key = pattern.to_string();
                    if seen.insert(key) {
                        cleaned.push(pattern.clone());
                    }
                }
            }
        }
        
        self.patterns = cleaned;
    }
    
    /// Get the repository reference
    pub fn repo(&self) -> &GitRepo {
        &self.repo
    }
    
    /// Get the .gitignore file path
    pub fn path(&self) -> &Path {
        &self.gitignore_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_gitignore_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let manager = GitIgnoreManager::new(&repo).unwrap();
        
        assert_eq!(manager.path(), &temp_dir.path().join(".gitignore"));
    }
    
    #[tokio::test]
    async fn test_pattern_operations() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let mut manager = GitIgnoreManager::new(&repo).unwrap();
        
        // Add patterns
        manager.add_pattern("*.enc").await.unwrap();
        manager.add_include_pattern("!config.toml").await.unwrap();
        manager.add_comment("CargoCrypt files").await.unwrap();
        
        assert_eq!(manager.patterns.len(), 3);
        assert!(manager.has_pattern("*.enc"));
    }
    
    #[tokio::test]
    async fn test_cargocrypt_patterns() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let mut manager = GitIgnoreManager::new(&repo).unwrap();
        
        manager.add_cargocrypt_patterns().await.unwrap();
        
        assert!(manager.has_cargocrypt_patterns());
        assert!(manager.has_pattern("*.cargocrypt"));
        assert!(manager.has_pattern("*.enc"));
    }
    
    #[tokio::test]
    async fn test_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let mut manager = GitIgnoreManager::new(&repo).unwrap();
        
        // Add patterns and save
        manager.add_pattern("*.test").await.unwrap();
        manager.save().await.unwrap();
        
        // Create new manager and load
        let mut manager2 = GitIgnoreManager::new(&repo).unwrap();
        manager2.load().await.unwrap();
        
        assert!(manager2.has_pattern("*.test"));
    }
    
    #[test]
    fn test_ignore_pattern_parsing() {
        assert_eq!(IgnorePattern::from_line("*.enc"), IgnorePattern::Ignore("*.enc".to_string()));
        assert_eq!(IgnorePattern::from_line("!config.toml"), IgnorePattern::Include("config.toml".to_string()));
        assert_eq!(IgnorePattern::from_line("# Comment"), IgnorePattern::Comment("# Comment".to_string()));
        assert_eq!(IgnorePattern::from_line(""), IgnorePattern::Empty);
    }
    
    #[test]
    fn test_pattern_cleanup() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let mut manager = GitIgnoreManager::new(&repo).unwrap();
        
        // Add duplicate patterns
        manager.patterns.push(IgnorePattern::Ignore("*.enc".to_string()));
        manager.patterns.push(IgnorePattern::Empty);
        manager.patterns.push(IgnorePattern::Empty);
        manager.patterns.push(IgnorePattern::Ignore("*.enc".to_string()));
        
        manager.cleanup_patterns();
        
        // Should have only one *.enc and one empty line
        let ignore_count = manager.patterns.iter()
            .filter(|p| matches!(p, IgnorePattern::Ignore(s) if s == "*.enc"))
            .count();
        let empty_count = manager.patterns.iter()
            .filter(|p| matches!(p, IgnorePattern::Empty))
            .count();
        
        assert_eq!(ignore_count, 1);
        assert_eq!(empty_count, 1);
    }
}