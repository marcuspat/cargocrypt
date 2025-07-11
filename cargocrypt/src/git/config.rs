//! Configuration management for Git integration
//! 
//! This module handles all configuration aspects of CargoCrypt's git integration,
//! including repository setup, integration modes, and feature toggles.

use super::{GitRepo, GitError, GitResult};
use std::path::{Path, PathBuf};
use tokio::fs;
use serde::{Deserialize, Serialize};

/// Main configuration for Git integration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitCryptConfig {
    /// Integration mode
    pub mode: IntegrationMode,
    /// Repository setup configuration
    pub setup: RepositorySetup,
    /// Feature toggles
    pub features: FeatureConfig,
    /// Git-specific settings
    pub git: GitSettings,
    /// Performance settings
    pub performance: PerformanceConfig,
}

impl Default for GitCryptConfig {
    fn default() -> Self {
        Self {
            mode: IntegrationMode::GitNative,
            setup: RepositorySetup::default(),
            features: FeatureConfig::default(),
            git: GitSettings::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl GitCryptConfig {
    /// Load configuration from repository
    pub async fn load_or_default(repo: &GitRepo) -> GitResult<Self> {
        let config_path = repo.workdir().join(".cargocrypt").join("git.toml");
        
        if config_path.exists() {
            let content = fs::read_to_string(&config_path).await
                .map_err(|e| GitError::InitializationFailed(format!("Failed to read git config: {}", e)))?;
            
            toml::from_str(&content)
                .map_err(|e| GitError::InitializationFailed(format!("Failed to parse git config: {}", e)))
        } else {
            // Create default config
            let config = Self::default();
            config.save(repo).await?;
            Ok(config)
        }
    }
    
    /// Save configuration to repository
    pub async fn save(&self, repo: &GitRepo) -> GitResult<()> {
        let config_path = repo.workdir().join(".cargocrypt").join("git.toml");
        
        // Ensure directory exists
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent).await
                .map_err(|e| GitError::InitializationFailed(format!("Failed to create config directory: {}", e)))?;
        }
        
        let content = toml::to_string_pretty(self)
            .map_err(|e| GitError::InitializationFailed(format!("Failed to serialize git config: {}", e)))?;
        
        fs::write(&config_path, content).await
            .map_err(|e| GitError::InitializationFailed(format!("Failed to write git config: {}", e)))?;
        
        Ok(())
    }
    
    /// Update configuration with new values
    pub async fn update<F>(&mut self, repo: &GitRepo, updater: F) -> GitResult<()>
    where
        F: FnOnce(&mut Self),
    {
        updater(self);
        self.save(repo).await
    }
    
    /// Check if a feature is enabled
    pub fn is_feature_enabled(&self, feature: &str) -> bool {
        match feature {
            "gitignore_management" => self.features.gitignore_management,
            "git_attributes" => self.features.git_attributes,
            "git_hooks" => self.features.git_hooks,
            "encrypted_storage" => self.features.encrypted_storage,
            "team_sharing" => self.features.team_sharing,
            "auto_encryption" => self.features.auto_encryption,
            "secret_detection" => self.features.secret_detection,
            _ => false,
        }
    }
    
    /// Enable a feature
    pub fn enable_feature(&mut self, feature: &str) {
        match feature {
            "gitignore_management" => self.features.gitignore_management = true,
            "git_attributes" => self.features.git_attributes = true,
            "git_hooks" => self.features.git_hooks = true,
            "encrypted_storage" => self.features.encrypted_storage = true,
            "team_sharing" => self.features.team_sharing = true,
            "auto_encryption" => self.features.auto_encryption = true,
            "secret_detection" => self.features.secret_detection = true,
            _ => {}
        }
    }
    
    /// Disable a feature
    pub fn disable_feature(&mut self, feature: &str) {
        match feature {
            "gitignore_management" => self.features.gitignore_management = false,
            "git_attributes" => self.features.git_attributes = false,
            "git_hooks" => self.features.git_hooks = false,
            "encrypted_storage" => self.features.encrypted_storage = false,
            "team_sharing" => self.features.team_sharing = false,
            "auto_encryption" => self.features.auto_encryption = false,
            "secret_detection" => self.features.secret_detection = false,
            _ => {}
        }
    }
}

/// Integration modes for Git
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IntegrationMode {
    /// Full git-native integration (default)
    GitNative,
    /// Compatibility mode (like git-crypt)
    Compatibility,
    /// Standalone mode (minimal git integration)
    Standalone,
    /// Custom mode with specific settings
    Custom,
}

/// Repository setup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositorySetup {
    /// Automatically initialize on first use
    pub auto_init: bool,
    /// Backup existing files before setup
    pub backup_existing: bool,
    /// Create example configurations
    pub create_examples: bool,
    /// Initialize with team setup
    pub setup_team: bool,
    /// Default encryption patterns
    pub default_patterns: Vec<String>,
}

impl Default for RepositorySetup {
    fn default() -> Self {
        Self {
            auto_init: true,
            backup_existing: true,
            create_examples: false,
            setup_team: false,
            default_patterns: vec![
                "*.secret".to_string(),
                "*.key".to_string(),
                "secrets/*".to_string(),
                "config/secrets.*".to_string(),
                "*.env.local".to_string(),
                "*.env.production".to_string(),
            ],
        }
    }
}

/// Feature configuration toggles
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureConfig {
    /// Enable .gitignore management
    pub gitignore_management: bool,
    /// Enable git attributes configuration
    pub git_attributes: bool,
    /// Enable git hooks installation
    pub git_hooks: bool,
    /// Enable encrypted storage in git
    pub encrypted_storage: bool,
    /// Enable team key sharing
    pub team_sharing: bool,
    /// Enable automatic encryption based on patterns
    pub auto_encryption: bool,
    /// Enable secret detection in hooks
    pub secret_detection: bool,
}

impl Default for FeatureConfig {
    fn default() -> Self {
        Self {
            gitignore_management: true,
            git_attributes: true,
            git_hooks: true,
            encrypted_storage: true,
            team_sharing: false, // Disabled by default for security
            auto_encryption: true,
            secret_detection: true,
        }
    }
}

/// Git-specific settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitSettings {
    /// Git refs configuration
    pub refs: GitRefsConfig,
    /// Commit message templates
    pub commit_templates: CommitTemplates,
    /// Branch configuration
    pub branches: BranchConfig,
    /// Remote configuration
    pub remotes: RemoteConfig,
}

impl Default for GitSettings {
    fn default() -> Self {
        Self {
            refs: GitRefsConfig::default(),
            commit_templates: CommitTemplates::default(),
            branches: BranchConfig::default(),
            remotes: RemoteConfig::default(),
        }
    }
}

/// Git refs configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRefsConfig {
    /// Ref for encrypted storage
    pub storage_ref: String,
    /// Ref for team data
    pub team_ref: String,
    /// Ref for configuration backups
    pub backup_ref: String,
}

impl Default for GitRefsConfig {
    fn default() -> Self {
        Self {
            storage_ref: "refs/cargocrypt/storage".to_string(),
            team_ref: "refs/cargocrypt/team".to_string(),
            backup_ref: "refs/cargocrypt/backups".to_string(),
        }
    }
}

/// Commit message templates
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitTemplates {
    /// Template for encryption operations
    pub encrypt: String,
    /// Template for decryption operations
    pub decrypt: String,
    /// Template for team operations
    pub team: String,
    /// Template for setup operations
    pub setup: String,
}

impl Default for CommitTemplates {
    fn default() -> Self {
        Self {
            encrypt: "🔐 Encrypt: {}".to_string(),
            decrypt: "🔓 Decrypt: {}".to_string(),
            team: "👥 Team: {}".to_string(),
            setup: "⚙️ Setup: {}".to_string(),
        }
    }
}

/// Branch configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchConfig {
    /// Default branch for CargoCrypt operations
    pub default_branch: Option<String>,
    /// Create separate branches for encryption operations
    pub use_encryption_branches: bool,
    /// Branch naming pattern
    pub branch_pattern: String,
}

impl Default for BranchConfig {
    fn default() -> Self {
        Self {
            default_branch: None, // Use repository default
            use_encryption_branches: false,
            branch_pattern: "cargocrypt/{}".to_string(),
        }
    }
}

/// Remote configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteConfig {
    /// Automatically push CargoCrypt refs
    pub auto_push_refs: bool,
    /// Remote name for CargoCrypt operations
    pub remote_name: String,
    /// Sync team data with remote
    pub sync_team_data: bool,
}

impl Default for RemoteConfig {
    fn default() -> Self {
        Self {
            auto_push_refs: false,
            remote_name: "origin".to_string(),
            sync_team_data: false,
        }
    }
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable parallel operations
    pub enable_parallel: bool,
    /// Maximum concurrent operations
    pub max_concurrent: usize,
    /// Cache configuration
    pub cache: CacheConfig,
    /// Compression settings
    pub compression: CompressionConfig,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_parallel: true,
            max_concurrent: 4,
            cache: CacheConfig::default(),
            compression: CompressionConfig::default(),
        }
    }
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,
    /// Cache size in MB
    pub size_mb: usize,
    /// Cache TTL in seconds
    pub ttl_seconds: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            size_mb: 64,
            ttl_seconds: 3600, // 1 hour
        }
    }
}

/// Compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionConfig {
    /// Enable compression for encrypted storage
    pub enabled: bool,
    /// Compression level (1-9)
    pub level: u32,
    /// Minimum file size for compression (bytes)
    pub min_size: usize,
}

impl Default for CompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            level: 6,
            min_size: 1024, // 1KB
        }
    }
}

/// Configuration validation and migration
impl GitCryptConfig {
    /// Validate configuration settings
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        
        // Validate refs
        if self.git.refs.storage_ref.is_empty() {
            errors.push("Storage ref cannot be empty".to_string());
        }
        
        if self.git.refs.team_ref.is_empty() {
            errors.push("Team ref cannot be empty".to_string());
        }
        
        // Validate performance settings
        if self.performance.max_concurrent == 0 {
            errors.push("Max concurrent operations must be greater than 0".to_string());
        }
        
        if self.performance.compression.level > 9 {
            errors.push("Compression level must be between 1 and 9".to_string());
        }
        
        // Validate feature dependencies
        if self.features.team_sharing && !self.features.encrypted_storage {
            errors.push("Team sharing requires encrypted storage to be enabled".to_string());
        }
        
        if self.features.auto_encryption && !self.features.git_attributes {
            errors.push("Auto encryption requires git attributes to be enabled".to_string());
        }
        
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
    
    /// Migrate configuration from older versions
    pub fn migrate_from_version(&mut self, version: u32) -> GitResult<()> {
        match version {
            1 => {
                // Migration from version 1 to current
                // Add any new fields with default values
                // This is handled automatically by serde with #[serde(default)]
            }
            _ => {
                // Unknown version, use defaults
                *self = Self::default();
            }
        }
        
        Ok(())
    }
    
    /// Get configuration summary for display
    pub fn summary(&self) -> ConfigSummary {
        ConfigSummary {
            mode: self.mode.clone(),
            enabled_features: self.get_enabled_features(),
            git_refs: vec![
                self.git.refs.storage_ref.clone(),
                self.git.refs.team_ref.clone(),
                self.git.refs.backup_ref.clone(),
            ],
            performance_settings: format!(
                "Parallel: {}, Max Concurrent: {}, Cache: {}MB",
                self.performance.enable_parallel,
                self.performance.max_concurrent,
                self.performance.cache.size_mb
            ),
        }
    }
    
    /// Get list of enabled features
    fn get_enabled_features(&self) -> Vec<String> {
        let mut features = Vec::new();
        
        if self.features.gitignore_management {
            features.push("gitignore_management".to_string());
        }
        if self.features.git_attributes {
            features.push("git_attributes".to_string());
        }
        if self.features.git_hooks {
            features.push("git_hooks".to_string());
        }
        if self.features.encrypted_storage {
            features.push("encrypted_storage".to_string());
        }
        if self.features.team_sharing {
            features.push("team_sharing".to_string());
        }
        if self.features.auto_encryption {
            features.push("auto_encryption".to_string());
        }
        if self.features.secret_detection {
            features.push("secret_detection".to_string());
        }
        
        features
    }
}

/// Configuration summary for display
#[derive(Debug, Clone)]
pub struct ConfigSummary {
    pub mode: IntegrationMode,
    pub enabled_features: Vec<String>,
    pub git_refs: Vec<String>,
    pub performance_settings: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_config_creation_and_save() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        
        let config = GitCryptConfig::default();
        config.save(&repo).await.unwrap();
        
        let config_path = temp_dir.path().join(".cargocrypt/git.toml");
        assert!(config_path.exists());
    }
    
    #[tokio::test]
    async fn test_config_load_or_default() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        
        // Should create default config if none exists
        let config = GitCryptConfig::load_or_default(&repo).await.unwrap();
        assert_eq!(config.mode, IntegrationMode::GitNative);
        
        // Should load existing config
        let config2 = GitCryptConfig::load_or_default(&repo).await.unwrap();
        assert_eq!(config.mode, config2.mode);
    }
    
    #[test]
    fn test_feature_management() {
        let mut config = GitCryptConfig::default();
        
        assert!(config.is_feature_enabled("gitignore_management"));
        
        config.disable_feature("gitignore_management");
        assert!(!config.is_feature_enabled("gitignore_management"));
        
        config.enable_feature("gitignore_management");
        assert!(config.is_feature_enabled("gitignore_management"));
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = GitCryptConfig::default();
        assert!(config.validate().is_ok());
        
        // Test invalid compression level
        config.performance.compression.level = 10;
        assert!(config.validate().is_err());
        
        // Test invalid max concurrent
        config.performance.compression.level = 6;
        config.performance.max_concurrent = 0;
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_feature_dependencies() {
        let mut config = GitCryptConfig::default();
        
        // Enable team sharing but disable encrypted storage
        config.features.team_sharing = true;
        config.features.encrypted_storage = false;
        
        let validation_result = config.validate();
        assert!(validation_result.is_err());
        
        let errors = validation_result.unwrap_err();
        assert!(errors.iter().any(|e| e.contains("Team sharing requires encrypted storage")));
    }
    
    #[test]
    fn test_config_summary() {
        let config = GitCryptConfig::default();
        let summary = config.summary();
        
        assert_eq!(summary.mode, IntegrationMode::GitNative);
        assert!(!summary.enabled_features.is_empty());
        assert_eq!(summary.git_refs.len(), 3);
    }
}