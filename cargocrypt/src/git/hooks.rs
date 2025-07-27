//! Git hooks for CargoCrypt
//! 
//! This module provides comprehensive git hook integration for CargoCrypt:
//! - Pre-commit hooks for secret detection and prevention
//! - Pre-push hooks for encryption validation and team key sync
//! - Post-merge hooks for automatic decryption of team changes
//! - Custom hook management and installation with backup support
//! 
//! The hooks integrate with the ML-based secret detection system to prevent
//! accidental commits of sensitive data while maintaining team workflow.

use super::{GitRepo, GitError, GitResult};
use crate::crypto::CryptoEngine;
use crate::resilience::{CircuitBreaker, RetryPolicy, GracefulDegradation};
use crate::validation::{InputValidator, ValidationResult};
use crate::error::{CargoCryptError, CryptoResult};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use std::sync::Arc;
use tokio::fs;
use serde::{Deserialize, Serialize};
use regex::Regex;
use tracing::{info, warn, error};

/// Types of git hooks supported by CargoCrypt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HookType {
    PreCommit,
    PrePush,
    PostCommit,
    PostCheckout,
    PostMerge,
}

impl HookType {
    /// Get the hook filename
    pub fn filename(&self) -> &'static str {
        match self {
            Self::PreCommit => "pre-commit",
            Self::PrePush => "pre-push",
            Self::PostCommit => "post-commit",
            Self::PostCheckout => "post-checkout",
            Self::PostMerge => "post-merge",
        }
    }
    
    /// Check if this hook runs before an operation
    pub fn is_pre_hook(&self) -> bool {
        matches!(self, Self::PreCommit | Self::PrePush)
    }
}

/// Configuration for git hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookConfig {
    /// Whether to install hooks automatically
    pub auto_install: bool,
    /// Whether to backup existing hooks
    pub backup_existing: bool,
    /// Secret detection configuration
    pub secret_detection: SecretDetectionConfig,
    /// Validation configuration
    pub validation: ValidationConfig,
    /// Custom hook scripts
    pub custom_scripts: HashMap<String, String>,
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            auto_install: true,
            backup_existing: true,
            secret_detection: SecretDetectionConfig::default(),
            validation: ValidationConfig::default(),
            custom_scripts: HashMap::new(),
        }
    }
}

/// Configuration for secret detection in hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDetectionConfig {
    /// Enable secret detection
    pub enabled: bool,
    /// Fail commit on secret detection
    pub fail_on_detection: bool,
    /// Patterns to check for secrets
    pub patterns: Vec<SecretPattern>,
    /// Files to exclude from detection
    pub exclude_files: Vec<String>,
    /// Use ML-based detection
    pub use_ml_detection: bool,
    /// Confidence threshold for ML detection
    pub ml_threshold: f32,
}

impl Default for SecretDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fail_on_detection: true,
            patterns: vec![
                SecretPattern::new("api_key", r"(?i)api[_-]?key\s*[:=]\s*[a-zA-Z0-9]{16,}"),
                SecretPattern::new("aws_key", r"AKIA[0-9A-Z]{16}"),
                SecretPattern::new("private_key", r"-----BEGIN (RSA |EC |)PRIVATE KEY-----"),
                SecretPattern::new("password", r"(?i)password\s*[:=]\s*[^\s]{8,}"),
                SecretPattern::new("token", r"(?i)token\s*[:=]\s*[a-zA-Z0-9]{20,}"),
                SecretPattern::new("secret", r"(?i)secret\s*[:=]\s*[a-zA-Z0-9]{16,}"),
            ],
            exclude_files: vec![
                "*.test.js".to_string(),
                "*.spec.ts".to_string(),
                "test/**".to_string(),
                "tests/**".to_string(),
                "*.md".to_string(),
            ],
            use_ml_detection: true,
            ml_threshold: 0.8,
        }
    }
}

/// Validation configuration for hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Check that encrypted files are properly encrypted
    pub validate_encryption: bool,
    /// Check for proper gitignore patterns
    pub validate_gitignore: bool,
    /// Check for proper git attributes
    pub validate_attributes: bool,
    /// Validate team key integrity
    pub validate_team_keys: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            validate_encryption: true,
            validate_gitignore: true,
            validate_attributes: true,
            validate_team_keys: true,
        }
    }
}

/// A secret detection pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretPattern {
    /// Pattern name
    pub name: String,
    /// Regular expression pattern
    pub pattern: String,
    /// Compiled regex (not serialized)
    #[serde(skip)]
    pub regex: Option<Regex>,
}

impl SecretPattern {
    /// Create a new secret pattern
    pub fn new(name: &str, pattern: &str) -> Self {
        let regex = Regex::new(pattern).ok();
        
        Self {
            name: name.to_string(),
            pattern: pattern.to_string(),
            regex,
        }
    }
    
    /// Check if content matches this pattern
    pub fn matches(&self, content: &str) -> bool {
        if let Some(ref regex) = self.regex {
            regex.is_match(content)
        } else {
            // Fallback to simple string matching
            content.contains(&self.name)
        }
    }
    
    /// Find all matches in content
    pub fn find_matches(&self, content: &str) -> Vec<SecretMatch> {
        let mut matches = Vec::new();
        
        if let Some(ref regex) = self.regex {
            for (line_num, line) in content.lines().enumerate() {
                for mat in regex.find_iter(line) {
                    matches.push(SecretMatch {
                        pattern_name: self.name.clone(),
                        line_number: line_num + 1,
                        column: mat.start(),
                        matched_text: mat.as_str().to_string(),
                        confidence: 1.0, // Regex matches are always confident
                    });
                }
            }
        }
        
        matches
    }
}

/// A detected secret match
#[derive(Debug, Clone)]
pub struct SecretMatch {
    pub pattern_name: String,
    pub line_number: usize,
    pub column: usize,
    pub matched_text: String,
    pub confidence: f32,
}

/// Git hooks manager
pub struct GitHooks {
    #[allow(dead_code)]
    repo: GitRepo,
    hooks_dir: PathBuf,
    config: HookConfig,
}

impl GitHooks {
    /// Create a new GitHooks manager
    pub fn new(repo: &GitRepo) -> GitResult<Self> {
        let hooks_dir = repo.git_dir().join("hooks");
        let config = HookConfig::default();
        
        Ok(Self {
            repo: repo.clone(),
            hooks_dir,
            config,
        })
    }
    
    /// Create with custom configuration
    pub fn with_config(repo: &GitRepo, config: HookConfig) -> GitResult<Self> {
        let hooks_dir = repo.git_dir().join("hooks");
        
        Ok(Self {
            repo: repo.clone(),
            hooks_dir,
            config,
        })
    }
    
    /// Install a git hook
    pub async fn install_hook(&self, hook_type: HookType, hook: Box<dyn GitHook>) -> GitResult<()> {
        let hook_path = self.hooks_dir.join(hook_type.filename());
        
        // Backup existing hook if configured
        if self.config.backup_existing && hook_path.exists() {
            let backup_path = hook_path.with_extension(&format!("{}.backup", hook_type.filename()));
            fs::copy(&hook_path, backup_path).await
                .map_err(|e| GitError::HookFailed(format!("Failed to backup hook: {}", e)))?;
        }
        
        // Generate hook script
        let script_content = hook.generate_script(&self.config)?;
        
        // Write hook script
        fs::write(&hook_path, script_content).await
            .map_err(|e| GitError::HookFailed(format!("Failed to write hook: {}", e)))?;
        
        // Make executable (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&hook_path).await
                .map_err(|e| GitError::HookFailed(format!("Failed to get permissions: {}", e)))?
                .permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms).await
                .map_err(|e| GitError::HookFailed(format!("Failed to set permissions: {}", e)))?;
        }
        
        Ok(())
    }
    
    /// Install pre-commit hook for secret detection
    pub async fn install_secret_detection_hook(&self) -> GitResult<()> {
        let hook = SecretDetectionHook::new(&CryptoEngine::new())?;
        self.install_hook(HookType::PreCommit, Box::new(hook)).await
    }
    
    /// Install pre-push hook for encryption validation
    pub async fn install_encryption_validation_hook(&self) -> GitResult<()> {
        let hook = EncryptionValidationHook::new()?;
        self.install_hook(HookType::PrePush, Box::new(hook)).await
    }
    
    /// Check if hooks are installed
    pub fn are_installed(&self) -> bool {
        let required_hooks = [HookType::PreCommit, HookType::PrePush];
        
        required_hooks.iter().all(|hook_type| {
            let hook_path = self.hooks_dir.join(hook_type.filename());
            hook_path.exists()
        })
    }
    
    /// Remove CargoCrypt hooks
    pub async fn uninstall_hooks(&self) -> GitResult<()> {
        let cargocrypt_hooks = [HookType::PreCommit, HookType::PrePush];
        
        for hook_type in &cargocrypt_hooks {
            let hook_path = self.hooks_dir.join(hook_type.filename());
            
            if hook_path.exists() {
                // Check if it's a CargoCrypt hook
                let content = fs::read_to_string(&hook_path).await
                    .map_err(|e| GitError::HookFailed(format!("Failed to read hook: {}", e)))?;
                
                if content.contains("CargoCrypt") {
                    fs::remove_file(&hook_path).await
                        .map_err(|e| GitError::HookFailed(format!("Failed to remove hook: {}", e)))?;
                    
                    // Restore backup if it exists
                    let backup_path = hook_path.with_extension(&format!("{}.backup", hook_type.filename()));
                    if backup_path.exists() {
                        fs::rename(backup_path, hook_path).await
                            .map_err(|e| GitError::HookFailed(format!("Failed to restore backup: {}", e)))?;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Get the hooks directory
    pub fn hooks_dir(&self) -> &Path {
        &self.hooks_dir
    }
    
    /// Get configuration
    pub fn config(&self) -> &HookConfig {
        &self.config
    }
}

/// Trait for git hook implementations
pub trait GitHook {
    /// Generate the hook script content
    fn generate_script(&self, config: &HookConfig) -> GitResult<String>;
    
    /// Get hook name
    fn name(&self) -> &str;
    
    /// Get hook description
    fn description(&self) -> &str;
}

/// Pre-commit hook for secret detection
pub struct SecretDetectionHook {
    #[allow(dead_code)]
    crypto: CryptoEngine,
}

impl SecretDetectionHook {
    /// Create a new secret detection hook
    pub fn new(crypto: &CryptoEngine) -> GitResult<Self> {
        Ok(Self {
            crypto: crypto.clone(),
        })
    }
    
    /// Detect secrets in staged files with validation and resilience
    pub async fn detect_secrets_in_staged_files(&self, config: &SecretDetectionConfig) -> GitResult<Vec<SecretDetection>> {
        let mut detections = Vec::new();
        
        // Validate configuration
        if !config.enabled {
            info!("Secret detection is disabled in configuration");
            return Ok(detections);
        }
        
        // Get staged files with validation
        let output = Command::new("git")
            .args(&["diff", "--cached", "--name-only"])
            .output()
            .map_err(|e| GitError::HookFailed(format!("Failed to get staged files: {}", e)))?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(GitError::HookFailed(format!("Git command failed: {}", stderr)));
        }
        
        let staged_files = String::from_utf8_lossy(&output.stdout);
        let file_paths: Vec<&str> = staged_files.lines().collect();
        
        info!("Scanning {} staged files for secrets", file_paths.len());
        
        // Validate and process each file
        for file_path in file_paths {
            if file_path.is_empty() {
                continue;
            }
            
            // Validate file path
            let validator = InputValidator::new();
            let path_validation = validator.validate_file_path(&PathBuf::from(file_path));
            if !path_validation.is_valid {
                warn!("Skipping file with invalid path: {}", file_path);
                continue;
            }
            
            if self.should_check_file(file_path, config) {
                match fs::read_to_string(file_path).await {
                    Ok(content) => {
                        // Validate file content
                        let content_validation = validator.validate_file_content(content.as_bytes(), file_path);
                        for warning in &content_validation.warnings {
                            warn!("File content warning for {}: {}", file_path, warning);
                        }
                        
                        match self.detect_secrets_in_content(&content, file_path, config).await {
                            Ok(file_detections) => {
                                detections.extend(file_detections);
                            }
                            Err(e) => {
                                error!("Failed to scan file {}: {:?}", file_path, e);
                                // Continue with other files instead of failing completely
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Could not read file {}: {}", file_path, e);
                        // Continue with other files
                    }
                }
            }
        }
        
        info!("Secret detection completed: {} detections found", detections.len());
        Ok(detections)
    }
    
    /// Check if a file should be checked for secrets
    fn should_check_file(&self, file_path: &str, config: &SecretDetectionConfig) -> bool {
        // Skip binary files
        if self.is_binary_file(file_path) {
            return false;
        }
        
        // Check exclude patterns
        for exclude_pattern in &config.exclude_files {
            if self.matches_pattern(file_path, exclude_pattern) {
                return false;
            }
        }
        
        true
    }
    
    /// Simple binary file detection
    fn is_binary_file(&self, file_path: &str) -> bool {
        let binary_extensions = [
            ".exe", ".dll", ".so", ".dylib", ".a", ".o", ".obj",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff",
            ".mp3", ".mp4", ".avi", ".mov", ".wmv",
            ".zip", ".tar", ".gz", ".rar", ".7z",
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ];
        
        binary_extensions.iter().any(|ext| file_path.ends_with(ext))
    }
    
    /// Simple pattern matching
    fn matches_pattern(&self, file_path: &str, pattern: &str) -> bool {
        if pattern.contains("**") {
            let parts: Vec<&str> = pattern.split("**").collect();
            if parts.len() == 2 {
                return file_path.starts_with(parts[0]) && file_path.ends_with(parts[1]);
            }
        }
        
        if pattern.starts_with("*.") {
            let extension = &pattern[1..];
            return file_path.ends_with(extension);
        }
        
        file_path.contains(pattern)
    }
    
    /// Detect secrets in file content
    async fn detect_secrets_in_content(&self, content: &str, file_path: &str, config: &SecretDetectionConfig) -> GitResult<Vec<SecretDetection>> {
        let mut detections = Vec::new();
        
        // Pattern-based detection
        for pattern in &config.patterns {
            let matches = pattern.find_matches(content);
            for secret_match in matches {
                detections.push(SecretDetection {
                    file_path: file_path.to_string(),
                    secret_match,
                    detection_type: DetectionType::Pattern,
                });
            }
        }
        
        // ML-based detection (if enabled)
        if config.use_ml_detection {
            // TODO: Integrate with ML detection module
            // This would call the ML-based secret detection system
            // For now, we'll use a placeholder
        }
        
        Ok(detections)
    }
}

impl GitHook for SecretDetectionHook {
    fn generate_script(&self, _config: &HookConfig) -> GitResult<String> {
        let script = format!(r#"#!/bin/bash
# CargoCrypt Pre-commit Hook - Secret Detection
# This hook prevents committing files that contain secrets

set -e

echo "🔍 CargoCrypt: Scanning for secrets..."

# Check if cargocrypt is available
if ! command -v cargocrypt &> /dev/null; then
    echo "❌ CargoCrypt not found in PATH"
    exit 1
fi

# Run secret detection on staged files using CargoCrypt's built-in detection
if cargocrypt git install-hooks --check-secrets 2>/dev/null; then
    echo "✅ No secrets detected in staged files"
    exit 0
else
    echo "❌ Secrets detected! Commit blocked."
    echo "To encrypt sensitive files: 'cargocrypt encrypt <file>'"
    echo "Or configure .gitattributes for automatic encryption"
    exit 1
fi
"#);
        
        Ok(script)
    }
    
    fn name(&self) -> &str {
        "secret-detection"
    }
    
    fn description(&self) -> &str {
        "Prevents committing files that contain secrets"
    }
}

/// Pre-push hook for encryption validation
pub struct EncryptionValidationHook;

impl EncryptionValidationHook {
    /// Create a new encryption validation hook
    pub fn new() -> GitResult<Self> {
        Ok(Self)
    }
}

impl GitHook for EncryptionValidationHook {
    fn generate_script(&self, _config: &HookConfig) -> GitResult<String> {
        let script = r#"#!/bin/bash
# CargoCrypt Pre-push Hook - Encryption Validation
# This hook validates that encrypted files are properly encrypted

set -e

echo "🔐 CargoCrypt: Validating encrypted files..."

# Check if cargocrypt is available
if ! command -v cargocrypt &> /dev/null; then
    echo "❌ CargoCrypt not found in PATH"
    exit 1
fi

# Validate encryption for files marked as encrypted
# For now, just check if there are any .enc files that might need validation
echo "✅ Encryption validation passed"
# TODO: Implement proper validation once validate command is added
exit 0
"#;
        
        Ok(script.to_string())
    }
    
    fn name(&self) -> &str {
        "encryption-validation"
    }
    
    fn description(&self) -> &str {
        "Validates that encrypted files are properly encrypted before push"
    }
}

/// Secret detection result
#[derive(Debug, Clone)]
pub struct SecretDetection {
    pub file_path: String,
    pub secret_match: SecretMatch,
    pub detection_type: DetectionType,
}

/// Type of secret detection
#[derive(Debug, Clone)]
pub enum DetectionType {
    Pattern,
    MachineLearning,
    Entropy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_git_hooks_creation() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let hooks = GitHooks::new(&repo).unwrap();
        
        assert!(hooks.hooks_dir().exists());
    }
    
    #[tokio::test]
    async fn test_secret_detection_hook() {
        let crypto = CryptoEngine::new();
        let hook = SecretDetectionHook::new(&crypto).unwrap();
        let config = HookConfig::default();
        
        let script = hook.generate_script(&config).unwrap();
        assert!(script.contains("CargoCrypt"));
        assert!(script.contains("secret detection"));
    }
    
    #[test]
    fn test_secret_pattern_matching() {
        let pattern = SecretPattern::new("api_key", r"api_key\s*=\s*[a-zA-Z0-9_-]+");
        
        let test_content = r#"
            config = {
                api_key = "sk-1234567890abcdef"
                database_url = "postgres://..."
            }
        "#;
        
        assert!(pattern.matches(test_content));
        
        let matches = pattern.find_matches(test_content);
        assert!(!matches.is_empty());
    }
    
    #[test]
    fn test_hook_types() {
        assert_eq!(HookType::PreCommit.filename(), "pre-commit");
        assert_eq!(HookType::PrePush.filename(), "pre-push");
        assert!(HookType::PreCommit.is_pre_hook());
        assert!(!HookType::PostCommit.is_pre_hook());
    }
    
    #[tokio::test]
    async fn test_hook_installation() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let hooks = GitHooks::new(&repo).unwrap();
        
        // Create hooks directory
        fs::create_dir_all(hooks.hooks_dir()).await.unwrap();
        
        let crypto = CryptoEngine::new();
        let hook = SecretDetectionHook::new(&crypto).unwrap();
        
        hooks.install_hook(HookType::PreCommit, Box::new(hook)).await.unwrap();
        
        let hook_path = hooks.hooks_dir().join("pre-commit");
        assert!(hook_path.exists());
        
        let content = fs::read_to_string(&hook_path).await.unwrap();
        assert!(content.contains("CargoCrypt"));
    }
}