//! Git attributes management for CargoCrypt
//! 
//! This module handles .gitattributes configuration for automatic encryption/decryption
//! through git clean/smudge filters, similar to git-crypt and transcrypt patterns.

use super::{GitRepo, GitError, GitResult, GitCryptConfig};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use serde::{Deserialize, Serialize};

/// Configuration for git attributes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributeConfig {
    /// Encryption patterns with their attributes
    pub patterns: HashMap<String, String>,
    /// Custom filter configurations
    pub filters: HashMap<String, FilterConfig>,
    /// Whether to use clean/smudge filters
    pub enable_filters: bool,
    /// Default encryption attribute name
    pub default_encrypt_attr: String,
}

impl Default for AttributeConfig {
    fn default() -> Self {
        let mut patterns = HashMap::new();
        patterns.insert("*.secret".to_string(), "cargocrypt-encrypt".to_string());
        patterns.insert("*.key".to_string(), "cargocrypt-encrypt".to_string());
        patterns.insert("secrets/*".to_string(), "cargocrypt-encrypt".to_string());
        patterns.insert("config/secrets.*".to_string(), "cargocrypt-encrypt".to_string());
        patterns.insert("*.env.local".to_string(), "cargocrypt-encrypt".to_string());
        patterns.insert("*.env.production".to_string(), "cargocrypt-encrypt".to_string());
        
        let mut filters = HashMap::new();
        filters.insert("cargocrypt-encrypt".to_string(), FilterConfig {
            clean: "cargocrypt filter-clean %f".to_string(),
            smudge: "cargocrypt filter-smudge %f".to_string(),
            required: true,
        });
        
        Self {
            patterns,
            filters,
            enable_filters: true,
            default_encrypt_attr: "cargocrypt-encrypt".to_string(),
        }
    }
}

/// Git filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    /// Clean filter command (for staging)
    pub clean: String,
    /// Smudge filter command (for checkout)
    pub smudge: String,
    /// Whether the filter is required
    pub required: bool,
}

/// Represents an encryption pattern for git attributes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionPattern {
    /// File pattern (e.g., "*.secret")
    pub pattern: String,
    /// Attribute name (e.g., "cargocrypt-encrypt")
    pub attribute: String,
    /// Additional attributes
    pub extra_attrs: Vec<String>,
}

impl EncryptionPattern {
    /// Create a new encryption pattern
    pub fn new(pattern: &str, attribute: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            attribute: attribute.to_string(),
            extra_attrs: Vec::new(),
        }
    }
    
    /// Add an additional attribute
    pub fn with_attr(mut self, attr: &str) -> Self {
        self.extra_attrs.push(attr.to_string());
        self
    }
    
    /// Convert to gitattributes line format
    pub fn to_line(&self) -> String {
        let mut line = format!("{} {}", self.pattern, self.attribute);
        
        for attr in &self.extra_attrs {
            line.push(' ');
            line.push_str(attr);
        }
        
        line
    }
    
    /// Parse from gitattributes line
    pub fn from_line(line: &str) -> Option<Self> {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        
        if parts.len() >= 2 {
            let pattern = parts[0].to_string();
            let attribute = parts[1].to_string();
            let extra_attrs = parts[2..].iter().map(|s| s.to_string()).collect();
            
            Some(Self {
                pattern,
                attribute,
                extra_attrs,
            })
        } else {
            None
        }
    }
    
    /// Check if this pattern matches a file path
    pub fn matches_path(&self, path: &Path) -> bool {
        // Simple pattern matching - could be enhanced with glob patterns
        let path_str = path.to_string_lossy();
        
        if self.pattern.starts_with("*.") {
            let extension = &self.pattern[2..];
            path_str.ends_with(&format!(".{}", extension))
        } else if self.pattern.ends_with("/*") {
            let dir = &self.pattern[..self.pattern.len() - 2];
            path_str.starts_with(&format!("{}/", dir))
        } else {
            path_str == self.pattern
        }
    }
}

/// Manages .gitattributes file for CargoCrypt integration
pub struct GitAttributes {
    repo: GitRepo,
    attributes_path: PathBuf,
    patterns: Vec<EncryptionPattern>,
    config: AttributeConfig,
}

impl GitAttributes {
    /// Create a new GitAttributes manager
    pub fn new(repo: &GitRepo) -> GitResult<Self> {
        let attributes_path = repo.workdir().join(".gitattributes");
        let config = AttributeConfig::default();
        
        Ok(Self {
            repo: repo.clone(),
            attributes_path,
            patterns: Vec::new(),
            config,
        })
    }
    
    /// Create with custom configuration
    pub fn with_config(repo: &GitRepo, config: AttributeConfig) -> GitResult<Self> {
        let attributes_path = repo.workdir().join(".gitattributes");
        
        Ok(Self {
            repo: repo.clone(),
            attributes_path,
            patterns: Vec::new(),
            config,
        })
    }
    
    /// Load existing .gitattributes file
    pub async fn load(&mut self) -> GitResult<()> {
        if self.attributes_path.exists() {
            let content = fs::read_to_string(&self.attributes_path).await
                .map_err(|e| GitError::AttributesFailed(format!("Failed to read .gitattributes: {}", e)))?;
            
            self.patterns = content
                .lines()
                .filter(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
                .filter_map(EncryptionPattern::from_line)
                .collect();
        }
        
        Ok(())
    }
    
    /// Save .gitattributes file
    pub async fn save(&self) -> GitResult<()> {
        let mut content = String::new();
        
        // Add header comment
        content.push_str("# CargoCrypt - Automatic encryption patterns\n");
        content.push_str("# Files matching these patterns will be automatically encrypted/decrypted\n\n");
        
        // Add patterns
        for pattern in &self.patterns {
            content.push_str(&pattern.to_line());
            content.push('\n');
        }
        
        fs::write(&self.attributes_path, content).await
            .map_err(|e| GitError::AttributesFailed(format!("Failed to write .gitattributes: {}", e)))?;
        
        Ok(())
    }
    
    /// Add an encryption pattern
    pub async fn add_pattern(&mut self, pattern: &str, attribute: &str) -> GitResult<()> {
        let encryption_pattern = EncryptionPattern::new(pattern, attribute);
        
        // Check if pattern already exists
        if !self.patterns.iter().any(|p| p.pattern == pattern) {
            self.patterns.push(encryption_pattern);
        }
        
        Ok(())
    }
    
    /// Add default CargoCrypt patterns
    pub async fn add_cargocrypt_patterns(&mut self) -> GitResult<()> {
        for (pattern, attribute) in &self.config.patterns {
            self.add_pattern(pattern, attribute).await?;
        }
        
        Ok(())
    }
    
    /// Configure git filters for automatic clean/smudge
    pub async fn configure_filters(&self, git_config: &GitCryptConfig) -> GitResult<()> {
        if !self.config.enable_filters {
            return Ok(());
        }
        
        let git_config_path = self.repo.git_dir().join("config");
        
        // Read existing git config
        let mut config_content = if git_config_path.exists() {
            fs::read_to_string(&git_config_path).await
                .map_err(|e| GitError::AttributesFailed(format!("Failed to read git config: {}", e)))?
        } else {
            String::new()
        };
        
        // Add filter configurations
        for (filter_name, filter_config) in &self.config.filters {
            let filter_section = format!(
                "\n[filter \"{}\"]\n\tclean = {}\n\tsmudge = {}\n\trequired = {}\n",
                filter_name,
                filter_config.clean,
                filter_config.smudge,
                filter_config.required
            );
            
            // Check if filter already exists
            if !config_content.contains(&format!("[filter \"{}\"]", filter_name)) {
                config_content.push_str(&filter_section);
            }
        }
        
        fs::write(&git_config_path, config_content).await
            .map_err(|e| GitError::AttributesFailed(format!("Failed to write git config: {}", e)))?;
        
        Ok(())
    }
    
    /// Check if a file should be encrypted based on patterns
    pub fn should_encrypt(&self, file_path: &Path) -> bool {
        self.patterns.iter().any(|pattern| pattern.matches_path(file_path))
    }
    
    /// Get encryption attribute for a file
    pub fn get_encryption_attribute(&self, file_path: &Path) -> Option<&str> {
        self.patterns
            .iter()
            .find(|pattern| pattern.matches_path(file_path))
            .map(|pattern| pattern.attribute.as_str())
    }
    
    /// Check if CargoCrypt patterns are present
    pub fn has_cargocrypt_patterns(&self) -> bool {
        self.patterns.iter().any(|p| {
            p.attribute.contains("cargocrypt") || 
            p.pattern.contains("secret") ||
            p.pattern.contains("*.key")
        })
    }
    
    /// Remove CargoCrypt patterns
    pub async fn remove_cargocrypt_patterns(&mut self) -> GitResult<()> {
        self.patterns.retain(|p| !p.attribute.contains("cargocrypt"));
        Ok(())
    }
    
    /// Get patterns that match a specific attribute
    pub fn get_patterns_for_attribute(&self, attribute: &str) -> Vec<&EncryptionPattern> {
        self.patterns
            .iter()
            .filter(|p| p.attribute == attribute)
            .collect()
    }
    
    /// Update patterns based on project structure analysis
    pub async fn update_smart_patterns(&mut self) -> GitResult<()> {
        let workdir = self.repo.workdir();
        
        // Scan for common secret file patterns
        let mut discovered_patterns = Vec::new();
        
        // Check for environment files
        for env_file in ["*.env", "*.env.local", "*.env.production", "*.env.staging"] {
            if self.has_files_matching_pattern(env_file).await? {
                discovered_patterns.push((env_file.to_string(), self.config.default_encrypt_attr.clone()));
            }
        }
        
        // Check for key files
        for key_pattern in ["*.pem", "*.key", "*.p12", "*.pfx", "id_rsa", "id_ed25519"] {
            if self.has_files_matching_pattern(key_pattern).await? {
                discovered_patterns.push((key_pattern.to_string(), self.config.default_encrypt_attr.clone()));
            }
        }
        
        // Check for config directories
        for config_dir in ["secrets/", "config/secrets/", "keys/", "certs/"] {
            let dir_path = workdir.join(config_dir);
            if dir_path.exists() && dir_path.is_dir() {
                discovered_patterns.push((format!("{}*", config_dir), self.config.default_encrypt_attr.clone()));
            }
        }
        
        // Add discovered patterns
        for (pattern, attribute) in discovered_patterns {
            self.add_pattern(&pattern, &attribute).await?;
        }
        
        Ok(())
    }
    
    /// Check if files matching a pattern exist
    async fn has_files_matching_pattern(&self, pattern: &str) -> GitResult<bool> {
        let workdir = self.repo.workdir();
        
        // Use walkdir to search for matching files
        use walkdir::WalkDir;
        
        for entry in WalkDir::new(workdir).max_depth(3) {
            let entry = entry.map_err(|e| GitError::AttributesFailed(format!("Walk error: {}", e)))?;
            let path = entry.path();
            
            if path.is_file() {
                let relative_path = path.strip_prefix(workdir).unwrap_or(path);
                let test_pattern = EncryptionPattern::new(pattern, "test");
                
                if test_pattern.matches_path(relative_path) {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }
    
    /// Validate attribute configurations
    pub fn validate_attributes(&self) -> GitResult<Vec<String>> {
        let mut warnings = Vec::new();
        
        // Check for conflicting patterns
        for (i, pattern1) in self.patterns.iter().enumerate() {
            for (j, pattern2) in self.patterns.iter().enumerate() {
                if i != j && pattern1.pattern == pattern2.pattern && pattern1.attribute != pattern2.attribute {
                    warnings.push(format!(
                        "Conflicting attributes for pattern '{}': '{}' and '{}'",
                        pattern1.pattern, pattern1.attribute, pattern2.attribute
                    ));
                }
            }
        }
        
        // Check for overly broad patterns
        for pattern in &self.patterns {
            if pattern.pattern == "*" {
                warnings.push("Pattern '*' will encrypt all files - this may not be intended".to_string());
            }
        }
        
        Ok(warnings)
    }
    
    /// Export patterns for use in other tools (git-crypt format)
    pub fn export_git_crypt_format(&self) -> String {
        let mut output = String::new();
        output.push_str("# git-crypt compatible format\n");
        
        for pattern in &self.patterns {
            if pattern.attribute.contains("encrypt") {
                output.push_str(&format!("{} filter=git-crypt diff=git-crypt\n", pattern.pattern));
            }
        }
        
        output
    }
    
    /// Import patterns from git-crypt format
    pub async fn import_git_crypt_patterns(&mut self, content: &str) -> GitResult<()> {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1].contains("git-crypt") {
                self.add_pattern(parts[0], &self.config.default_encrypt_attr).await?;
            }
        }
        
        Ok(())
    }
    
    /// Get all patterns
    pub fn get_patterns(&self) -> &[EncryptionPattern] {
        &self.patterns
    }
    
    /// Get the repository reference
    pub fn repo(&self) -> &GitRepo {
        &self.repo
    }
    
    /// Get the .gitattributes file path
    pub fn path(&self) -> &Path {
        &self.attributes_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs::File;
    use std::io::Write;
    
    #[tokio::test]
    async fn test_git_attributes_creation() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let attributes = GitAttributes::new(&repo).unwrap();
        
        assert_eq!(attributes.path(), &temp_dir.path().join(".gitattributes"));
    }
    
    #[tokio::test]
    async fn test_pattern_operations() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let mut attributes = GitAttributes::new(&repo).unwrap();
        
        attributes.add_pattern("*.secret", "cargocrypt-encrypt").await.unwrap();
        
        assert_eq!(attributes.patterns.len(), 1);
        assert!(attributes.should_encrypt(Path::new("test.secret")));
        assert!(!attributes.should_encrypt(Path::new("test.txt")));
    }
    
    #[test]
    fn test_encryption_pattern() {
        let pattern = EncryptionPattern::new("*.secret", "cargocrypt-encrypt")
            .with_attr("binary");
        
        assert_eq!(pattern.to_line(), "*.secret cargocrypt-encrypt binary");
        
        // Test parsing
        let parsed = EncryptionPattern::from_line("*.key cargocrypt-encrypt required").unwrap();
        assert_eq!(parsed.pattern, "*.key");
        assert_eq!(parsed.attribute, "cargocrypt-encrypt");
        assert_eq!(parsed.extra_attrs, vec!["required"]);
    }
    
    #[test]
    fn test_pattern_matching() {
        let pattern = EncryptionPattern::new("*.secret", "cargocrypt-encrypt");
        
        assert!(pattern.matches_path(Path::new("test.secret")));
        assert!(pattern.matches_path(Path::new("config/prod.secret")));
        assert!(!pattern.matches_path(Path::new("test.txt")));
        
        let dir_pattern = EncryptionPattern::new("secrets/*", "cargocrypt-encrypt");
        assert!(dir_pattern.matches_path(Path::new("secrets/api.key")));
        assert!(!dir_pattern.matches_path(Path::new("config/api.key")));
    }
    
    #[tokio::test]
    async fn test_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let mut attributes = GitAttributes::new(&repo).unwrap();
        
        attributes.add_pattern("*.test", "cargocrypt-encrypt").await.unwrap();
        attributes.save().await.unwrap();
        
        let mut attributes2 = GitAttributes::new(&repo).unwrap();
        attributes2.load().await.unwrap();
        
        assert!(attributes2.should_encrypt(Path::new("file.test")));
    }
    
    #[tokio::test]
    async fn test_cargocrypt_patterns() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let mut attributes = GitAttributes::new(&repo).unwrap();
        
        attributes.add_cargocrypt_patterns().await.unwrap();
        
        assert!(attributes.has_cargocrypt_patterns());
        assert!(attributes.should_encrypt(Path::new("api.secret")));
        assert!(attributes.should_encrypt(Path::new("secrets/database.key")));
    }
}