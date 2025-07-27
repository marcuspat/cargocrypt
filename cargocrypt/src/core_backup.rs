//! Core CargoCrypt functionality
//!
//! This module provides the main CargoCrypt struct and configuration types
//! for zero-config cryptographic operations.

use crate::error::{CargoCryptError, CryptoResult};
use crate::crypto::{CryptoEngine, PerformanceProfile, EncryptedSecret, PlaintextSecret, MemorySecretStore, EncryptionOptions, SecretStore};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure bytes wrapper that zeroizes memory on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Create from a string
    pub fn from_str(s: &str) -> Self {
        Self {
            inner: s.as_bytes().to_vec(),
        }
    }
    
    /// Get the length
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    
    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    
    /// Convert to string lossy
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.inner).to_string()
    }
    
    /// Get a reference to the inner bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
}

/// Main CargoCrypt struct providing cryptographic operations
///
/// This struct embodies the zero-config philosophy - it works out of the box
/// with sensible defaults while allowing customization when needed.
#[derive(Debug, Clone)]
pub struct CargoCrypt {
    /// Cryptographic engine for operations
    engine: Arc<CryptoEngine>,
    /// Configuration settings
    config: Arc<RwLock<CryptoConfig>>,
    /// Project root directory
    project_root: PathBuf,
    /// Secret store for memory-safe secret management
    secret_store: Arc<dyn SecretStore>,
}

/// Configuration for CargoCrypt operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Default performance profile for encryption
    pub performance_profile: PerformanceProfile,
    /// Key derivation parameters
    pub key_params: KeyDerivationConfig,
    /// File operation settings
    pub file_ops: FileOperationConfig,
    /// Security settings
    pub security: SecurityConfig,
    /// Performance settings
    pub performance: PerformanceConfig,
}

/// Key derivation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationConfig {
    /// Memory cost in KiB (default: 65536 = 64 MB)
    pub memory_cost: u32,
    /// Time cost (iterations, default: 3)
    pub time_cost: u32,
    /// Parallelism (default: 4)
    pub parallelism: u32,
    /// Output length in bytes (default: 32)
    pub output_length: u32,
}

/// File operation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileOperationConfig {
    /// Backup original files before encryption
    pub backup_originals: bool,
    /// File extension for encrypted files
    pub encrypted_extension: String,
    /// Buffer size for file operations
    pub buffer_size: usize,
    /// Preserve file permissions
    pub preserve_permissions: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Require password confirmation for destructive operations
    pub require_confirmation: bool,
    /// Automatically zeroize sensitive data
    pub auto_zeroize: bool,
    /// Fail secure by default
    pub fail_secure: bool,
    /// Maximum password attempts
    pub max_password_attempts: u32,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Enable async operations
    pub async_operations: bool,
    /// Number of concurrent operations
    pub max_concurrent_ops: usize,
    /// Enable progress reporting
    pub progress_reporting: bool,
    /// Cache frequently used keys
    pub key_caching: bool,
}


/// Memory-safe secret storage with automatic zeroization
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Create a new secret from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { inner: data }
    }
    
    /// Create a new secret from a string
    pub fn from_str(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }
    
    /// Get the secret data (careful with this!)
    pub fn expose_secret(&self) -> &[u8] {
        &self.inner
    }
    
    /// Get the length of the secret
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    
    /// Check if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    
    /// Convert to a string (if valid UTF-8)
    pub fn to_string_lossy(&self) -> String {
        String::from_utf8_lossy(&self.inner).to_string()
    }
}

/// In-memory secret store implementation
#[derive(Debug, Default)]
pub struct InMemorySecretStore {
    secrets: Arc<RwLock<std::collections::HashMap<String, SecretBytes>>>,
}

impl InMemorySecretStore {
    /// Create a new in-memory secret store
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
}

impl SecretStore for InMemorySecretStore {
    fn store_secret(&self, key: &str, secret: SecretBytes) -> CryptoResult<()> {
        let mut secrets = self.secrets.blocking_write();
        secrets.insert(key.to_string(), secret);
        Ok(())
    }
    
    fn get_secret(&self, key: &str) -> CryptoResult<Option<SecretBytes>> {
        let secrets = self.secrets.blocking_read();
        Ok(secrets.get(key).cloned())
    }
    
    fn remove_secret(&self, key: &str) -> CryptoResult<bool> {
        let mut secrets = self.secrets.blocking_write();
        Ok(secrets.remove(key).is_some())
    }
    
    fn clear_all(&self) -> CryptoResult<()> {
        let mut secrets = self.secrets.blocking_write();
        secrets.clear();
        Ok(())
    }
    
    fn contains_secret(&self, key: &str) -> bool {
        let secrets = self.secrets.blocking_read();
        secrets.contains_key(key)
    }
    
    fn secret_count(&self) -> usize {
        let secrets = self.secrets.blocking_read();
        secrets.len()
    }
}

/// Default implementations for configuration structs
impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            performance_profile: PerformanceProfile::Balanced,
            key_params: KeyDerivationConfig::default(),
            file_ops: FileOperationConfig::default(),
            security: SecurityConfig::default(),
            performance: PerformanceConfig::default(),
        }
    }
}

impl Default for KeyDerivationConfig {
    fn default() -> Self {
        Self {
            memory_cost: 65536,    // 64 MB
            time_cost: 3,          // 3 iterations
            parallelism: 4,        // 4 parallel threads
            output_length: 32,     // 32 bytes (256 bits)
        }
    }
}

impl Default for FileOperationConfig {
    fn default() -> Self {
        Self {
            backup_originals: true,
            encrypted_extension: "enc".to_string(),
            buffer_size: 64 * 1024, // 64 KB buffer
            preserve_permissions: true,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            require_confirmation: true,
            auto_zeroize: true,
            fail_secure: true,
            max_password_attempts: 3,
        }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            async_operations: true,
            max_concurrent_ops: 4,
            progress_reporting: true,
            key_caching: true,
        }
    }
}

/// Builder for constructing CargoCrypt instances with custom configuration
pub struct CargoCryptBuilder {
    config: Option<CryptoConfig>,
    project_root: Option<PathBuf>,
}

/// Implementation of CargoCrypt main functionality
impl CargoCryptBuilder {
    /// Create a new builder instance
    pub fn new() -> Self {
        Self {
            config: None,
            project_root: None,
        }
    }

    /// Set custom configuration
    pub fn config(mut self, config: CryptoConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set project root directory
    pub fn project_root<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.project_root = Some(path.as_ref().to_path_buf());
        self
    }

    /// Build the CargoCrypt instance
    pub async fn build(self) -> CryptoResult<CargoCrypt> {
        let config = self.config.unwrap_or_default();
        let project_root = match self.project_root {
            Some(root) => root,
            None => crate::utils::find_project_root()?,
        };

        // Initialize crypto engine and secret store
        let engine = Arc::new(CryptoEngine::new());
        let secret_store = Arc::new(MemorySecretStore::new());

        Ok(CargoCrypt {
            engine,
            config: Arc::new(RwLock::new(config)),
            project_root,
            secret_store,
        })
    }
}

impl CargoCrypt {
    /// Create a new CargoCrypt instance with default configuration
    ///
    /// This is the zero-config entry point - it automatically:
    /// - Detects the current project structure
    /// - Loads or creates configuration
    /// - Initializes crypto engine with secure defaults
    /// - Sets up memory-safe secret storage
    pub async fn new() -> CryptoResult<Self> {
        let config = CryptoConfig::default();
        Self::with_config(config).await
    }
    
    /// Create a new CargoCrypt instance with custom configuration
    pub async fn with_config(config: CryptoConfig) -> CryptoResult<Self> {
        let project_root = crate::utils::find_project_root()?;
        let engine = Arc::new(CryptoEngine::with_performance_profile(config.performance_profile));
        let secret_store = Arc::new(InMemorySecretStore::new());
        
        Ok(Self {
            engine,
            config: Arc::new(RwLock::new(config)),
            project_root,
            secret_store,
        })
    }
    
    /// Create a builder for configuring CargoCrypt instances
    ///
    /// This method returns a `CargoCryptBuilder` that allows for fluent
    /// configuration of CargoCrypt instances with custom settings.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use cargocrypt::CargoCrypt;
    /// use cargocrypt::crypto::PerformanceProfile;
    ///
    /// # #[tokio::main]
    /// # async fn main() -> anyhow::Result<()> {
    /// let crypt = CargoCrypt::builder()
    ///     .performance_profile(PerformanceProfile::Secure)
    ///     .project_root("/path/to/project")
    ///     .build()
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn builder() -> CargoCryptBuilder {
        CargoCryptBuilder::new()
    }
    
    /// Initialize CargoCrypt in a project directory
    ///
    /// This creates the necessary configuration files and directory structure
    /// if they don't already exist.
    pub async fn init_project() -> CryptoResult<()> {
        let project_root = crate::utils::find_project_root()?;
        let config_dir = project_root.join(".cargocrypt");
        
        // Create configuration directory
        if !config_dir.exists() {
            tokio::fs::create_dir_all(&config_dir).await?;
        }
        
        // Create default configuration file
        let config_path = config_dir.join("config.toml");
        if !config_path.exists() {
            let default_config = CryptoConfig::default();
            let config_toml = toml::to_string_pretty(&default_config)
                .map_err(|e| CargoCryptError::Serialization {
                    message: "Failed to serialize default configuration".to_string(),
                    source: Box::new(e),
                })?;
            tokio::fs::write(&config_path, config_toml).await?;
        }
        
        // Create .gitignore entry for secrets
        let gitignore_path = project_root.join(".gitignore");
        let gitignore_entry = "\n# CargoCrypt secrets\n.cargocrypt/secrets/\n*.enc\n";
        
        if gitignore_path.exists() {
            let existing_content = tokio::fs::read_to_string(&gitignore_path).await?;
            if !existing_content.contains(".cargocrypt/secrets/") {
                tokio::fs::write(&gitignore_path, existing_content + gitignore_entry).await?;
            }
        } else {
            tokio::fs::write(&gitignore_path, gitignore_entry).await?;
        }
        
        Ok(())
    }
    
    /// Encrypt a file with the current configuration
    pub async fn encrypt_file<P: AsRef<Path>>(&self, path: P, password: &str) -> CryptoResult<PathBuf> {
        let path = path.as_ref();
        let config = self.config.read().await;
        
        // Generate output path
        // For files with extensions, replace the extension with "original_ext.enc"
        // For files without extensions (including dotfiles), just append ".enc"
        let output_path = if let Some(ext) = path.extension() {
            path.with_extension(format!("{}.{}", ext.to_string_lossy(), config.file_ops.encrypted_extension))
        } else {
            // No extension, just append .enc
            let mut path_str = path.to_string_lossy().into_owned();
            path_str.push('.');
            path_str.push_str(&config.file_ops.encrypted_extension);
            PathBuf::from(path_str)
        };
        
        // Read input file
        let input_data = tokio::fs::read(path).await?;
        
        // Encrypt the data
        let encrypted = self.engine.encrypt_data(&input_data, password)?;
        
        // Write encrypted data to output file
        let encrypted_bytes = bincode::serialize(&encrypted)
            .map_err(|e| CargoCryptError::Serialization {
                message: format!("Failed to serialize encrypted data: {}", e),
                source: Box::new(e),
            })?;
        
        tokio::fs::write(&output_path, encrypted_bytes).await?;
        
        // Handle backup if configured
        if config.file_ops.backup_originals {
            let backup_path = if let Some(ext) = path.extension() {
                path.with_extension(format!("{}.backup", ext.to_string_lossy()))
            } else {
                // No extension, just append .backup
                let mut path_str = path.to_string_lossy().into_owned();
                path_str.push_str(".backup");
                PathBuf::from(path_str)
            };
            tokio::fs::copy(path, backup_path).await?;
        }
        
        Ok(output_path)
    }
    
    /// Decrypt a file with the current configuration
    pub async fn decrypt_file<P: AsRef<Path>>(&self, path: P, password: &str) -> CryptoResult<PathBuf> {
        let path = path.as_ref();
        let config = self.config.read().await;
        
        // Generate output path (remove .enc extension)
        let path_str = path.to_string_lossy();
        let enc_ext = format!(".{}", config.file_ops.encrypted_extension);
        
        let output_path = if path_str.ends_with(&enc_ext) {
            // Remove the .enc extension
            let new_path = path_str[..path_str.len() - enc_ext.len()].to_string();
            PathBuf::from(new_path)
        } else {
            return Err(CargoCryptError::Config {
                message: format!("File '{}' doesn't appear to be encrypted", path.display()),
                suggestion: Some(format!("Encrypted files should have the .{} extension", config.file_ops.encrypted_extension).to_string()),
            });
        };
        
        // Read encrypted file
        let encrypted_data = tokio::fs::read(path).await?;
        
        // Deserialize encrypted data
        let encrypted: EncryptedSecret = bincode::deserialize(&encrypted_data)
            .map_err(|e| CargoCryptError::Serialization {
                message: format!("Failed to deserialize encrypted data: {}", e),
                source: Box::new(e),
            })?;
        
        // Decrypt the data
        let decrypted_data = self.engine.decrypt_data(&encrypted, password)?;
        
        // Write decrypted data to output file
        tokio::fs::write(&output_path, decrypted_data).await?;
        
        Ok(output_path)
    }
    
    /// Get the current configuration
    pub async fn config(&self) -> CryptoConfig {
        self.config.read().await.clone()
    }
    
    /// Update the configuration
    pub async fn update_config<F>(&self, updater: F) -> CryptoResult<()>
    where
        F: FnOnce(&mut CryptoConfig),
    {
        let mut config = self.config.write().await;
        updater(&mut *config);
        Ok(())
    }
    
    /// Get the project root directory
    pub fn project_root(&self) -> &Path {
        &self.project_root
    }
    
    /// Get a reference to the secret store
    pub fn secret_store(&self) -> &dyn SecretStore {
        self.secret_store.as_ref()
    }
    
    /// Get the crypto engine
    pub fn engine(&self) -> &CryptoEngine {
        &self.engine
    }
    
    /// Get the crypto engine
    pub fn crypto_engine(&self) -> &CryptoEngine {
        &self.engine
    }
}


impl Default for CargoCryptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Implementation of useful trait methods
impl CryptoConfig {
    /// Get the list of supported performance profiles
    pub fn performance_profiles(&self) -> Vec<PerformanceProfile> {
        vec![
            PerformanceProfile::Fast,
            PerformanceProfile::Balanced,
            PerformanceProfile::Secure,
            PerformanceProfile::Paranoid,
        ]
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> CryptoResult<()> {
        // Validate key derivation parameters
        if self.key_params.memory_cost < 1024 {
            return Err(CargoCryptError::Config {
                message: "Memory cost too low (minimum 1024 KiB)".to_string(),
                suggestion: Some("Increase memory_cost to at least 1024 for security".to_string()),
            });
        }
        
        if self.key_params.time_cost < 1 {
            return Err(CargoCryptError::Config {
                message: "Time cost too low (minimum 1)".to_string(),
                suggestion: Some("Increase time_cost to at least 1".to_string()),
            });
        }
        
        if self.key_params.parallelism < 1 {
            return Err(CargoCryptError::Config {
                message: "Parallelism too low (minimum 1)".to_string(),
                suggestion: Some("Increase parallelism to at least 1".to_string()),
            });
        }
        
        // Validate file operations
        if self.file_ops.buffer_size < 1024 {
            return Err(CargoCryptError::Config {
                message: "Buffer size too small (minimum 1024 bytes)".to_string(),
                suggestion: Some("Increase buffer_size to at least 1024".to_string()),
            });
        }
        
        // Validate security settings
        if self.security.max_password_attempts < 1 {
            return Err(CargoCryptError::Config {
                message: "Max password attempts too low (minimum 1)".to_string(),
                suggestion: Some("Increase max_password_attempts to at least 1".to_string()),
            });
        }
        
        // Validate performance settings
        if self.performance.max_concurrent_ops < 1 {
            return Err(CargoCryptError::Config {
                message: "Max concurrent operations too low (minimum 1)".to_string(),
                suggestion: Some("Increase max_concurrent_ops to at least 1".to_string()),
            });
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_config() {
        let config = CryptoConfig::default();
        assert_eq!(config.performance_profile, PerformanceProfile::Balanced);
        assert_eq!(config.key_params.memory_cost, 65536);
        assert_eq!(config.key_params.time_cost, 3);
        assert_eq!(config.key_params.parallelism, 4);
        assert_eq!(config.file_ops.encrypted_extension, "enc");
        assert!(config.security.fail_secure);
        assert!(config.performance.async_operations);
    }
    
    #[test]
    fn test_config_validation() {
        let mut config = CryptoConfig::default();
        assert!(config.validate().is_ok());
        
        config.key_params.memory_cost = 512; // Too low
        assert!(config.validate().is_err());
        
        config.key_params.memory_cost = 65536; // Reset
        config.security.max_password_attempts = 0; // Too low
        assert!(config.validate().is_err());
    }
    
    #[tokio::test]
    async fn test_secret_store() {
        let store = InMemorySecretStore::new();
        let secret = SecretBytes::from_str("test-secret");
        
        // Store and retrieve
        store.store_secret("test-key", secret.clone()).unwrap();
        let retrieved = store.get_secret("test-key").unwrap().unwrap();
        assert_eq!(retrieved.expose_secret(), secret.expose_secret());
        
        // Check existence
        assert!(store.contains_secret("test-key"));
        assert!(!store.contains_secret("non-existent"));
        
        // Remove
        assert!(store.remove_secret("test-key").unwrap());
        assert!(!store.contains_secret("test-key"));
    }
    
    #[test]
    fn test_secret_bytes_zeroization() {
        let mut secret = SecretBytes::from_str("sensitive-data");
        assert!(!secret.is_empty());
        assert_eq!(secret.len(), 14);
        
        // Zeroize should be called automatically on drop
        drop(secret);
        // Note: We can't test the actual zeroization since the data is dropped
        // but the Zeroize trait ensures it happens
    }
    
    #[test]
    fn test_builder_pattern() {
        let builder = CargoCryptBuilder::new()
            .performance_profile(PerformanceProfile::Secure)
            .project_root("/tmp/test");
        
        // The builder should be configurable
        assert_eq!(builder.config.performance_profile, PerformanceProfile::Secure);
    }
    
    #[tokio::test]
    async fn test_filename_extension_handling() {
        use tempfile::TempDir;
        
        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Create test instance
        let cargocrypt = CargoCrypt::builder()
            .project_root(temp_path)
            .build()
            .await
            .unwrap();
        
        // Test cases: (input_filename, expected_encrypted_filename)
        let test_cases = vec![
            (".env", ".env.enc"),
            ("secrets.txt", "secrets.txt.enc"),
            ("config.json", "config.json.enc"),
            (".gitignore", ".gitignore.enc"),
            ("file.tar.gz", "file.tar.gz.enc"),
            ("noextension", "noextension.enc"),
        ];
        
        let password = "test-password";
        
        for (input_file, expected_encrypted) in test_cases {
            // Create test file
            let input_path = temp_path.join(input_file);
            tokio::fs::write(&input_path, format!("Test content for {}", input_file))
                .await
                .unwrap();
            
            // Encrypt the file
            let encrypted_path = cargocrypt.encrypt_file(&input_path, password)
                .await
                .unwrap();
            
            // Check the encrypted filename
            assert_eq!(
                encrypted_path.file_name().unwrap().to_str().unwrap(),
                expected_encrypted,
                "Failed encryption naming for {}",
                input_file
            );
            
            // Verify encrypted file exists
            assert!(encrypted_path.exists(), "Encrypted file doesn't exist for {}", input_file);
            
            // Now decrypt it back
            let decrypted_path = cargocrypt.decrypt_file(&encrypted_path, password)
                .await
                .unwrap();
            
            // Check the decrypted filename matches the original
            assert_eq!(
                decrypted_path.file_name().unwrap().to_str().unwrap(),
                input_file,
                "Failed decryption naming for {}",
                expected_encrypted
            );
            
            // Verify content is the same
            let decrypted_content = tokio::fs::read_to_string(&decrypted_path)
                .await
                .unwrap();
            assert_eq!(
                decrypted_content,
                format!("Test content for {}", input_file),
                "Content mismatch after decrypt for {}",
                input_file
            );
            
            // Cleanup
            let _ = tokio::fs::remove_file(&input_path).await;
            let _ = tokio::fs::remove_file(&encrypted_path).await;
            let _ = tokio::fs::remove_file(&decrypted_path).await;
        }
    }
}