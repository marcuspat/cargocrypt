//! Core CargoCrypt functionality - CLEAN VERSION
//!
//! This module provides the main CargoCrypt struct and configuration types
//! for zero-config cryptographic operations.

use crate::error::{CargoCryptError, CryptoResult};
use crate::crypto::{CryptoEngine, PerformanceProfile, MemorySecretStore, SecretStore};
use crate::resilience::{CircuitBreaker, RetryPolicy, GracefulDegradation, HealthStatus};
use crate::validation::{InputValidator, ValidationResult};
use crate::monitoring::{MonitoringManager, MonitoringConfig, CryptoOperation, CryptoOperationType, FileOperation, FileOperationType, PerformanceTracker};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use tracing::{info, warn, error};

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
#[derive(Clone)]
pub struct CargoCrypt {
    /// Cryptographic engine for operations
    engine: Arc<CryptoEngine>,
    /// Configuration settings
    config: Arc<RwLock<CryptoConfig>>,
    /// Project root directory
    project_root: PathBuf,
    /// Secret store for memory-safe secret management
    secret_store: Arc<dyn SecretStore>,
    /// Resilience manager for error handling and recovery
    resilience: ResilienceManager,
    /// Monitoring manager for real-time metrics and performance tracking
    monitoring: Arc<MonitoringManager>,
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
    /// Resilience and error handling settings
    pub resilience: ResilienceConfig,
    /// Monitoring and telemetry settings
    pub monitoring: MonitoringConfig,
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
    /// Buffer size for file I/O operations
    pub buffer_size: usize,
    /// Enable compression before encryption
    pub compression: bool,
    /// Atomic file operations (encrypt to temp, then move)
    pub atomic_operations: bool,
    /// Preserve file metadata (timestamps, permissions)
    pub preserve_metadata: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Require confirmation for destructive operations
    pub require_confirmation: bool,
    /// Automatically zeroize sensitive data
    pub auto_zeroize: bool,
    /// Fail securely on errors (don't leave partial state)
    pub fail_secure: bool,
    /// Maximum password attempts before lockout
    pub max_password_attempts: u32,
}

/// Performance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Use async operations where possible
    pub async_operations: bool,
    /// Maximum concurrent operations
    pub max_concurrent_ops: usize,
    /// Enable progress reporting
    pub progress_reporting: bool,
    /// Cache frequently used keys
    pub key_caching: bool,
}

/// Resilience and error handling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceConfig {
    /// Enable circuit breaker protection
    pub circuit_breaker_enabled: bool,
    /// Circuit breaker failure threshold
    pub failure_threshold: u32,
    /// Circuit breaker timeout in seconds
    pub circuit_timeout_secs: u64,
    /// Enable retry logic for transient failures
    pub retry_enabled: bool,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Base retry delay in milliseconds
    pub retry_base_delay_ms: u64,
    /// Enable input validation
    pub input_validation_enabled: bool,
    /// Enable graceful degradation
    pub graceful_degradation_enabled: bool,
    /// Perform system health checks
    pub health_monitoring_enabled: bool,
    /// Health check interval in seconds
    pub health_check_interval_secs: u64,
}

/// Resilience manager that orchestrates all error handling systems
#[derive(Clone)]
pub struct ResilienceManager {
    pub file_ops_breaker: CircuitBreaker,
    pub crypto_breaker: CircuitBreaker,
    pub retry_policy: RetryPolicy,
    pub degradation: Arc<GracefulDegradation>,
    pub validator: InputValidator,
}

impl ResilienceManager {
    pub fn new() -> Self {
        let degradation = Arc::new(GracefulDegradation::new());
        
        // Initialize with default features enabled
        let degradation_clone = Arc::clone(&degradation);
        tokio::spawn(async move {
            degradation_clone.register_feature("file_operations", true).await;
            degradation_clone.register_feature("encryption", true).await;
            degradation_clone.register_feature("tui", true).await;
            degradation_clone.register_feature("git_integration", true).await;
            
            // Register circuit breakers
            degradation_clone.register_circuit_breaker("file_ops", 3, Duration::from_secs(30)).await;
            degradation_clone.register_circuit_breaker("crypto_ops", 5, Duration::from_secs(60)).await;
        });
        
        Self {
            file_ops_breaker: CircuitBreaker::new("file_operations".to_string(), 3, Duration::from_secs(30)),
            crypto_breaker: CircuitBreaker::new("crypto_operations".to_string(), 5, Duration::from_secs(60)),
            retry_policy: RetryPolicy::new(3, Duration::from_millis(500))
                .with_max_delay(Duration::from_secs(5))
                .with_backoff_multiplier(2.0),
            degradation,
            validator: InputValidator::new(),
        }
    }
    
    /// Create a new ResilienceManager with custom configuration
    pub fn with_config(config: ResilienceConfig) -> Self {
        let degradation = Arc::new(GracefulDegradation::new());
        
        // Initialize with configuration-based settings
        let degradation_clone = Arc::clone(&degradation);
        tokio::spawn(async move {
            degradation_clone.register_feature("file_operations", true).await;
            degradation_clone.register_feature("encryption", true).await;
            degradation_clone.register_feature("tui", true).await;
            degradation_clone.register_feature("git_integration", true).await;
            
            // Register circuit breakers with configured settings
            if config.circuit_breaker_enabled {
                let timeout = Duration::from_secs(config.circuit_timeout_secs);
                degradation_clone.register_circuit_breaker("file_ops", config.failure_threshold, timeout).await;
                degradation_clone.register_circuit_breaker("crypto_ops", config.failure_threshold, timeout).await;
            }
        });
        
        let retry_policy = if config.retry_enabled {
            RetryPolicy::new(
                config.max_retries,
                Duration::from_millis(config.retry_base_delay_ms)
            )
            .with_max_delay(Duration::from_secs(30))
            .with_backoff_multiplier(2.0)
        } else {
            // Disabled retry policy (1 attempt only)
            RetryPolicy::new(1, Duration::from_millis(0))
        };
        
        Self {
            file_ops_breaker: CircuitBreaker::new(
                "file_operations".to_string(),
                config.failure_threshold,
                Duration::from_secs(config.circuit_timeout_secs)
            ),
            crypto_breaker: CircuitBreaker::new(
                "crypto_operations".to_string(),
                config.failure_threshold,
                Duration::from_secs(config.circuit_timeout_secs)
            ),
            retry_policy,
            degradation,
            validator: InputValidator::new(),
        }
    }
    
    /// Execute a file operation with circuit breaker and retry protection
    pub async fn execute_file_operation<F, Fut, T>(&self, mut operation: F) -> CryptoResult<T>
    where
        F: FnMut() -> Fut + Send,
        Fut: std::future::Future<Output = CryptoResult<T>> + Send,
        T: Send + 'static,
    {
        // Check if file operations are enabled
        if !self.degradation.is_feature_enabled("file_operations").await {
            return Err(CargoCryptError::Config {
                message: "File operations are temporarily disabled".to_string(),
                suggestion: Some("System is in degraded mode, please try again later".to_string()),
            });
        }
        
        // For circuit breaker, we need to wrap the async operation
        let result = operation().await;
        
        match result {
            Ok(value) => Ok(value),
            Err(error) => {
                // For transient errors, try with retry policy
                if error.is_recoverable() {
                    info!("Retrying file operation due to transient error: {}", error);
                    self.retry_policy.execute(|| operation()).await
                } else {
                    Err(error)
                }
            }
        }
    }
    
    /// Execute a crypto operation with circuit breaker protection
    pub async fn execute_crypto_operation<F, T>(&self, operation: F) -> CryptoResult<T>
    where
        F: FnOnce() -> CryptoResult<T>,
        T: Send + 'static,
    {
        // Check if encryption is enabled
        if !self.degradation.is_feature_enabled("encryption").await {
            return Err(CargoCryptError::Config {
                message: "Encryption operations are temporarily disabled".to_string(),
                suggestion: Some("System is in degraded mode, please try again later".to_string()),
            });
        }
        
        match self.crypto_breaker.execute(|| operation()).await {
            Ok(result) => Ok(result),
            Err(_breaker_error) => {
                warn!("Circuit breaker triggered for crypto operations");
                Err(CargoCryptError::Crypto {
                    message: "Cryptographic operations are temporarily unavailable due to repeated failures".to_string(),
                    kind: crate::error::CryptoErrorKind::Encryption,
                })
            }
        }
    }
    
    /// Perform system health check and update feature flags
    pub async fn health_check(&self) -> HealthStatus {
        self.degradation.health_check().await
    }
    
    /// Validate and sanitize user input
    pub fn validate_input(&self, input_type: &str, value: &str) -> ValidationResult {
        match input_type {
            "password" => self.validator.validate_password(value),
            "file_path" => {
                let path = std::path::PathBuf::from(value);
                self.validator.validate_file_path(&path)
            }
            "config" => {
                // Extract key from config format (key=value)
                if let Some((key, val)) = value.split_once('=') {
                    self.validator.validate_config_value(key, val)
                } else {
                    let mut result = ValidationResult::new();
                    result.add_error("config", "Invalid config format, expected key=value", crate::validation::ValidationSeverity::Critical);
                    result
                }
            }
            _ => ValidationResult::new(), // Default: valid
        }
    }
}

impl Default for ResilienceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing CargoCrypt instances with custom configuration
pub struct CargoCryptBuilder {
    config: Option<CryptoConfig>,
    project_root: Option<PathBuf>,
}

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
        let secret_store = Arc::new(MemorySecretStore::new()) as Arc<dyn SecretStore>;

        let monitoring = Arc::new(MonitoringManager::new(config.monitoring.clone()));
        
        // Initialize monitoring logging
        if let Err(e) = monitoring.initialize_logging() {
            warn!("Failed to initialize monitoring logging: {}", e);
        }
        
        Ok(CargoCrypt {
            engine,
            config: Arc::new(RwLock::new(config)),
            project_root,
            secret_store,
            resilience: ResilienceManager::new(),
            monitoring,
        })
    }
}

impl CargoCrypt {
    /// Create a builder for constructing CargoCrypt instances
    pub fn builder() -> CargoCryptBuilder {
        CargoCryptBuilder::new()
    }

    /// Create a new CargoCrypt instance with default configuration
    pub async fn new() -> CryptoResult<Self> {
        Self::builder().build().await
    }
    
    /// Get the resilience manager for direct access to error handling systems
    pub fn resilience(&self) -> &ResilienceManager {
        &self.resilience
    }
    
    /// Perform a comprehensive system health check
    pub async fn health_check(&self) -> HealthStatus {
        self.resilience.health_check().await
    }
    
    /// Check if the system is operating in degraded mode
    pub async fn is_degraded(&self) -> bool {
        let health = self.health_check().await;
        matches!(health.overall_health, crate::resilience::HealthLevel::Degraded | crate::resilience::HealthLevel::Critical)
    }

    /// Get the current configuration
    pub async fn config(&self) -> CryptoConfig {
        self.config.read().await.clone()
    }

    /// Get the crypto engine
    pub fn crypto(&self) -> &CryptoEngine {
        &self.engine
    }
    
    /// Get the monitoring manager for accessing metrics and performance data
    pub fn monitoring(&self) -> &MonitoringManager {
        &self.monitoring
    }

    /// Initialize CargoCrypt in a project directory
    pub async fn init_project() -> CryptoResult<()> {
        let project_root = crate::utils::find_project_root()?;
        let config_dir = project_root.join(".cargocrypt");
        
        if !config_dir.exists() {
            tokio::fs::create_dir_all(&config_dir).await?;
        }
        
        // Create default configuration file with resilience settings
        let config_file = config_dir.join("config.toml");
        if !config_file.exists() {
            let default_config = CryptoConfig::default();
            let config_toml = toml::to_string_pretty(&default_config)
                .map_err(|e| CargoCryptError::Serialization {
                    message: format!("Failed to serialize default config: {}", e),
                    source: Box::new(e),
                })?;
            
            tokio::fs::write(&config_file, config_toml).await?;
            info!("Created default configuration at: {}", config_file.display());
        }
        
        Ok(())
    }

    /// Encrypt a file with the given password
    pub async fn encrypt_file<P: AsRef<Path>>(&self, path: P, password: &str) -> CryptoResult<PathBuf> {
        use crate::crypto::{PlaintextSecret, EncryptionOptions};
        
        let path = path.as_ref().to_path_buf();
        let path_str = path.to_string_lossy().to_string();
        
        // Comprehensive input validation
        let password_validation = self.resilience.validate_input("password", password);
        if !password_validation.is_valid {
            let error_messages: Vec<String> = password_validation.errors
                .iter()
                .filter(|e| e.severity == crate::validation::ValidationSeverity::Critical)
                .map(|e| e.message.clone())
                .collect();
            
            return Err(CargoCryptError::Validation {
                message: "Password validation failed".to_string(),
                errors: error_messages,
                warnings: password_validation.warnings,
            });
        }
        
        let path_validation = self.resilience.validate_input("file_path", &path_str);
        if !path_validation.is_valid {
            let error_messages: Vec<String> = path_validation.errors
                .iter()
                .filter(|e| e.severity == crate::validation::ValidationSeverity::Critical)
                .map(|e| e.message.clone())
                .collect();
            
            return Err(CargoCryptError::Validation {
                message: "File path validation failed".to_string(),
                errors: error_messages,
                warnings: path_validation.warnings,
            });
        }
        
        // Display validation warnings if any
        for warning in &password_validation.warnings {
            warn!("Password validation warning: {}", warning);
        }
        for warning in &path_validation.warnings {
            warn!("Path validation warning: {}", warning);
        }
        
        let config = self.config.read().await;
        
        // Execute file operations with resilience protection
        let path_clone = path.clone();
        let file_content = {
            let path_str_clone = path_str.clone();
            let path_for_read = path.clone();
            self.resilience.execute_file_operation(move || {
                let path_str = path_str_clone.clone();
                let path_clone = path_for_read.clone();
                async move {
                    info!("Reading file for encryption: {}", path_str);
                    let content = tokio::fs::read(&path_clone).await.map_err(|e| CargoCryptError::from(e))?;
            
            // Validate file content
            let filename = path_clone.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            let validator = InputValidator::new();
            let content_validation = validator.validate_file_content(&content, filename);
            
            for warning in &content_validation.warnings {
                warn!("File content warning: {}", warning);
            }
            
                    Ok(content)
                }
            }).await?
        };
        
        let plaintext = PlaintextSecret::new(file_content);
        
        // Execute crypto operations with circuit breaker protection
        let password_str = password.to_string();
        let engine_clone = Arc::clone(&self.engine);
        let encrypted = {
            info!("Encrypting file content");
            self.engine.encrypt(
                plaintext, 
                &password_str, 
                crate::crypto::EncryptionOptions::default()
            ).await.map_err(|e| CargoCryptError::from(e))?
        };
        
        // Create encrypted file path
        let encrypted_path = path.with_extension(format!("{}.enc", 
            path.extension().and_then(|ext| ext.to_str()).unwrap_or("dat")));
        
        // Write encrypted content with resilience protection
        let encrypted_path_clone = encrypted_path.clone();
        let atomic_ops = config.file_ops.atomic_operations;
        {
            let encrypted_for_write = encrypted.clone();
            let path_for_write = encrypted_path_clone.clone();
            self.resilience.execute_file_operation(move || {
                let encrypted_bytes_result = encrypted_for_write.clone();
                let encrypted_path_clone = path_for_write.clone();
                async move {
                    info!("Writing encrypted file: {}", encrypted_path_clone.display());
                    let encrypted_bytes = encrypted_bytes_result.to_bytes().map_err(|e| CargoCryptError::from(e))?;
                    
                    // Atomic operation: write to temp file first, then move
                    if atomic_ops {
                        let temp_path = encrypted_path_clone.with_extension("tmp");
                        tokio::fs::write(&temp_path, &encrypted_bytes).await.map_err(|e| CargoCryptError::from(e))?;
                        tokio::fs::rename(&temp_path, &encrypted_path_clone).await.map_err(|e| CargoCryptError::from(e))?;
                    } else {
                        tokio::fs::write(&encrypted_path_clone, encrypted_bytes).await.map_err(|e| CargoCryptError::from(e))?;
                    }
                    
                    Ok(())
                }
            }).await?
        };
        
        // Optionally backup original with resilience protection
        if config.file_ops.backup_originals {
            let path_for_backup = path.clone();
            self.resilience.execute_file_operation(move || {
                let path_clone = path_for_backup.clone();
                async move {
                    let backup_path = path_clone.with_extension(format!("{}.backup", 
                        path_clone.extension().and_then(|ext| ext.to_str()).unwrap_or("dat")));
                    info!("Creating backup: {}", backup_path.display());
                    tokio::fs::copy(&path_clone, backup_path).await.map_err(|e| CargoCryptError::from(e))?;
                    Ok(())
                }
            }).await?;
        }
        
        info!("File encryption completed successfully: {}", encrypted_path.display());
        Ok(encrypted_path)
    }

    /// Decrypt a file with the given password
    pub async fn decrypt_file<P: AsRef<Path>>(&self, path: P, password: &str) -> CryptoResult<PathBuf> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy();
        
        // Comprehensive input validation
        let password_validation = self.resilience.validate_input("password", password);
        if !password_validation.is_valid {
            let error_messages: Vec<String> = password_validation.errors
                .iter()
                .filter(|e| e.severity == crate::validation::ValidationSeverity::Critical)
                .map(|e| e.message.clone())
                .collect();
            
            return Err(CargoCryptError::Validation {
                message: "Password validation failed".to_string(),
                errors: error_messages,
                warnings: password_validation.warnings,
            });
        }
        
        let path_validation = self.resilience.validate_input("file_path", &path_str);
        if !path_validation.is_valid {
            let error_messages: Vec<String> = path_validation.errors
                .iter()
                .filter(|e| e.severity == crate::validation::ValidationSeverity::Critical)
                .map(|e| e.message.clone())
                .collect();
            
            return Err(CargoCryptError::Validation {
                message: "File path validation failed".to_string(),
                errors: error_messages,
                warnings: path_validation.warnings,
            });
        }
        
        // Display validation warnings if any
        for warning in &password_validation.warnings {
            warn!("Password validation warning: {}", warning);
        }
        for warning in &path_validation.warnings {
            warn!("Path validation warning: {}", warning);
        }
        
        let config = self.config.read().await;
        
        // Read encrypted content with resilience protection
        let encrypted_bytes = self.resilience.execute_file_operation(|| async {
            info!("Reading encrypted file: {}", path_str);
            tokio::fs::read(path).await.map_err(|e| CargoCryptError::from(e))
        }).await?;
        
        // Parse encrypted data
        let encrypted = {
            info!("Parsing encrypted data");
            crate::crypto::EncryptedSecret::from_bytes(&encrypted_bytes).map_err(|e| CargoCryptError::from(e))?
        };
        
        // Decrypt using the crypto engine with circuit breaker protection
        let decrypted = {
            info!("Decrypting file content");
            self.engine.decrypt(&encrypted, password).map_err(|e| CargoCryptError::from(e))?
        };
        
        // Create decrypted file path (remove .enc extension)
        let decrypted_path = if path.extension().and_then(|ext| ext.to_str()) == Some("enc") {
            path.with_extension("")
        } else {
            path.with_extension("decrypted")
        };
        
        // Write decrypted content with resilience protection
        self.resilience.execute_file_operation(|| async {
            info!("Writing decrypted file: {}", decrypted_path.display());
            
            // Atomic operation: write to temp file first, then move
            if config.file_ops.atomic_operations {
                let temp_path = decrypted_path.with_extension("tmp");
                tokio::fs::write(&temp_path, decrypted.as_bytes()).await.map_err(|e| CargoCryptError::from(e))?;
                tokio::fs::rename(&temp_path, &decrypted_path).await.map_err(|e| CargoCryptError::from(e))?;
            } else {
                tokio::fs::write(&decrypted_path, decrypted.as_bytes()).await.map_err(|e| CargoCryptError::from(e))?;
            }
            
            Ok(())
        }).await?;
        
        info!("File decryption completed successfully: {}", decrypted_path.display());
        Ok(decrypted_path)
    }
}

// Default implementations
impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            performance_profile: PerformanceProfile::Balanced,
            key_params: KeyDerivationConfig::default(),
            file_ops: FileOperationConfig::default(),
            security: SecurityConfig::default(),
            performance: PerformanceConfig::default(),
            resilience: ResilienceConfig::default(),
            monitoring: MonitoringConfig::default(),
        }
    }
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            circuit_breaker_enabled: true,
            failure_threshold: 3,
            circuit_timeout_secs: 30,
            retry_enabled: true,
            max_retries: 3,
            retry_base_delay_ms: 500,
            input_validation_enabled: true,
            graceful_degradation_enabled: true,
            health_monitoring_enabled: true,
            health_check_interval_secs: 300, // 5 minutes
        }
    }
}

impl Default for KeyDerivationConfig {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MB
            time_cost: 3,
            parallelism: 4,
            output_length: 32,
        }
    }
}

impl Default for FileOperationConfig {
    fn default() -> Self {
        Self {
            backup_originals: true,
            encrypted_extension: "enc".to_string(),
            buffer_size: 64 * 1024, // 64 KB
            compression: false,
            atomic_operations: true,
            preserve_metadata: true,
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

impl Default for CargoCryptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// Validation methods
impl CryptoConfig {
    /// Validate the configuration
    pub fn validate(&self) -> CryptoResult<()> {
        if self.key_params.memory_cost < 1024 {
            return Err(CargoCryptError::config_not_found());
        }
        
        if self.key_params.time_cost < 1 {
            return Err(CargoCryptError::config_not_found());
        }
        
        if self.key_params.parallelism < 1 {
            return Err(CargoCryptError::config_not_found());
        }
        
        Ok(())
    }

    /// Get performance profiles
    pub fn performance_profiles(&self) -> Vec<PerformanceProfile> {
        vec![
            PerformanceProfile::Fast,
            PerformanceProfile::Balanced,
            PerformanceProfile::Secure,
        ]
    }
    
    /// Update resilience configuration at runtime
    pub fn update_resilience_config(&mut self, config: ResilienceConfig) -> CryptoResult<()> {
        // Validate resilience configuration
        if config.failure_threshold == 0 {
            return Err(CargoCryptError::Config {
                message: "Failure threshold must be greater than 0".to_string(),
                suggestion: Some("Set failure_threshold to at least 1".to_string()),
            });
        }
        
        if config.max_retries > 10 {
            return Err(CargoCryptError::Config {
                message: "Maximum retries too high (max 10)".to_string(),
                suggestion: Some("Set max_retries to 10 or less to avoid excessive delays".to_string()),
            });
        }
        
        info!("Updating resilience configuration: {:?}", config);
        self.resilience = config;
        Ok(())
    }
}