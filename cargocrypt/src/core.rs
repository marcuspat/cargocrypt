//! Core CargoCrypt functionality - CLEAN VERSION
//!
//! This module provides the main CargoCrypt struct and configuration types
//! for zero-config cryptographic operations.

use crate::crypto::{CryptoEngine, MemorySecretStore, PerformanceProfile, SecretStore};
use crate::error::{CargoCryptError, CryptoResult};
use crate::monitoring::{MonitoringConfig, MonitoringManager};
use crate::resilience::{CircuitBreaker, GracefulDegradation, HealthStatus, RetryPolicy};
use crate::validation::{InputValidator, ValidationResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure bytes wrapper that zeroizes memory on drop
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Create from a string
    #[allow(clippy::should_implement_trait)]
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
    #[allow(dead_code)]
    project_root: PathBuf,
    /// Secret store for memory-safe secret management
    #[allow(dead_code)]
    secret_store: Arc<dyn SecretStore>,
    /// Resilience manager for error handling and recovery
    resilience: ResilienceManager,
    /// Monitoring manager for real-time metrics and performance tracking
    monitoring: Arc<MonitoringManager>,
}

/// Configuration for CargoCrypt operations
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
#[serde(default)]
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
            degradation_clone
                .register_feature("file_operations", true)
                .await;
            degradation_clone.register_feature("encryption", true).await;
            degradation_clone.register_feature("tui", true).await;
            degradation_clone
                .register_feature("git_integration", true)
                .await;

            // Register circuit breakers
            degradation_clone
                .register_circuit_breaker("file_ops", 3, Duration::from_secs(30))
                .await;
            degradation_clone
                .register_circuit_breaker("crypto_ops", 5, Duration::from_secs(60))
                .await;
        });

        Self {
            file_ops_breaker: CircuitBreaker::new(
                "file_operations".to_string(),
                3,
                Duration::from_secs(30),
            ),
            crypto_breaker: CircuitBreaker::new(
                "crypto_operations".to_string(),
                5,
                Duration::from_secs(60),
            ),
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
            degradation_clone
                .register_feature("file_operations", true)
                .await;
            degradation_clone.register_feature("encryption", true).await;
            degradation_clone.register_feature("tui", true).await;
            degradation_clone
                .register_feature("git_integration", true)
                .await;

            // Register circuit breakers with configured settings
            if config.circuit_breaker_enabled {
                let timeout = Duration::from_secs(config.circuit_timeout_secs);
                degradation_clone
                    .register_circuit_breaker("file_ops", config.failure_threshold, timeout)
                    .await;
                degradation_clone
                    .register_circuit_breaker("crypto_ops", config.failure_threshold, timeout)
                    .await;
            }
        });

        let retry_policy = if config.retry_enabled {
            RetryPolicy::new(
                config.max_retries,
                Duration::from_millis(config.retry_base_delay_ms),
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
                Duration::from_secs(config.circuit_timeout_secs),
            ),
            crypto_breaker: CircuitBreaker::new(
                "crypto_operations".to_string(),
                config.failure_threshold,
                Duration::from_secs(config.circuit_timeout_secs),
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
                    self.retry_policy.execute(operation).await
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

        match self.crypto_breaker.execute(operation).await {
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
                    result.add_error(
                        "config",
                        "Invalid config format, expected key=value",
                        crate::validation::ValidationSeverity::Critical,
                    );
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
        let project_root = match self.project_root {
            Some(root) => root,
            None => crate::utils::find_project_root()?,
        };
        // An explicit configuration wins; otherwise the project's
        // `.cargocrypt/config.toml` is used when it exists.
        let config = match self.config {
            Some(config) => config,
            None => CryptoConfig::load(&project_root)?,
        };
        config.validate()?;

        // Initialize crypto engine and secret store
        let engine = Arc::new(CryptoEngine::with_performance_profile(
            config.performance_profile,
        ));
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

impl CryptoConfig {
    /// Path of the configuration file inside a project.
    pub fn path_in(project_root: &Path) -> PathBuf {
        project_root.join(".cargocrypt").join("config.toml")
    }

    /// Load `<project_root>/.cargocrypt/config.toml`, or the defaults when the
    /// file does not exist. Keys missing from the file take their defaults.
    pub fn load(project_root: &Path) -> CryptoResult<Self> {
        let path = Self::path_in(project_root);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e.into()),
        };
        toml::from_str(&text).map_err(|e| CargoCryptError::Config {
            message: format!("{}: {}", path.display(), e),
            suggestion: Some("Fix the file, or delete it and run `cargocrypt init`".to_string()),
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
        matches!(
            health.overall_health,
            crate::resilience::HealthLevel::Degraded | crate::resilience::HealthLevel::Critical
        )
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
            let config_toml = toml::to_string_pretty(&default_config).map_err(|e| {
                CargoCryptError::Serialization {
                    message: format!("Failed to serialize default config: {}", e),
                    source: Box::new(e),
                }
            })?;

            tokio::fs::write(&config_file, config_toml).await?;
            info!(
                "Created default configuration at: {}",
                config_file.display()
            );
        }

        Ok(())
    }

    /// Encrypt a file with the given password
    pub async fn encrypt_file<P: AsRef<Path>>(
        &self,
        path: P,
        password: &str,
    ) -> CryptoResult<PathBuf> {
        let path = path.as_ref().to_path_buf();
        let path_str = path.to_string_lossy().to_string();

        // Comprehensive input validation
        let password_validation = self.resilience.validate_input("password", password);
        if !password_validation.is_valid {
            let error_messages: Vec<String> = password_validation
                .errors
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
            let error_messages: Vec<String> = path_validation
                .errors
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

        // Create encrypted file path
        let encrypted_path = path.with_extension(format!(
            "{}.enc",
            path.extension()
                .and_then(|ext| ext.to_str())
                .unwrap_or("dat")
        ));

        // Stream the file through the cipher in fixed-size chunks: memory use
        // does not grow with the file. The output only appears at its final
        // path once it is complete and synced.
        info!("Encrypting {} -> {}", path_str, encrypted_path.display());
        let kdf = self.engine.performance_profile().kdf_params();
        let source = path.clone();
        let destination = encrypted_path.clone();
        let password_owned = zeroize::Zeroizing::new(password.to_string());
        tokio::task::spawn_blocking(move || -> CryptoResult<()> {
            let mut reader = std::io::BufReader::new(std::fs::File::open(&source)?);
            let mut output = crate::atomic::AtomicFile::create(&destination)?;
            {
                let mut writer = std::io::BufWriter::new(output.file());
                crate::crypto::stream::encrypt_stream(
                    &mut reader,
                    &mut writer,
                    &password_owned,
                    kdf,
                )?;
            }
            output.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| CargoCryptError::from(std::io::Error::other(e.to_string())))??;

        // Optionally backup original with resilience protection
        if config.file_ops.backup_originals {
            let path_for_backup = path.clone();
            self.resilience
                .execute_file_operation(move || {
                    let path_clone = path_for_backup.clone();
                    async move {
                        let backup_path = path_clone.with_extension(format!(
                            "{}.backup",
                            path_clone
                                .extension()
                                .and_then(|ext| ext.to_str())
                                .unwrap_or("dat")
                        ));
                        info!("Creating backup: {}", backup_path.display());
                        // The backup is plaintext: write it owner-only.
                        tokio::task::spawn_blocking(move || -> CryptoResult<()> {
                            let mut source = std::fs::File::open(&path_clone)?;
                            let mut backup = crate::atomic::AtomicFile::create(&backup_path)?;
                            std::io::copy(&mut source, backup.file())?;
                            backup.commit()?;
                            Ok(())
                        })
                        .await
                        .map_err(|e| {
                            CargoCryptError::from(std::io::Error::other(e.to_string()))
                        })??;
                        Ok(())
                    }
                })
                .await?;
        }

        info!(
            "File encryption completed successfully: {}",
            encrypted_path.display()
        );
        Ok(encrypted_path)
    }

    /// Decrypt a file with the given password
    pub async fn decrypt_file<P: AsRef<Path>>(
        &self,
        path: P,
        password: &str,
    ) -> CryptoResult<PathBuf> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy();

        // Comprehensive input validation
        let password_validation = self.resilience.validate_input("password", password);
        if !password_validation.is_valid {
            let error_messages: Vec<String> = password_validation
                .errors
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
            let error_messages: Vec<String> = path_validation
                .errors
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

        // Create decrypted file path (remove .enc extension)
        let decrypted_path = if path.extension().and_then(|ext| ext.to_str()) == Some("enc") {
            path.with_extension("")
        } else {
            path.with_extension("decrypted")
        };

        info!("Decrypting {} -> {}", path_str, decrypted_path.display());
        let source = path.to_path_buf();
        let destination = decrypted_path.clone();
        let password_owned = zeroize::Zeroizing::new(password.to_string());
        tokio::task::spawn_blocking(move || -> CryptoResult<()> {
            // Plaintext goes to a private temporary file and is only moved
            // into place once the whole container has authenticated. On any
            // error the temporary is removed when `output` is dropped.
            let mut output = crate::atomic::AtomicFile::create(&destination)?;
            {
                let mut writer = std::io::BufWriter::new(output.file());
                decrypt_any(&source, &password_owned, &mut writer)?;
            }
            output.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| CargoCryptError::from(std::io::Error::other(e.to_string())))??;

        info!(
            "File decryption completed successfully: {}",
            decrypted_path.display()
        );
        Ok(decrypted_path)
    }

    /// Check that an encrypted file is intact and that `password` opens it.
    ///
    /// The whole container is decrypted and authenticated; the plaintext is
    /// discarded and nothing is written to disk.
    pub async fn verify_file<P: AsRef<Path>>(
        &self,
        path: P,
        password: &str,
    ) -> CryptoResult<ContainerInfo> {
        let source = path.as_ref().to_path_buf();
        let password_owned = zeroize::Zeroizing::new(password.to_string());
        tokio::task::spawn_blocking(move || {
            decrypt_any(&source, &password_owned, &mut std::io::sink())
        })
        .await
        .map_err(|e| CargoCryptError::from(std::io::Error::other(e.to_string())))?
    }

    /// Re-encrypt a file in place under a new password and/or profile.
    ///
    /// The plaintext is piped in memory from the decryptor to the encryptor
    /// and never touches the disk. The result is always a streaming
    /// (version 3) container, so this also upgrades older formats. The file
    /// is replaced atomically, and only after the old container has fully
    /// authenticated: on any failure it is left byte-for-byte as it was.
    pub async fn rekey_file<P: AsRef<Path>>(
        &self,
        path: P,
        old_password: &str,
        new_password: &str,
        profile: Option<PerformanceProfile>,
    ) -> CryptoResult<ContainerInfo> {
        let password_validation = self.resilience.validate_input("password", new_password);
        if !password_validation.is_valid {
            return Err(CargoCryptError::Validation {
                message: "New password validation failed".to_string(),
                errors: password_validation
                    .errors
                    .iter()
                    .filter(|e| e.severity == crate::validation::ValidationSeverity::Critical)
                    .map(|e| e.message.clone())
                    .collect(),
                warnings: password_validation.warnings,
            });
        }

        let kdf = profile
            .unwrap_or_else(|| self.engine.performance_profile())
            .kdf_params();
        let target = path.as_ref().to_path_buf();
        let old = zeroize::Zeroizing::new(old_password.to_string());
        let new = zeroize::Zeroizing::new(new_password.to_string());

        tokio::task::spawn_blocking(move || -> CryptoResult<ContainerInfo> {
            use std::io::Write;

            let (pipe_reader, pipe_writer) = std::io::pipe()?;
            let source = target.clone();
            let decryptor = std::thread::spawn(move || -> CryptoResult<ContainerInfo> {
                let mut writer = std::io::BufWriter::new(pipe_writer);
                let info = decrypt_any(&source, &old, &mut writer)?;
                writer.flush()?;
                Ok(info)
                // `pipe_writer` is dropped here, which ends the encryptor's input.
            });

            let mut output = crate::atomic::AtomicFile::create(&target)?;
            let encrypted = {
                let mut reader = std::io::BufReader::new(pipe_reader);
                let mut writer = std::io::BufWriter::new(output.file());
                crate::crypto::stream::encrypt_stream(&mut reader, &mut writer, &new, kdf)
                // The reader is dropped here; if encryption failed early this
                // unblocks a decryptor that is still writing.
            };
            let decrypted = decryptor
                .join()
                .map_err(|_| std::io::Error::other("decryption thread panicked"))?;

            // A failed decryption ends the pipe early, and the encryptor
            // cannot tell that from a short file: the decryptor's verdict
            // decides whether the output is kept.
            let previous = match (decrypted, encrypted) {
                (Ok(info), Ok(_)) => info,
                (Ok(_), Err(e)) => return Err(e.into()),
                (Err(e), _) => return Err(e),
            };
            output.commit()?;
            Ok(ContainerInfo {
                version: crate::crypto::stream::STREAM_VERSION,
                kdf,
                plaintext_len: previous.plaintext_len,
            })
        })
        .await
        .map_err(|e| CargoCryptError::from(std::io::Error::other(e.to_string())))?
    }
}

/// What a container is and how it was protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerInfo {
    /// Container format version (1, 2 or 3)
    pub version: u8,
    /// Argon2id cost parameters the key was derived with
    pub kdf: crate::crypto::KdfParams,
    /// Size of the decrypted contents in bytes
    pub plaintext_len: u64,
}

/// Decrypt a container of any supported version into `writer`.
///
/// For streaming containers plaintext is written as chunks authenticate, so
/// the caller must discard what `writer` received if this returns an error.
fn decrypt_any(
    source: &Path,
    password: &str,
    writer: &mut dyn std::io::Write,
) -> CryptoResult<ContainerInfo> {
    use std::io::{Read, Seek, SeekFrom};

    let mut file = std::fs::File::open(source)?;
    let mut prefix = [0u8; 19];
    let mut seen = 0;
    while seen < prefix.len() {
        match file.read(&mut prefix[seen..])? {
            0 => break,
            n => seen += n,
        }
    }
    file.seek(SeekFrom::Start(0))?;

    if crate::crypto::stream::is_stream_container(&prefix[..seen]) {
        let field =
            |i: usize| u32::from_le_bytes([prefix[i], prefix[i + 1], prefix[i + 2], prefix[i + 3]]);
        let kdf = if seen == prefix.len() {
            crate::crypto::KdfParams {
                m_cost: field(7),
                t_cost: field(11),
                p_cost: field(15),
            }
        } else {
            crate::crypto::KdfParams::default() // too short; decrypt_stream rejects it
        };
        let mut reader = std::io::BufReader::new(file);
        let mut writer = writer;
        let plaintext_len =
            crate::crypto::stream::decrypt_stream(&mut reader, &mut writer, password)?;
        Ok(ContainerInfo {
            version: crate::crypto::stream::STREAM_VERSION,
            kdf,
            plaintext_len,
        })
    } else {
        // Version 1 and 2 containers are single-shot and held in memory.
        let mut encrypted_bytes = Vec::new();
        file.read_to_end(&mut encrypted_bytes)?;
        let encrypted = crate::crypto::EncryptedSecret::from_bytes(&encrypted_bytes)?;
        let decrypted = encrypted.decrypt_with_password(password)?;
        writer.write_all(decrypted.as_bytes())?;
        Ok(ContainerInfo {
            version: encrypted.version(),
            kdf: encrypted.kdf_params(),
            plaintext_len: decrypted.len() as u64,
        })
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
            // Off by default: a backup is a second plaintext copy of the
            // very file being protected.
            backup_originals: false,
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
                suggestion: Some(
                    "Set max_retries to 10 or less to avoid excessive delays".to_string(),
                ),
            });
        }

        info!("Updating resilience configuration: {:?}", config);
        self.resilience = config;
        Ok(())
    }
}
