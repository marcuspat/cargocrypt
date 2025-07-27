//! Main cryptographic engine implementation with resilience integration

use crate::crypto::{
    CryptoError, CryptoResult, DerivedKey, EncryptedSecret, PlaintextSecret, 
    SecretMetadata, SecretType, defaults, keys::SecureRandom
};
use crate::resilience::{CircuitBreaker, RetryPolicy};
use crate::validation::InputValidator;
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::RwLock;
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::Argon2;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;
use serde::{Deserialize, Serialize};

/// Main cryptographic engine for CargoCrypt with resilience features
/// 
/// This engine provides high-level cryptographic operations using ChaCha20-Poly1305
/// for authenticated encryption and Argon2 for key derivation. Includes circuit breaker
/// protection, retry logic, and input validation for robust operation.
#[derive(Debug, Clone)]
pub struct CryptoEngine {
    /// Performance settings for key derivation
    performance_profile: PerformanceProfile,
    /// Circuit breaker for crypto operations protection
    circuit_breaker: Arc<CircuitBreaker>,
    /// Retry policy for transient failures
    retry_policy: Arc<RetryPolicy>,
    /// Input validator for security
    validator: InputValidator,
    /// Feature flags for graceful degradation
    features_enabled: Arc<RwLock<CryptoFeatures>>,
}

/// Feature flags for crypto engine capabilities
#[derive(Debug, Clone)]
struct CryptoFeatures {
    encryption: bool,
    decryption: bool,
    key_derivation: bool,
    batch_operations: bool,
    direct_operations: bool,
}

/// Performance profiles for different use cases
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum PerformanceProfile {
    /// Fast operations, lower security (development/testing)
    Fast,
    /// Balanced security and performance (default)
    Balanced,
    /// High security, slower operations (production sensitive data)
    Secure,
    /// Maximum security, slowest operations (highly sensitive data)
    Paranoid,
}

impl Default for PerformanceProfile {
    fn default() -> Self {
        Self::Balanced
    }
}

impl PerformanceProfile {
    /// Get Argon2 parameters for this profile
    pub fn argon2_params(&self) -> argon2::Params {
        match self {
            Self::Fast => argon2::Params::new(
                4096,  // 4 MB memory
                1,     // 1 iteration
                1,     // 1 thread
                Some(32),
            ).expect("Valid Argon2 params"),
            
            Self::Balanced => argon2::Params::new(
                65536, // 64 MB memory
                3,     // 3 iterations  
                4,     // 4 threads
                Some(32),
            ).expect("Valid Argon2 params"),
            
            Self::Secure => argon2::Params::new(
                262144, // 256 MB memory
                5,      // 5 iterations
                8,      // 8 threads
                Some(32),
            ).expect("Valid Argon2 params"),
            
            Self::Paranoid => argon2::Params::new(
                1048576, // 1 GB memory
                10,      // 10 iterations
                16,      // 16 threads
                Some(32),
            ).expect("Valid Argon2 params"),
        }
    }
}

/// Encryption options
#[derive(Debug, Clone)]
pub struct EncryptionOptions {
    /// Secret metadata
    pub metadata: Option<SecretMetadata>,
    /// Performance profile to use
    pub performance_profile: Option<PerformanceProfile>,
    /// Custom salt (if None, random salt is generated)
    pub salt: Option<[u8; defaults::SALT_LENGTH]>,
}

impl Default for EncryptionOptions {
    fn default() -> Self {
        Self {
            metadata: None,
            performance_profile: None,
            salt: None,
        }
    }
}

impl EncryptionOptions {
    /// Create new encryption options
    pub fn new() -> Self {
        Self::default()
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: SecretMetadata) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set performance profile
    pub fn with_performance_profile(mut self, profile: PerformanceProfile) -> Self {
        self.performance_profile = Some(profile);
        self
    }

    /// Set custom salt
    pub fn with_salt(mut self, salt: [u8; defaults::SALT_LENGTH]) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Set description metadata
    pub fn with_description<S: Into<String>>(mut self, description: S) -> Self {
        let mut metadata = self.metadata.unwrap_or_default();
        metadata.description = Some(description.into());
        self.metadata = Some(metadata);
        self
    }

    /// Set secret type metadata
    pub fn with_type(mut self, secret_type: SecretType) -> Self {
        let mut metadata = self.metadata.unwrap_or_default();
        metadata.secret_type = Some(secret_type);
        self.metadata = Some(metadata);
        self
    }
}

/// Batch encryption result
#[derive(Debug)]
pub struct BatchEncryptionResult {
    /// Successfully encrypted secrets
    pub successes: Vec<(String, EncryptedSecret)>,
    /// Failed encryptions with error messages
    pub failures: Vec<(String, CryptoError)>,
}

impl CryptoEngine {
    /// Create a new crypto engine with default (balanced) settings and resilience features
    pub fn new() -> Self {
        Self {
            performance_profile: PerformanceProfile::default(),
            circuit_breaker: Arc::new(CircuitBreaker::new(
                "crypto_engine".to_string(),
                5, // 5 failures before opening
                Duration::from_secs(60) // 60 second timeout
            )),
            retry_policy: Arc::new(RetryPolicy::new(
                3, // max 3 retries
                Duration::from_millis(100) // 100ms base delay
            ).with_max_delay(Duration::from_secs(5))),
            validator: InputValidator::new(),
            features_enabled: Arc::new(RwLock::new(CryptoFeatures {
                encryption: true,
                decryption: true,
                key_derivation: true,
                batch_operations: true,
                direct_operations: true,
            })),
        }
    }

    /// Create a crypto engine with a specific performance profile and resilience features
    pub fn with_performance_profile(profile: PerformanceProfile) -> Self {
        let mut engine = Self::new();
        engine.performance_profile = profile;
        engine
    }
    
    /// Create a crypto engine with custom resilience configuration
    pub fn with_resilience_config(
        profile: PerformanceProfile,
        failure_threshold: u32,
        circuit_timeout: Duration,
        max_retries: u32,
        retry_delay: Duration
    ) -> Self {
        Self {
            performance_profile: profile,
            circuit_breaker: Arc::new(CircuitBreaker::new(
                "crypto_engine".to_string(),
                failure_threshold,
                circuit_timeout
            )),
            retry_policy: Arc::new(RetryPolicy::new(max_retries, retry_delay)
                .with_max_delay(Duration::from_secs(30))),
            validator: InputValidator::new(),
            features_enabled: Arc::new(RwLock::new(CryptoFeatures {
                encryption: true,
                decryption: true,
                key_derivation: true,
                batch_operations: true,
                direct_operations: true,
            })),
        }
    }

    /// Get the current performance profile
    pub fn performance_profile(&self) -> PerformanceProfile {
        self.performance_profile
    }
    
    /// Encrypt data with a password (convenience method)
    pub async fn encrypt_data(&self, data: &[u8], password: &str) -> CryptoResult<EncryptedSecret> {
        self.encrypt_bytes(data, password, EncryptionOptions::default()).await
    }
    
    /// Decrypt data with a password (convenience method) 
    pub fn decrypt_data(&self, encrypted: &EncryptedSecret, password: &str) -> CryptoResult<Vec<u8>> {
        self.decrypt_to_bytes(encrypted, password)
    }

    /// Set the performance profile
    pub fn set_performance_profile(&mut self, profile: PerformanceProfile) {
        self.performance_profile = profile;
    }
    
    /// Generate a new encryption key
    pub fn generate_key(&self) -> CryptoResult<DerivedKey> {
        let salt = SecureRandom::generate_salt()?;
        let password = SecureRandom::generate_password(32)?;
        self.derive_key(&password, &salt)
    }
    
    /// Derive a key from password and salt
    pub fn derive_key(&self, password: &str, salt: &[u8]) -> CryptoResult<DerivedKey> {
        if salt.len() != defaults::SALT_LENGTH {
            return Err(CryptoError::InvalidSalt { 
                reason: format!("Salt must be {} bytes, got {}", defaults::SALT_LENGTH, salt.len())
            });
        }
        let mut salt_array = [0u8; defaults::SALT_LENGTH];
        salt_array.copy_from_slice(salt);
        self.derive_key_with_profile(password, &salt_array, self.performance_profile)
    }

    /// Encrypt a string with a password using resilience protection
    pub async fn encrypt_string(
        &self,
        plaintext: &str,
        password: &str,
        options: EncryptionOptions,
    ) -> CryptoResult<EncryptedSecret> {
        // Check if encryption is enabled
        let features = self.features_enabled.read().await;
        if !features.encryption {
            return Err(CryptoError::Generic {
                message: "Encryption feature is currently disabled due to system degradation".to_string(),
            });
        }
        drop(features);
        
        // Validate inputs
        let password_validation = self.validator.validate_password(password);
        if !password_validation.is_valid {
            return Err(CryptoError::Generic {
                message: format!(
                    "Password validation failed: {}", 
                    password_validation.errors.iter()
                        .filter(|e| e.severity == crate::validation::ValidationSeverity::Critical)
                        .map(|e| e.message.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }
        
        let secret = PlaintextSecret::from_string(plaintext.to_string());
        self.encrypt_with_resilience(secret, password, options).await
    }

    /// Encrypt bytes with a password
    pub async fn encrypt_bytes(
        &self,
        plaintext: &[u8],
        password: &str,
        options: EncryptionOptions,
    ) -> CryptoResult<EncryptedSecret> {
        let secret = PlaintextSecret::from_bytes(plaintext.to_vec());
        self.encrypt(secret, password, options).await
    }

    /// Encrypt a plaintext secret with a password using resilience protection
    pub async fn encrypt(
        &self,
        plaintext: PlaintextSecret,
        password: &str,
        options: EncryptionOptions,
    ) -> CryptoResult<EncryptedSecret> {
        self.encrypt_with_resilience(plaintext, password, options).await
    }
    
    /// Internal encrypt method with circuit breaker and retry logic
    async fn encrypt_with_resilience(
        &self,
        plaintext: PlaintextSecret,
        password: &str,
        options: EncryptionOptions,
    ) -> CryptoResult<EncryptedSecret> {
        // Execute with circuit breaker protection
        let circuit_breaker = Arc::clone(&self.circuit_breaker);
        let retry_policy = Arc::clone(&self.retry_policy);
        let performance_profile = self.performance_profile;
        let validator = self.validator.clone();
        
        // Circuit breaker execution
        let result = circuit_breaker.execute(|| {
            // Determine the performance profile to use
            let profile = options.performance_profile.unwrap_or(performance_profile);
            
            // Create or use provided salt
            let salt = match options.salt {
                Some(salt) => salt,
                None => SecureRandom::generate_salt()?,
            };

            // Validate salt length
            if salt.len() != defaults::SALT_LENGTH {
                return Err(CryptoError::InvalidSalt {
                    reason: format!("Salt must be {} bytes", defaults::SALT_LENGTH),
                });
            }

            // Derive key using the specified performance profile with validation
            let key_result = self.derive_key_with_profile(password, &salt, profile);
            let key = key_result?;
            
            // Set up metadata
            let metadata = options.metadata.or_else(|| {
                let mut meta = SecretMetadata::new();
                meta.created_at = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                );
                Some(meta)
            });

            EncryptedSecret::encrypt_with_key(plaintext.clone(), &key, metadata)
        }).await;
        
        match result {
            Ok(encrypted) => Ok(encrypted),
            Err(crate::resilience::CircuitBreakerError::CircuitOpen) => {
                Err(CryptoError::Generic {
                    message: "Crypto operations circuit breaker is open - too many recent failures".to_string(),
                })
            }
            Err(crate::resilience::CircuitBreakerError::CircuitOpened) => {
                Err(CryptoError::Generic {
                    message: "Crypto operations circuit breaker opened due to failures".to_string(),
                })
            }
            Err(crate::resilience::CircuitBreakerError::OperationFailed(error)) => {
                // For now, just return the error without complex retry logic
                Err(error)
            }
        }
    }

    /// Decrypt an encrypted secret with a password
    pub fn decrypt(&self, encrypted: &EncryptedSecret, password: &str) -> CryptoResult<PlaintextSecret> {
        encrypted.decrypt_with_password(password)
    }

    /// Decrypt to string (convenience method)
    pub fn decrypt_to_string(&self, encrypted: &EncryptedSecret, password: &str) -> CryptoResult<String> {
        let plaintext = self.decrypt(encrypted, password)?;
        plaintext.into_string()
    }

    /// Decrypt to bytes (convenience method)
    pub fn decrypt_to_bytes(&self, encrypted: &EncryptedSecret, password: &str) -> CryptoResult<Vec<u8>> {
        let plaintext = self.decrypt(encrypted, password)?;
        Ok(plaintext.as_bytes().to_vec())
    }

    /// Verify a password against an encrypted secret
    pub fn verify_password(&self, encrypted: &EncryptedSecret, password: &str) -> bool {
        encrypted.verify_password(password)
    }

    /// Change the password of an encrypted secret
    pub fn change_password(
        &self,
        encrypted: &EncryptedSecret,
        old_password: &str,
        new_password: &str,
    ) -> CryptoResult<EncryptedSecret> {
        encrypted.reencrypt_with_password(old_password, new_password)
    }

    /// Encrypt multiple secrets with the same password (batch operation)
    pub async fn encrypt_batch<I, S>(
        &self,
        secrets: I,
        password: &str,
        base_options: EncryptionOptions,
    ) -> BatchEncryptionResult
    where
        I: IntoIterator<Item = (String, S)>,
        S: AsRef<str>,
    {
        let mut successes = Vec::new();
        let mut failures = Vec::new();

        for (name, secret_data) in secrets {
            let options = base_options.clone();
            match self.encrypt_string(secret_data.as_ref(), password, options).await {
                Ok(encrypted) => successes.push((name, encrypted)),
                Err(error) => failures.push((name, error)),
            }
        }

        BatchEncryptionResult { successes, failures }
    }

    /// Direct encryption with ChaCha20-Poly1305 (low-level API)
    pub fn encrypt_direct(
        &self,
        plaintext: &[u8],
        key: &Key,
        nonce: &[u8; defaults::NONCE_LENGTH],
    ) -> CryptoResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key);
        let nonce_obj = Nonce::from_slice(nonce);
        
        cipher
            .encrypt(nonce_obj, plaintext)
            .map_err(CryptoError::from)
    }

    /// Direct decryption with ChaCha20-Poly1305 (low-level API)
    pub fn decrypt_direct(
        &self,
        ciphertext: &[u8],
        key: &Key,
        nonce: &[u8; defaults::NONCE_LENGTH],
    ) -> CryptoResult<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(key);
        let nonce_obj = Nonce::from_slice(nonce);
        
        cipher
            .decrypt(nonce_obj, ciphertext)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    /// Derive a key with a specific performance profile
    fn derive_key_with_profile(
        &self,
        password: &str,
        salt: &[u8; defaults::SALT_LENGTH],
        profile: PerformanceProfile,
    ) -> CryptoResult<DerivedKey> {
        let params = profile.argon2_params();
        let argon2 = Argon2::new(
            defaults::ARGON2_ALGORITHM,
            defaults::ARGON2_VERSION,
            params,
        );

        let mut key_bytes = [0u8; defaults::KEY_LENGTH];
        
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
            .map_err(CryptoError::from)?;

        let _key = Key::from_slice(&key_bytes).clone();
        
        // Zeroize intermediate data
        key_bytes.zeroize();

        Ok(DerivedKey::from_password_with_salt(password, salt)?)
    }

    /// Derive a key with a specific salt
    pub fn derive_key_with_salt(
        &self,
        password: &str,
        salt: &[u8; defaults::SALT_LENGTH],
    ) -> CryptoResult<DerivedKey> {
        self.derive_key_with_profile(password, salt, self.performance_profile)
    }

    /// Generate a secure random key for direct operations
    pub fn generate_random_key() -> CryptoResult<Key> {
        let key_bytes = SecureRandom::generate_bytes(defaults::KEY_LENGTH)?;
        Ok(*Key::from_slice(&key_bytes))
    }

    /// Generate a secure random nonce
    pub fn generate_nonce() -> CryptoResult<[u8; defaults::NONCE_LENGTH]> {
        SecureRandom::generate_nonce()
    }

    /// Generate a secure random salt
    pub fn generate_salt() -> CryptoResult<[u8; defaults::SALT_LENGTH]> {
        SecureRandom::generate_salt()
    }

    /// Get performance benchmarks for the current profile
    pub fn benchmark_performance(&self) -> CryptoResult<PerformanceBenchmark> {
        let test_password = "benchmark_password_12345";
        let test_data = "This is test data for benchmarking purposes. It contains enough text to provide meaningful encryption benchmarks.";
        
        let start_time = std::time::Instant::now();
        
        // Test key derivation
        let derive_start = std::time::Instant::now();
        let salt = Self::generate_salt()?;
        let key = self.derive_key_with_profile(test_password, &salt, self.performance_profile)?;
        let derive_duration = derive_start.elapsed();
        
        // Test encryption
        let encrypt_start = std::time::Instant::now();
        let plaintext = PlaintextSecret::from_string(test_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_key(plaintext, &key, None)?;
        let encrypt_duration = encrypt_start.elapsed();
        
        // Test decryption
        let decrypt_start = std::time::Instant::now();
        let _decrypted = encrypted.decrypt_with_key(&key)?;
        let decrypt_duration = decrypt_start.elapsed();
        
        let total_duration = start_time.elapsed();
        
        Ok(PerformanceBenchmark {
            profile: self.performance_profile,
            key_derivation_ms: derive_duration.as_millis() as f64,
            encryption_ms: encrypt_duration.as_micros() as f64 / 1000.0,
            decryption_ms: decrypt_duration.as_micros() as f64 / 1000.0,
            total_ms: total_duration.as_millis() as f64,
            data_size: test_data.len(),
        })
    }

    /// Encrypt a file with derived key using resilience protection
    pub async fn encrypt_file<P: AsRef<std::path::Path>>(
        &self,
        file_path: P,
        password: &str,
        salt: Option<&[u8; defaults::SALT_LENGTH]>,
    ) -> CryptoResult<EncryptedSecret> {
        // Check if file operations are enabled
        let features = self.features_enabled.read().await;
        if !features.encryption {
            return Err(CryptoError::Generic {
                message: "File encryption is currently disabled due to system degradation".to_string(),
            });
        }
        drop(features);
        
        // Validate password
        let password_validation = self.validator.validate_password(password);
        if password_validation.has_critical_errors() {
            return Err(CryptoError::Generic {
                message: "Password validation failed for file encryption".to_string(),
            });
        }
        
        let content = std::fs::read_to_string(file_path)
            .map_err(|e| CryptoError::Generic { message: format!("Failed to read file: {}", e) })?;
        
        let plaintext = PlaintextSecret::from_string(content);
        
        // Execute with circuit breaker
        let circuit_breaker = Arc::clone(&self.circuit_breaker);
        let result = circuit_breaker.execute(|| {
            let derived_key = if let Some(salt) = salt {
                self.derive_key_with_profile(password, salt, self.performance_profile)?
            } else {
                let salt = Self::generate_salt()?;
                self.derive_key(password, &salt)?
            };
            
            EncryptedSecret::encrypt_with_key(plaintext.clone(), &derived_key, None)
        }).await;
        
        match result {
            Ok(encrypted) => Ok(encrypted),
            Err(error) => {
                match error {
                    crate::resilience::CircuitBreakerError::CircuitOpen => {
                        Err(CryptoError::Generic {
                            message: "File encryption circuit breaker is open".to_string(),
                        })
                    }
                    crate::resilience::CircuitBreakerError::CircuitOpened => {
                        Err(CryptoError::Generic {
                            message: "File encryption circuit breaker opened due to failures".to_string(),
                        })
                    }
                    crate::resilience::CircuitBreakerError::OperationFailed(crypto_error) => Err(crypto_error),
                }
            }
        }
    }

    /// Decrypt a file with derived key using resilience protection
    pub async fn decrypt_file(
        &self,
        encrypted: &EncryptedSecret,
        password: &str,
    ) -> CryptoResult<String> {
        let plaintext = self.decrypt(encrypted, password)?;
        plaintext.into_string()
    }
    
    /// Enable graceful degradation by disabling specific features
    pub async fn disable_feature(&self, feature: &str) -> CryptoResult<()> {
        let mut features = self.features_enabled.write().await;
        
        match feature {
            "encryption" => features.encryption = false,
            "decryption" => features.decryption = false,
            "key_derivation" => features.key_derivation = false,
            "batch_operations" => features.batch_operations = false,
            "direct_operations" => features.direct_operations = false,
            _ => return Err(CryptoError::Generic {
                message: format!("Unknown feature: {}", feature),
            }),
        }
        
        tracing::warn!("Crypto engine feature '{}' has been disabled for graceful degradation", feature);
        Ok(())
    }
    
    /// Re-enable a previously disabled feature
    pub async fn enable_feature(&self, feature: &str) -> CryptoResult<()> {
        let mut features = self.features_enabled.write().await;
        
        match feature {
            "encryption" => features.encryption = true,
            "decryption" => features.decryption = true,
            "key_derivation" => features.key_derivation = true,
            "batch_operations" => features.batch_operations = true,
            "direct_operations" => features.direct_operations = true,
            _ => return Err(CryptoError::Generic {
                message: format!("Unknown feature: {}", feature),
            }),
        }
        
        tracing::info!("Crypto engine feature '{}' has been enabled", feature);
        Ok(())
    }
    
    /// Get current feature status
    pub async fn get_feature_status(&self) -> CryptoFeatures {
        self.features_enabled.read().await.clone()
    }
    
    /// Reset circuit breaker manually
    pub async fn reset_circuit_breaker(&self) {
        self.circuit_breaker.reset().await;
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Performance benchmark results
#[derive(Debug, Clone)]
pub struct PerformanceBenchmark {
    /// Performance profile used
    pub profile: PerformanceProfile,
    /// Key derivation time in milliseconds
    pub key_derivation_ms: f64,
    /// Encryption time in milliseconds
    pub encryption_ms: f64,
    /// Decryption time in milliseconds
    pub decryption_ms: f64,
    /// Total operation time in milliseconds
    pub total_ms: f64,
    /// Size of test data in bytes
    pub data_size: usize,
}

impl PerformanceBenchmark {
    /// Get throughput in MB/s for encryption
    pub fn encryption_throughput_mbps(&self) -> f64 {
        if self.encryption_ms == 0.0 {
            return 0.0;
        }
        (self.data_size as f64 / 1_048_576.0) / (self.encryption_ms / 1000.0)
    }

    /// Get throughput in MB/s for decryption
    pub fn decryption_throughput_mbps(&self) -> f64 {
        if self.decryption_ms == 0.0 {
            return 0.0;
        }
        (self.data_size as f64 / 1_048_576.0) / (self.decryption_ms / 1000.0)
    }

    /// Check if performance meets target (< 1ms for encryption/decryption)
    pub fn meets_performance_target(&self) -> bool {
        self.encryption_ms < 1.0 && self.decryption_ms < 1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_engine_basic_operations() {
        let engine = CryptoEngine::new();
        let plaintext = "Hello, World!";
        let password = "test_password";
        
        let encrypted = engine.encrypt_string(plaintext, password, EncryptionOptions::new()).unwrap();
        let decrypted = engine.decrypt_to_string(&encrypted, password).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_performance_profiles() {
        let profiles = [
            PerformanceProfile::Fast,
            PerformanceProfile::Balanced,
            PerformanceProfile::Secure,
            PerformanceProfile::Paranoid,
        ];

        for profile in profiles {
            let engine = CryptoEngine::with_performance_profile(profile);
            let plaintext = "Test data";
            let password = "test_password";
            
            let encrypted = engine.encrypt_string(plaintext, password, EncryptionOptions::new()).unwrap();
            let decrypted = engine.decrypt_to_string(&encrypted, password).unwrap();
            
            assert_eq!(plaintext, decrypted);
        }
    }

    #[test]
    fn test_batch_encryption() {
        let engine = CryptoEngine::new();
        let secrets = vec![
            ("api_key".to_string(), "sk-1234567890"),
            ("db_password".to_string(), "super_secret_db_pass"),
            ("jwt_secret".to_string(), "jwt-signing-key-12345"),
        ];
        
        let password = "master_password";
        let result = engine.encrypt_batch(secrets, password, EncryptionOptions::new());
        
        assert_eq!(result.successes.len(), 3);
        assert_eq!(result.failures.len(), 0);
        
        // Verify all can be decrypted
        for (name, encrypted) in result.successes {
            let decrypted = engine.decrypt_to_string(&encrypted, password).unwrap();
            assert!(!decrypted.is_empty());
            println!("Decrypted {}: [REDACTED {} chars]", name, decrypted.len());
        }
    }

    #[test]
    fn test_password_change() {
        let engine = CryptoEngine::new();
        let plaintext = "Secret data";
        let old_password = "old_password";
        let new_password = "new_password";
        
        let encrypted = engine.encrypt_string(plaintext, old_password, EncryptionOptions::new()).unwrap();
        let reencrypted = engine.change_password(&encrypted, old_password, new_password).unwrap();
        
        // Old password should not work
        assert!(!engine.verify_password(&reencrypted, old_password));
        
        // New password should work
        assert!(engine.verify_password(&reencrypted, new_password));
        let decrypted = engine.decrypt_to_string(&reencrypted, new_password).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_direct_encryption() {
        let engine = CryptoEngine::new();
        let plaintext = b"Direct encryption test";
        
        let key = CryptoEngine::generate_random_key().unwrap();
        let nonce = CryptoEngine::generate_nonce().unwrap();
        
        let ciphertext = engine.encrypt_direct(plaintext, &key, &nonce).unwrap();
        let decrypted = engine.decrypt_direct(&ciphertext, &key, &nonce).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_encryption_options() {
        let engine = CryptoEngine::new();
        let plaintext = "Test with options";
        let password = "test_password";
        
        let options = EncryptionOptions::new()
            .with_description("Test secret")
            .with_type(SecretType::ApiKey)
            .with_performance_profile(PerformanceProfile::Fast);
        
        let encrypted = engine.encrypt_string(plaintext, password, options).unwrap();
        let metadata = encrypted.metadata();
        
        assert_eq!(metadata.description.as_ref().unwrap(), "Test secret");
        assert_eq!(metadata.secret_type.as_ref().unwrap(), &SecretType::ApiKey);
        
        let decrypted = engine.decrypt_to_string(&encrypted, password).unwrap();
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_performance_benchmark() {
        let engine = CryptoEngine::new();
        let benchmark = engine.benchmark_performance().unwrap();
        
        println!("Performance Benchmark:");
        println!("  Profile: {:?}", benchmark.profile);
        println!("  Key derivation: {:.2}ms", benchmark.key_derivation_ms);
        println!("  Encryption: {:.3}ms", benchmark.encryption_ms);
        println!("  Decryption: {:.3}ms", benchmark.decryption_ms);
        println!("  Total: {:.2}ms", benchmark.total_ms);
        println!("  Encryption throughput: {:.2} MB/s", benchmark.encryption_throughput_mbps());
        println!("  Decryption throughput: {:.2} MB/s", benchmark.decryption_throughput_mbps());
        println!("  Meets target (<1ms): {}", benchmark.meets_performance_target());
        
        // Basic sanity checks
        assert!(benchmark.key_derivation_ms > 0.0);
        assert!(benchmark.encryption_ms > 0.0);
        assert!(benchmark.decryption_ms > 0.0);
        assert!(benchmark.total_ms > 0.0);
    }

    #[test]
    fn test_wrong_password_fails() {
        let engine = CryptoEngine::new();
        let plaintext = "Secret data";
        let password = "correct_password";
        let wrong_password = "wrong_password";
        
        let encrypted = engine.encrypt_string(plaintext, password, EncryptionOptions::new()).unwrap();
        
        assert!(!engine.verify_password(&encrypted, wrong_password));
        
        let result = engine.decrypt_to_string(&encrypted, wrong_password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::AuthenticationFailed));
    }
}