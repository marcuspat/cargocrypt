//! Main cryptographic engine implementation

use crate::crypto::{
    CryptoError, CryptoResult, DerivedKey, EncryptedSecret, PlaintextSecret, 
    SecretMetadata, SecretType, defaults, keys::SecureRandom
};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit}};
use argon2::Argon2;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;
use serde::{Deserialize, Serialize};

/// Main cryptographic engine for CargoCrypt
/// 
/// This engine provides high-level cryptographic operations using ChaCha20-Poly1305
/// for authenticated encryption and Argon2 for key derivation.
#[derive(Debug, Clone)]
pub struct CryptoEngine {
    /// Performance settings for key derivation
    performance_profile: PerformanceProfile,
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
    /// Create a new crypto engine with default (balanced) settings
    pub fn new() -> Self {
        Self {
            performance_profile: PerformanceProfile::default(),
        }
    }

    /// Create a crypto engine with a specific performance profile
    pub fn with_performance_profile(profile: PerformanceProfile) -> Self {
        Self {
            performance_profile: profile,
        }
    }

    /// Get the current performance profile
    pub fn performance_profile(&self) -> PerformanceProfile {
        self.performance_profile
    }

    /// Set the performance profile
    pub fn set_performance_profile(&mut self, profile: PerformanceProfile) {
        self.performance_profile = profile;
    }

    /// Encrypt a string with a password
    pub fn encrypt_string(
        &self,
        plaintext: &str,
        password: &str,
        options: EncryptionOptions,
    ) -> CryptoResult<EncryptedSecret> {
        let secret = PlaintextSecret::from_string(plaintext.to_string());
        self.encrypt(secret, password, options)
    }

    /// Encrypt bytes with a password
    pub fn encrypt_bytes(
        &self,
        plaintext: &[u8],
        password: &str,
        options: EncryptionOptions,
    ) -> CryptoResult<EncryptedSecret> {
        let secret = PlaintextSecret::from_bytes(plaintext.to_vec());
        self.encrypt(secret, password, options)
    }

    /// Encrypt a plaintext secret with a password
    pub fn encrypt(
        &self,
        plaintext: PlaintextSecret,
        password: &str,
        options: EncryptionOptions,
    ) -> CryptoResult<EncryptedSecret> {
        // Determine the performance profile to use
        let profile = options.performance_profile.unwrap_or(self.performance_profile);
        
        // Create or use provided salt
        let salt = match options.salt {
            Some(salt) => salt,
            None => SecureRandom::generate_salt()?,
        };

        // Derive key using the specified performance profile
        let key = self.derive_key_with_profile(password, &salt, profile)?;
        
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

        EncryptedSecret::encrypt_with_key(plaintext, &key, metadata)
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
    pub fn encrypt_batch<I, S>(
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
            match self.encrypt_string(secret_data.as_ref(), password, options) {
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

        let key = Key::from_slice(&key_bytes).clone();
        
        // Zeroize intermediate data
        key_bytes.zeroize();

        Ok(DerivedKey::from_password_with_salt(password, salt)?)
    }

    /// Generate a secure random key for direct operations
    pub fn generate_key() -> CryptoResult<Key> {
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
        
        let key = CryptoEngine::generate_key().unwrap();
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