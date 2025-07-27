//! Cryptographic operations module
//! 
//! This module provides secure cryptographic operations using ChaCha20-Poly1305
//! for authenticated encryption and Argon2 for key derivation.

pub mod engine;
pub mod keys;
pub mod secrets;
pub mod errors;
pub mod algorithm;
pub mod store;
pub mod mock;
pub mod security;

pub use engine::{CryptoEngine, PerformanceProfile, EncryptionOptions, PerformanceBenchmark, BatchEncryptionResult};
pub use keys::{DerivedKey, KeyDerivationParams, SecureRandom};
pub use secrets::{EncryptedSecret, PlaintextSecret, SecretMetadata, SecretType};
pub use errors::{CryptoError, CryptoResult};
pub use algorithm::{Algorithm, AlgorithmExt};
pub use store::{SecretStore, MemorySecretStore};
pub use security::{SecureBuffer, SecureRandom as SecurityRandom, TimingDefense, KeyDerivationValidator, constant_time_compare};

// Re-export commonly used types
pub use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
pub use argon2::Argon2;

/// Default parameters for cryptographic operations
pub mod defaults {
    use argon2::{Algorithm, Params, Version};

    /// Default Argon2 parameters - balance between security and performance
    pub const ARGON2_PARAMS: Params = match Params::new(
        65536, // memory cost (64 MB)
        3,     // time cost (iterations)
        4,     // parallelism
        Some(32), // output length
    ) {
        Ok(params) => params,
        Err(_) => panic!("Invalid default Argon2 parameters"),
    };

    /// Default Argon2 algorithm and version
    pub const ARGON2_ALGORITHM: Algorithm = Algorithm::Argon2id;
    pub const ARGON2_VERSION: Version = Version::V0x13;

    /// Salt length for key derivation (32 bytes)
    pub const SALT_LENGTH: usize = 32;

    /// Nonce length for ChaCha20-Poly1305 (12 bytes)
    pub const NONCE_LENGTH: usize = 12;

    /// Key length for ChaCha20-Poly1305 (32 bytes)
    pub const KEY_LENGTH: usize = 32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_exports() {
        // Test that all public exports are accessible
        let _engine = CryptoEngine::new();
        assert!(true, "Module exports are accessible");
    }
}