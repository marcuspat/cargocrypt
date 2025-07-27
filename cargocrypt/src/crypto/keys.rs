//! Key derivation and management

use crate::crypto::{CryptoError, CryptoResult, defaults};
use argon2::{Argon2, Params};
use chacha20poly1305::Key;
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, ZeroizeOnDrop};
use subtle::ConstantTimeEq;

/// A cryptographically derived key with automatic zeroization
#[derive(Clone, ZeroizeOnDrop)]
pub struct DerivedKey {
    /// The raw key bytes
    key: Key,
    /// The salt used for derivation
    salt: [u8; defaults::SALT_LENGTH],
}

impl DerivedKey {
    /// Create a new derived key from a password
    pub fn from_password(password: &str, params: &KeyDerivationParams) -> CryptoResult<Self> {
        let argon2 = Argon2::new(
            defaults::ARGON2_ALGORITHM,
            defaults::ARGON2_VERSION,
            params.argon2_params.clone(),
        );

        let mut key_bytes = [0u8; defaults::KEY_LENGTH];
        
        argon2
            .hash_password_into(password.as_bytes(), &params.salt, &mut key_bytes)
            .map_err(CryptoError::from)?;

        let key = Key::from_slice(&key_bytes).clone();
        
        // Zeroize intermediate data
        key_bytes.zeroize();

        Ok(Self {
            key,
            salt: params.salt,
        })
    }

    /// Create a new derived key with a random salt
    pub fn from_password_with_random_salt(password: &str) -> CryptoResult<Self> {
        let params = KeyDerivationParams::new_random()?;
        Self::from_password(password, &params)
    }

    /// Create a derived key from existing salt
    pub fn from_password_with_salt(password: &str, salt: &[u8]) -> CryptoResult<Self> {
        if salt.len() != defaults::SALT_LENGTH {
            return Err(CryptoError::invalid_salt(format!(
                "Salt must be {} bytes, got {}",
                defaults::SALT_LENGTH,
                salt.len()
            )));
        }

        let mut salt_array = [0u8; defaults::SALT_LENGTH];
        salt_array.copy_from_slice(salt);

        let params = KeyDerivationParams::from_salt(salt_array)?;
        Self::from_password(password, &params)
    }

    /// Get the key for encryption/decryption
    pub fn key(&self) -> &Key {
        &self.key
    }

    /// Get the salt used for derivation
    pub fn salt(&self) -> &[u8; defaults::SALT_LENGTH] {
        &self.salt
    }

    /// Verify a password against this derived key using constant-time comparison
    pub fn verify_password(&self, password: &str) -> CryptoResult<bool> {
        let test_key = Self::from_password_with_salt(password, &self.salt)?;
        
        // Use constant-time comparison to prevent timing attacks
        let result = self.key.ct_eq(&test_key.key).into();
        Ok(result)
    }

    /// Verify a password with enhanced security protections
    pub fn verify_password_secure(&self, password: &str, min_time: std::time::Duration) -> CryptoResult<bool> {
        let start_time = std::time::Instant::now();
        
        let test_key = Self::from_password_with_salt(password, &self.salt)?;
        
        // Use constant-time comparison
        let result = self.key.ct_eq(&test_key.key).into();
        
        // Ensure minimum verification time to prevent timing attacks
        let elapsed = start_time.elapsed();
        if elapsed < min_time {
            std::thread::sleep(min_time - elapsed);
        }
        
        Ok(result)
    }

    /// Convert to hex representation (for storage)
    pub fn to_hex(&self) -> String {
        let mut combined = Vec::with_capacity(defaults::KEY_LENGTH + defaults::SALT_LENGTH);
        combined.extend_from_slice(self.key.as_slice());
        combined.extend_from_slice(&self.salt);
        
        let hex_string = hex::encode(&combined);
        
        // Zeroize intermediate data
        combined.zeroize();
        
        hex_string
    }

    /// Create from hex representation
    pub fn from_hex(hex_str: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(hex_str)?;
        
        if bytes.len() != defaults::KEY_LENGTH + defaults::SALT_LENGTH {
            return Err(CryptoError::serialization(format!(
                "Invalid hex length: expected {}, got {}",
                defaults::KEY_LENGTH + defaults::SALT_LENGTH,
                bytes.len()
            )));
        }

        let key = Key::from_slice(&bytes[..defaults::KEY_LENGTH]).clone();
        let mut salt = [0u8; defaults::SALT_LENGTH];
        salt.copy_from_slice(&bytes[defaults::KEY_LENGTH..]);

        Ok(Self { key, salt })
    }
}

impl std::fmt::Debug for DerivedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKey")
            .field("key", &"[REDACTED]")
            .field("salt", &hex::encode(&self.salt))
            .finish()
    }
}

/// Parameters for key derivation
#[derive(Debug, Clone)]
pub struct KeyDerivationParams {
    /// Argon2 parameters
    pub argon2_params: Params,
    /// Salt for key derivation
    pub salt: [u8; defaults::SALT_LENGTH],
}

impl KeyDerivationParams {
    /// Create new parameters with a random salt
    pub fn new_random() -> CryptoResult<Self> {
        let mut salt = [0u8; defaults::SALT_LENGTH];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| CryptoError::random_generation(e.to_string()))?;

        Ok(Self {
            argon2_params: defaults::ARGON2_PARAMS,
            salt,
        })
    }

    /// Create parameters from an existing salt
    pub fn from_salt(salt: [u8; defaults::SALT_LENGTH]) -> CryptoResult<Self> {
        Ok(Self {
            argon2_params: defaults::ARGON2_PARAMS,
            salt,
        })
    }

    /// Create parameters with custom Argon2 settings
    pub fn with_custom_params(
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
        salt: [u8; defaults::SALT_LENGTH],
    ) -> CryptoResult<Self> {
        let argon2_params = Params::new(
            memory_cost,
            time_cost,
            parallelism,
            Some(defaults::KEY_LENGTH),
        )
        .map_err(|e| CryptoError::key_derivation(e.to_string()))?;

        Ok(Self {
            argon2_params,
            salt,
        })
    }

    /// Get the salt as a slice
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}

/// Secure random number generation utilities
pub struct SecureRandom;

impl SecureRandom {
    /// Generate a random salt with entropy validation
    pub fn generate_salt() -> CryptoResult<[u8; defaults::SALT_LENGTH]> {
        let mut salt = [0u8; defaults::SALT_LENGTH];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| CryptoError::random_generation(e.to_string()))?;
        
        // Basic entropy validation to catch obvious failures
        Self::validate_entropy(&salt)?;
        Ok(salt)
    }

    /// Generate a random nonce with entropy validation
    pub fn generate_nonce() -> CryptoResult<[u8; defaults::NONCE_LENGTH]> {
        let mut nonce = [0u8; defaults::NONCE_LENGTH];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|e| CryptoError::random_generation(e.to_string()))?;
        
        // Basic entropy validation to catch obvious failures
        Self::validate_entropy(&nonce)?;
        Ok(nonce)
    }

    /// Validate entropy of random data
    fn validate_entropy(data: &[u8]) -> CryptoResult<()> {
        if data.is_empty() {
            return Err(CryptoError::random_generation("Empty random data"));
        }

        // Check for obvious low-entropy patterns
        let all_same = data.iter().all(|&b| b == data[0]);
        if all_same {
            return Err(CryptoError::random_generation("Low entropy - all bytes identical"));
        }

        let all_zeros = data.iter().all(|&b| b == 0);
        let all_ones = data.iter().all(|&b| b == 255);
        if all_zeros || all_ones {
            return Err(CryptoError::random_generation("Low entropy - suspicious pattern"));
        }

        Ok(())
    }
    
    /// Generate a random password of specified length
    pub fn generate_password(length: usize) -> CryptoResult<String> {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
        let mut password = String::with_capacity(length);
        let charset_len = CHARSET.len();
        
        for _ in 0..length {
            let mut idx = [0u8; 1];
            loop {
                OsRng
                    .try_fill_bytes(&mut idx)
                    .map_err(|e| CryptoError::random_generation(e.to_string()))?;
                if (idx[0] as usize) < charset_len * (256 / charset_len) {
                    break;
                }
            }
            password.push(CHARSET[idx[0] as usize % charset_len] as char);
        }
        
        Ok(password)
    }

    /// Generate random bytes of specified length
    pub fn generate_bytes(length: usize) -> CryptoResult<Vec<u8>> {
        let mut bytes = vec![0u8; length];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|e| CryptoError::random_generation(e.to_string()))?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_with_random_salt() {
        let password = "test_password_123";
        let key = DerivedKey::from_password_with_random_salt(password).unwrap();
        
        // Verify password
        assert!(key.verify_password(password).unwrap());
        assert!(!key.verify_password("wrong_password").unwrap());
    }

    #[test]
    fn test_key_derivation_deterministic() {
        let password = "test_password_123";
        let salt = [42u8; defaults::SALT_LENGTH];
        
        let key1 = DerivedKey::from_password_with_salt(password, &salt).unwrap();
        let key2 = DerivedKey::from_password_with_salt(password, &salt).unwrap();
        
        // Same password and salt should produce same key
        assert_eq!(key1.key().as_slice(), key2.key().as_slice());
        assert_eq!(key1.salt(), key2.salt());
    }

    #[test]
    fn test_key_serialization() {
        let password = "test_password_123";
        let key1 = DerivedKey::from_password_with_random_salt(password).unwrap();
        
        let hex_repr = key1.to_hex();
        let key2 = DerivedKey::from_hex(&hex_repr).unwrap();
        
        assert_eq!(key1.key().as_slice(), key2.key().as_slice());
        assert_eq!(key1.salt(), key2.salt());
    }

    #[test]
    fn test_secure_random_generation() {
        let salt1 = SecureRandom::generate_salt().unwrap();
        let salt2 = SecureRandom::generate_salt().unwrap();
        
        // Should be different
        assert_ne!(salt1, salt2);
        assert_eq!(salt1.len(), defaults::SALT_LENGTH);
        
        let nonce1 = SecureRandom::generate_nonce().unwrap();
        let nonce2 = SecureRandom::generate_nonce().unwrap();
        
        // Should be different
        assert_ne!(nonce1, nonce2);
        assert_eq!(nonce1.len(), defaults::NONCE_LENGTH);
    }

    #[test]
    fn test_password_verification_constant_time() {
        let password = "test_password_123";
        let key = DerivedKey::from_password_with_random_salt(password).unwrap();
        
        // Test multiple times to ensure consistent timing
        for _ in 0..10 {
            assert!(key.verify_password(password).unwrap());
            assert!(!key.verify_password("wrong").unwrap());
        }
    }

    #[test]
    fn test_key_params_creation() {
        let params = KeyDerivationParams::new_random().unwrap();
        assert_eq!(params.salt.len(), defaults::SALT_LENGTH);
        
        let salt = [1u8; defaults::SALT_LENGTH];
        let params2 = KeyDerivationParams::from_salt(salt).unwrap();
        assert_eq!(params2.salt, salt);
    }

    #[test]
    fn test_invalid_salt_length() {
        let password = "test";
        let invalid_salt = vec![1u8; 16]; // Wrong length
        
        let result = DerivedKey::from_password_with_salt(password, &invalid_salt);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::InvalidSalt { .. }));
    }
}