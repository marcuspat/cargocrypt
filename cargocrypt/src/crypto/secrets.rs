//! Encrypted secret storage with automatic zeroization

use crate::crypto::{CryptoError, CryptoResult, defaults, DerivedKey};
use chacha20poly1305::{ChaCha20Poly1305, Nonce, aead::{Aead, KeyInit}};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fmt;

/// An encrypted secret that automatically zeroizes plaintext data
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    /// Encrypted data
    ciphertext: Vec<u8>,
    /// Nonce used for encryption
    nonce: [u8; defaults::NONCE_LENGTH],
    /// Salt used for key derivation
    salt: [u8; defaults::SALT_LENGTH],
    /// Optional metadata (not encrypted)
    #[serde(default)]
    metadata: SecretMetadata,
}

/// Metadata associated with an encrypted secret
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Human-readable description
    pub description: Option<String>,
    /// Creation timestamp (Unix timestamp)
    pub created_at: Option<u64>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// Secret type hint
    pub secret_type: Option<SecretType>,
}

/// Types of secrets that can be stored
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SecretType {
    /// Generic secret data
    Generic,
    /// API key or token
    ApiKey,
    /// Password
    Password,
    /// Private key (cryptographic)
    PrivateKey,
    /// Database connection string
    DatabaseUrl,
    /// Configuration data
    Config,
    /// Custom type
    Custom(String),
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretType::Generic => write!(f, "generic"),
            SecretType::ApiKey => write!(f, "api_key"),
            SecretType::Password => write!(f, "password"),
            SecretType::PrivateKey => write!(f, "private_key"),
            SecretType::DatabaseUrl => write!(f, "database_url"),
            SecretType::Config => write!(f, "config"),
            SecretType::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// Plaintext secret data with automatic zeroization
#[derive(ZeroizeOnDrop)]
pub struct PlaintextSecret {
    /// The secret data
    data: Vec<u8>,
}

impl PlaintextSecret {
    /// Create a new plaintext secret from bytes
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new plaintext secret from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new plaintext secret from a string
    pub fn from_string(data: String) -> Self {
        Self {
            data: data.into_bytes(),
        }
    }

    /// Get the secret data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the secret data as a string (if valid UTF-8)
    pub fn as_string(&self) -> CryptoResult<&str> {
        std::str::from_utf8(&self.data)
            .map_err(|e| CryptoError::invalid_input(format!("Invalid UTF-8: {}", e)))
    }

    /// Convert to owned string (if valid UTF-8)
    pub fn into_string(self) -> CryptoResult<String> {
        String::from_utf8(self.data.clone())
            .map_err(|e| CryptoError::invalid_input(format!("Invalid UTF-8: {}", e.utf8_error())))
    }

    /// Get the length of the secret data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for PlaintextSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaintextSecret")
            .field("data", &format!("[{} bytes, REDACTED]", self.data.len()))
            .finish()
    }
}

impl EncryptedSecret {
    /// Encrypt a plaintext secret with a password
    pub fn encrypt_with_password(
        plaintext: PlaintextSecret,
        password: &str,
        metadata: Option<SecretMetadata>,
    ) -> CryptoResult<Self> {
        let key = DerivedKey::from_password_with_random_salt(password)?;
        Self::encrypt_with_key(plaintext, &key, metadata)
    }

    /// Encrypt a plaintext secret with a derived key
    pub fn encrypt_with_key(
        plaintext: PlaintextSecret,
        key: &DerivedKey,
        metadata: Option<SecretMetadata>,
    ) -> CryptoResult<Self> {
        // Generate random nonce
        let nonce_bytes = crate::crypto::keys::SecureRandom::generate_nonce()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Initialize cipher
        let cipher = ChaCha20Poly1305::new(key.key());

        // Encrypt the data
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(CryptoError::from)?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes,
            salt: *key.salt(),
            metadata: metadata.unwrap_or_default(),
        })
    }

    /// Decrypt the secret with a password
    pub fn decrypt_with_password(&self, password: &str) -> CryptoResult<PlaintextSecret> {
        let key = DerivedKey::from_password_with_salt(password, &self.salt)?;
        self.decrypt_with_key(&key)
    }

    /// Decrypt the secret with a derived key
    pub fn decrypt_with_key(&self, key: &DerivedKey) -> CryptoResult<PlaintextSecret> {
        // Verify the salt matches
        if key.salt() != &self.salt {
            return Err(CryptoError::decryption("Salt mismatch"));
        }

        let nonce = Nonce::from_slice(&self.nonce);
        let cipher = ChaCha20Poly1305::new(key.key());

        let plaintext_bytes = cipher
            .decrypt(nonce, self.ciphertext.as_slice())
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(PlaintextSecret::from_bytes(plaintext_bytes))
    }

    /// Get the metadata
    pub fn metadata(&self) -> &SecretMetadata {
        &self.metadata
    }

    /// Update the metadata (does not re-encrypt)
    pub fn set_metadata(&mut self, metadata: SecretMetadata) {
        self.metadata = metadata;
    }

    /// Get the salt used for key derivation
    pub fn salt(&self) -> &[u8; defaults::SALT_LENGTH] {
        &self.salt
    }

    /// Get the nonce used for encryption
    pub fn nonce(&self) -> &[u8; defaults::NONCE_LENGTH] {
        &self.nonce
    }

    /// Get the ciphertext length
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string(self).map_err(CryptoError::from)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> CryptoResult<Self> {
        serde_json::from_str(json).map_err(CryptoError::from)
    }

    /// Serialize to bytes (bincode)
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| CryptoError::serialization(e.to_string()))
    }

    /// Deserialize from bytes (bincode)
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        bincode::deserialize(bytes)
            .map_err(|e| CryptoError::serialization(e.to_string()))
    }

    /// Create a new secret with updated encryption (re-encrypt with new password)
    pub fn reencrypt_with_password(&self, old_password: &str, new_password: &str) -> CryptoResult<Self> {
        let plaintext = self.decrypt_with_password(old_password)?;
        Self::encrypt_with_password(plaintext, new_password, Some(self.metadata.clone()))
    }

    /// Verify that the secret can be decrypted with the given password
    pub fn verify_password(&self, password: &str) -> bool {
        self.decrypt_with_password(password).is_ok()
    }
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce", &hex::encode(&self.nonce))
            .field("salt", &hex::encode(&self.salt))
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl SecretMetadata {
    /// Create new metadata with current timestamp
    pub fn new() -> Self {
        Self {
            description: None,
            created_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            tags: Vec::new(),
            secret_type: None,
        }
    }

    /// Create metadata with description
    pub fn with_description<S: Into<String>>(description: S) -> Self {
        let mut metadata = Self::new();
        metadata.description = Some(description.into());
        metadata
    }

    /// Create metadata with type
    pub fn with_type(secret_type: SecretType) -> Self {
        let mut metadata = Self::new();
        metadata.secret_type = Some(secret_type);
        metadata
    }

    /// Add a tag
    pub fn add_tag<S: Into<String>>(&mut self, tag: S) -> &mut Self {
        self.tags.push(tag.into());
        self
    }

    /// Set the description
    pub fn set_description<S: Into<String>>(&mut self, description: S) -> &mut Self {
        self.description = Some(description.into());
        self
    }

    /// Set the secret type
    pub fn set_type(&mut self, secret_type: SecretType) -> &mut Self {
        self.secret_type = Some(secret_type);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_string() {
        let secret_data = "This is a secret message!";
        let password = "test_password_123";
        
        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_password(
            plaintext,
            password,
            Some(SecretMetadata::with_description("Test secret")),
        ).unwrap();
        
        let decrypted = encrypted.decrypt_with_password(password).unwrap();
        assert_eq!(decrypted.as_string().unwrap(), secret_data);
    }

    #[test]
    fn test_encrypt_decrypt_bytes() {
        let secret_data = vec![1, 2, 3, 4, 5, 255, 0, 128];
        let password = "test_password_123";
        
        let plaintext = PlaintextSecret::from_bytes(secret_data.clone());
        let encrypted = EncryptedSecret::encrypt_with_password(
            plaintext,
            password,
            None,
        ).unwrap();
        
        let decrypted = encrypted.decrypt_with_password(password).unwrap();
        assert_eq!(decrypted.as_bytes(), &secret_data);
    }

    #[test]
    fn test_wrong_password() {
        let secret_data = "This is a secret message!";
        let password = "correct_password";
        let wrong_password = "wrong_password";
        
        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_password(plaintext, password, None).unwrap();
        
        let result = encrypted.decrypt_with_password(wrong_password);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), CryptoError::AuthenticationFailed));
    }

    #[test]
    fn test_password_verification() {
        let secret_data = "secret";
        let password = "test_password";
        
        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_password(plaintext, password, None).unwrap();
        
        assert!(encrypted.verify_password(password));
        assert!(!encrypted.verify_password("wrong_password"));
    }

    #[test]
    fn test_json_serialization() {
        let secret_data = "This is a secret message!";
        let password = "test_password_123";
        
        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_password(
            plaintext,
            password,
            Some(SecretMetadata::with_description("Test secret")),
        ).unwrap();
        
        let json = encrypted.to_json().unwrap();
        let deserialized = EncryptedSecret::from_json(&json).unwrap();
        
        let decrypted = deserialized.decrypt_with_password(password).unwrap();
        assert_eq!(decrypted.as_string().unwrap(), secret_data);
    }

    #[test]
    fn test_reencryption() {
        let secret_data = "This is a secret message!";
        let old_password = "old_password";
        let new_password = "new_password";
        
        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_password(plaintext, old_password, None).unwrap();
        
        let reencrypted = encrypted.reencrypt_with_password(old_password, new_password).unwrap();
        
        // Old password should not work
        assert!(!reencrypted.verify_password(old_password));
        
        // New password should work
        let decrypted = reencrypted.decrypt_with_password(new_password).unwrap();
        assert_eq!(decrypted.as_string().unwrap(), secret_data);
    }

    #[test]
    fn test_metadata() {
        let mut metadata = SecretMetadata::new();
        metadata
            .set_description("API Key for service X")
            .add_tag("production")
            .add_tag("api")
            .set_type(SecretType::ApiKey);
        
        assert_eq!(metadata.description.as_ref().unwrap(), "API Key for service X");
        assert_eq!(metadata.tags, vec!["production", "api"]);
        assert_eq!(metadata.secret_type.as_ref().unwrap(), &SecretType::ApiKey);
        assert!(metadata.created_at.is_some());
    }

    #[test]
    fn test_secret_types() {
        assert_eq!(SecretType::Generic.to_string(), "generic");
        assert_eq!(SecretType::ApiKey.to_string(), "api_key");
        assert_eq!(SecretType::Custom("jwt".to_string()).to_string(), "custom:jwt");
    }

    #[test]
    fn test_plaintext_secret_zeroization() {
        let data = "sensitive_data".to_string();
        let secret = PlaintextSecret::from_string(data);
        
        assert_eq!(secret.len(), 14);
        assert!(!secret.is_empty());
        
        // Secret should be automatically zeroized when dropped
        drop(secret);
        // Can't test the actual zeroization as we can't access the memory after drop
    }
}