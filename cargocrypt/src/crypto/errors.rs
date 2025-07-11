//! Cryptographic error types

use thiserror::Error;

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    /// Key derivation failed
    #[error("Key derivation failed: {reason}")]
    KeyDerivation { reason: String },

    /// Encryption operation failed
    #[error("Encryption failed: {reason}")]
    Encryption { reason: String },

    /// Decryption operation failed
    #[error("Decryption failed: {reason}")]
    Decryption { reason: String },

    /// Invalid key format or length
    #[error("Invalid key: {reason}")]
    InvalidKey { reason: String },

    /// Invalid nonce format or length
    #[error("Invalid nonce: {reason}")]
    InvalidNonce { reason: String },

    /// Invalid salt format or length
    #[error("Invalid salt: {reason}")]
    InvalidSalt { reason: String },

    /// Random number generation failed
    #[error("Random number generation failed: {reason}")]
    RandomGeneration { reason: String },

    /// Invalid input data
    #[error("Invalid input: {reason}")]
    InvalidInput { reason: String },

    /// Serialization/deserialization error
    #[error("Serialization error: {reason}")]
    Serialization { reason: String },

    /// Authentication tag verification failed
    #[error("Authentication failed - data may have been tampered with")]
    AuthenticationFailed,

    /// Generic cryptographic error
    #[error("Cryptographic operation failed: {message}")]
    Generic { message: String },
}

impl CryptoError {
    /// Create a key derivation error
    pub fn key_derivation<S: Into<String>>(reason: S) -> Self {
        Self::KeyDerivation {
            reason: reason.into(),
        }
    }

    /// Create an encryption error
    pub fn encryption<S: Into<String>>(reason: S) -> Self {
        Self::Encryption {
            reason: reason.into(),
        }
    }

    /// Create a decryption error
    pub fn decryption<S: Into<String>>(reason: S) -> Self {
        Self::Decryption {
            reason: reason.into(),
        }
    }

    /// Create an invalid key error
    pub fn invalid_key<S: Into<String>>(reason: S) -> Self {
        Self::InvalidKey {
            reason: reason.into(),
        }
    }

    /// Create an invalid nonce error
    pub fn invalid_nonce<S: Into<String>>(reason: S) -> Self {
        Self::InvalidNonce {
            reason: reason.into(),
        }
    }

    /// Create an invalid salt error
    pub fn invalid_salt<S: Into<String>>(reason: S) -> Self {
        Self::InvalidSalt {
            reason: reason.into(),
        }
    }

    /// Create a random generation error
    pub fn random_generation<S: Into<String>>(reason: S) -> Self {
        Self::RandomGeneration {
            reason: reason.into(),
        }
    }

    /// Create an invalid input error
    pub fn invalid_input<S: Into<String>>(reason: S) -> Self {
        Self::InvalidInput {
            reason: reason.into(),
        }
    }

    /// Create a serialization error
    pub fn serialization<S: Into<String>>(reason: S) -> Self {
        Self::Serialization {
            reason: reason.into(),
        }
    }

    /// Create a generic error
    pub fn generic<S: Into<String>>(message: S) -> Self {
        Self::Generic {
            message: message.into(),
        }
    }

    /// Create an authentication failed error
    pub fn authentication_failed() -> Self {
        Self::AuthenticationFailed
    }
}

/// Convert from various error types
impl From<argon2::Error> for CryptoError {
    fn from(err: argon2::Error) -> Self {
        CryptoError::key_derivation(err.to_string())
    }
}

impl From<chacha20poly1305::Error> for CryptoError {
    fn from(err: chacha20poly1305::Error) -> Self {
        CryptoError::encryption(err.to_string())
    }
}

impl From<hex::FromHexError> for CryptoError {
    fn from(err: hex::FromHexError) -> Self {
        CryptoError::serialization(err.to_string())
    }
}

impl From<serde_json::Error> for CryptoError {
    fn from(err: serde_json::Error) -> Self {
        CryptoError::serialization(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = CryptoError::encryption("test reason");
        assert!(err.to_string().contains("test reason"));
    }

    #[test]
    fn test_error_conversion() {
        let argon_err = argon2::Error::B64Encoding(base64ct::Error::InvalidEncoding);
        let crypto_err: CryptoError = argon_err.into();
        assert!(matches!(crypto_err, CryptoError::KeyDerivation { .. }));
    }
}