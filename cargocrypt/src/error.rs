//! Error types for CargoCrypt
//!
//! This module provides comprehensive error handling with actionable error messages
//! that help developers understand and fix issues quickly.

use std::fmt;

/// Result type alias for CargoCrypt operations
pub type CryptoResult<T> = Result<T, CargoCryptError>;

/// Main error type for CargoCrypt operations
#[derive(Debug, thiserror::Error)]
pub enum CargoCryptError {
    /// I/O errors (file operations, network, etc.)
    #[error("File operation failed: {message}")]
    Io {
        message: String,
        #[source]
        source: std::io::Error,
    },

    /// Cryptographic operation errors
    #[error("Cryptographic operation failed: {message}")]
    Crypto {
        message: String,
        kind: CryptoErrorKind,
    },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        suggestion: Option<String>,
    },

    /// Project structure errors
    #[error("Project structure error: {message}")]
    Project {
        message: String,
        suggestion: Option<String>,
    },

    /// Authentication/Authorization errors
    #[error("Authentication failed: {message}")]
    Auth {
        message: String,
        retry_suggestion: Option<String>,
    },

    /// Key management errors
    #[error("Key management error: {message}")]
    KeyManagement {
        message: String,
        recovery_suggestion: Option<String>,
    },

    /// Serialization/Deserialization errors
    #[error("Serialization error: {message}")]
    Serialization {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Network-related errors
    #[error("Network error: {message}")]
    Network {
        message: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Git operations errors
    #[error("Git operation failed: {message}")]
    Git {
        message: String,
        #[source]
        source: Option<git2::Error>,
    },
}

/// Specific kinds of cryptographic errors
#[derive(Debug, Clone, PartialEq)]
pub enum CryptoErrorKind {
    /// Key derivation failed
    KeyDerivation,
    /// Encryption failed
    Encryption,
    /// Decryption failed
    Decryption,
    /// Invalid key format or length
    InvalidKey,
    /// Invalid nonce or IV
    InvalidNonce,
    /// Authentication tag verification failed
    AuthenticationFailed,
    /// Unsupported algorithm
    UnsupportedAlgorithm,
    /// Random number generation failed
    RandomGenerationFailed,
}

/// Commonly used error constructors for better ergonomics
impl CargoCryptError {
    /// Create a project not found error with helpful suggestion
    pub fn project_not_found() -> Self {
        Self::Project {
            message: "Could not find Cargo.toml in current directory or any parent directories".to_string(),
            suggestion: Some("Run this command from within a Rust project directory, or use 'cargo new' to create a new project".to_string()),
        }
    }

    /// Create a configuration file not found error
    pub fn config_not_found() -> Self {
        Self::Config {
            message: "CargoCrypt configuration file not found".to_string(),
            suggestion: Some("Run 'cargo crypt init' to create a new configuration".to_string()),
        }
    }

    /// Create an invalid password error
    pub fn invalid_password() -> Self {
        Self::Auth {
            message: "Password verification failed".to_string(),
            retry_suggestion: Some("Please check your password and try again".to_string()),
        }
    }

    /// Create a file not found error with context
    pub fn file_not_found(path: &std::path::Path) -> Self {
        Self::Io {
            message: format!("File not found: {}", path.display()),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("File '{}' does not exist", path.display()),
            ),
        }
    }

    /// Create a decryption failure error
    pub fn decryption_failed(details: &str) -> Self {
        Self::Crypto {
            message: format!("Decryption failed: {}", details),
            kind: CryptoErrorKind::Decryption,
        }
    }

    /// Create an encryption failure error
    pub fn encryption_failed(details: &str) -> Self {
        Self::Crypto {
            message: format!("Encryption failed: {}", details),
            kind: CryptoErrorKind::Encryption,
        }
    }

    /// Create a key derivation failure error
    pub fn key_derivation_failed(details: &str) -> Self {
        Self::Crypto {
            message: format!("Key derivation failed: {}", details),
            kind: CryptoErrorKind::KeyDerivation,
        }
    }

    /// Create an invalid key error
    pub fn invalid_key(details: &str) -> Self {
        Self::Crypto {
            message: format!("Invalid key: {}", details),
            kind: CryptoErrorKind::InvalidKey,
        }
    }

    /// Create an authentication failure error
    pub fn authentication_failed() -> Self {
        Self::Crypto {
            message: "Authentication tag verification failed - data may be corrupted or tampered with".to_string(),
            kind: CryptoErrorKind::AuthenticationFailed,
        }
    }

    /// Create a random generation failure error
    pub fn random_generation_failed() -> Self {
        Self::Crypto {
            message: "Failed to generate cryptographically secure random data".to_string(),
            kind: CryptoErrorKind::RandomGenerationFailed,
        }
    }

    /// Create a detection error
    pub fn detection_error(message: &str) -> Self {
        Self::Config {
            message: format!("Detection error: {}", message),
            suggestion: Some("Check detection configuration and patterns".to_string()),
        }
    }

    /// Get the error kind if this is a crypto error
    pub fn crypto_kind(&self) -> Option<&CryptoErrorKind> {
        match self {
            CargoCryptError::Crypto { kind, .. } => Some(kind),
            _ => None,
        }
    }

    /// Check if this error is recoverable (user can retry)
    pub fn is_recoverable(&self) -> bool {
        match self {
            CargoCryptError::Auth { .. } => true,
            CargoCryptError::Network { .. } => true,
            CargoCryptError::Io { source, .. } => matches!(
                source.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::PermissionDenied
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut
            ),
            CargoCryptError::Crypto { kind, .. } => matches!(
                kind,
                CryptoErrorKind::RandomGenerationFailed
            ),
            _ => false,
        }
    }

    /// Get a user-friendly suggestion for resolving this error
    pub fn suggestion(&self) -> Option<&str> {
        match self {
            CargoCryptError::Config { suggestion, .. } => suggestion.as_deref(),
            CargoCryptError::Project { suggestion, .. } => suggestion.as_deref(),
            CargoCryptError::Auth { retry_suggestion, .. } => retry_suggestion.as_deref(),
            CargoCryptError::KeyManagement { recovery_suggestion, .. } => recovery_suggestion.as_deref(),
            _ => None,
        }
    }
}

/// Convert from standard I/O errors
impl From<std::io::Error> for CargoCryptError {
    fn from(error: std::io::Error) -> Self {
        Self::Io {
            message: error.to_string(),
            source: error,
        }
    }
}

/// Convert from serde JSON errors
impl From<serde_json::Error> for CargoCryptError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization {
            message: format!("JSON serialization failed: {}", error),
            source: Box::new(error),
        }
    }
}

/// Convert from TOML errors
impl From<toml::de::Error> for CargoCryptError {
    fn from(error: toml::de::Error) -> Self {
        Self::Serialization {
            message: format!("TOML parsing failed: {}", error),
            source: Box::new(error),
        }
    }
}

/// Convert from reqwest errors
impl From<reqwest::Error> for CargoCryptError {
    fn from(error: reqwest::Error) -> Self {
        Self::Network {
            message: format!("HTTP request failed: {}", error),
            source: Box::new(error),
        }
    }
}

/// Convert from git2 errors
impl From<git2::Error> for CargoCryptError {
    fn from(error: git2::Error) -> Self {
        Self::Git {
            message: format!("Git operation failed: {}", error.message()),
            source: Some(error),
        }
    }
}

/// Error kind enumeration for programmatic error handling
#[derive(Debug, Clone, PartialEq)]
pub enum ErrorKind {
    /// Configuration-related errors
    Config,
    /// File system operation errors
    Io,
    /// Cryptographic operation errors
    Crypto,
    /// Network operation errors
    Network,
    /// Authentication/authorization errors
    Auth,
    /// Git operation errors
    Git,
    /// Project structure errors
    Project,
    /// Key management errors
    KeyManagement,
    /// Serialization errors
    Serialization,
}

impl CargoCryptError {
    /// Get the general error kind
    pub fn kind(&self) -> ErrorKind {
        match self {
            CargoCryptError::Config { .. } => ErrorKind::Config,
            CargoCryptError::Io { .. } => ErrorKind::Io,
            CargoCryptError::Crypto { .. } => ErrorKind::Crypto,
            CargoCryptError::Network { .. } => ErrorKind::Network,
            CargoCryptError::Auth { .. } => ErrorKind::Auth,
            CargoCryptError::Git { .. } => ErrorKind::Git,
            CargoCryptError::Project { .. } => ErrorKind::Project,
            CargoCryptError::KeyManagement { .. } => ErrorKind::KeyManagement,
            CargoCryptError::Serialization { .. } => ErrorKind::Serialization,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_constructors() {
        let err = CargoCryptError::project_not_found();
        assert!(matches!(err.kind(), ErrorKind::Project));
        assert!(err.suggestion().is_some());

        let err = CargoCryptError::invalid_password();
        assert!(matches!(err.kind(), ErrorKind::Auth));
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_crypto_error_kinds() {
        let err = CargoCryptError::decryption_failed("test");
        assert_eq!(err.crypto_kind(), Some(&CryptoErrorKind::Decryption));

        let err = CargoCryptError::encryption_failed("test");
        assert_eq!(err.crypto_kind(), Some(&CryptoErrorKind::Encryption));
    }

    #[test]
    fn test_error_conversions() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let crypto_err: CargoCryptError = io_err.into();
        assert!(matches!(crypto_err.kind(), ErrorKind::Io));
    }

    #[test]
    fn test_recoverable_errors() {
        let auth_err = CargoCryptError::invalid_password();
        assert!(auth_err.is_recoverable());

        let config_err = CargoCryptError::config_not_found();
        assert!(!config_err.is_recoverable());
    }
}