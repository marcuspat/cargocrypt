//! # CargoCrypt - Zero-config cryptographic operations for Rust projects
//!
//! CargoCrypt provides enterprise-grade cryptography with zero configuration required.
//! It follows the Rust ecosystem's convention-over-configuration philosophy, similar
//! to successful tools like cargo-audit and ripgrep.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use cargocrypt::{CargoCrypt, CryptoConfig};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Zero-config initialization
//!     let crypt = CargoCrypt::new().await?;
//!     
//!     // Encrypt a file
//!     crypt.encrypt_file("src/secrets.rs").await?;
//!     
//!     // Decrypt when needed
//!     crypt.decrypt_file("src/secrets.rs.enc").await?;
//!     
//!     Ok(())
//! }
//! ```

// Re-export main types for easy access
pub use crate::core::{CargoCrypt, CryptoConfig};
pub use crate::crypto::{
    CryptoEngine, DerivedKey, EncryptedSecret, PlaintextSecret, 
    SecretMetadata, SecretType as CryptoSecretType, PerformanceProfile, EncryptionOptions,
    CryptoError, CryptoResult as CryptoCoreResult
};
pub use crate::error::{CargoCryptError, ErrorKind, CryptoResult};
pub use crate::detection::{
    SecretDetector, ScanOptions, DetectionConfig, Finding, FoundSecret,
    SecretType as DetectionSecretType, PatternMatch, EntropyResult, CustomRule, RuleEngine,
};

// Core modules
pub mod core;
pub mod crypto;
pub mod error;

// Feature modules
// pub mod auth;
pub mod detection;
pub mod git;
// pub mod providers;
// pub mod tui;

/// Default configuration that works for most use cases
///
/// This embodies the "zero-config" philosophy - smart defaults that just work.
pub fn default_config() -> CryptoConfig {
    CryptoConfig::default()
}

/// Initialize CargoCrypt in the current directory
///
/// This is the equivalent of `cargo crypt init` - it sets up the necessary
/// directory structure and configuration files if they don't exist.
pub async fn init() -> CryptoResult<()> {
    CargoCrypt::init_project().await
}

/// Quick encrypt function for simple use cases
///
/// ```rust,no_run
/// # use cargocrypt::encrypt;
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// // Encrypt with default settings
/// encrypt("sensitive.txt").await?;
/// # Ok(())
/// # }
/// ```
pub async fn encrypt<P: AsRef<std::path::Path>>(path: P) -> CryptoResult<std::path::PathBuf> {
    let crypt = CargoCrypt::new().await?;
    crypt.encrypt_file(path).await
}

/// Quick decrypt function for simple use cases
///
/// ```rust,no_run
/// # use cargocrypt::decrypt;
/// # #[tokio::main]
/// # async fn main() -> anyhow::Result<()> {
/// // Decrypt with default settings
/// decrypt("sensitive.txt.enc").await?;
/// # Ok(())
/// # }
/// ```
pub async fn decrypt<P: AsRef<std::path::Path>>(path: P) -> CryptoResult<std::path::PathBuf> {
    let crypt = CargoCrypt::new().await?;
    crypt.decrypt_file(path).await
}

/// Utility functions for common operations
pub mod utils {
    use crate::CryptoResult;
    use std::path::Path;

    /// Check if a file is encrypted by CargoCrypt
    pub fn is_encrypted<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref()
            .extension()
            .map(|ext| ext == "enc")
            .unwrap_or(false)
    }

    /// Get the original filename for an encrypted file
    pub fn original_filename<P: AsRef<Path>>(encrypted_path: P) -> Option<String> {
        encrypted_path
            .as_ref()
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(|s| s.to_string())
    }

    /// Check if we're in a Rust project (has Cargo.toml)
    pub fn is_rust_project() -> bool {
        Path::new("Cargo.toml").exists()
    }

    /// Find the root of the current Rust project
    pub fn find_project_root() -> CryptoResult<std::path::PathBuf> {
        let mut current = std::env::current_dir()?;
        
        loop {
            if current.join("Cargo.toml").exists() {
                return Ok(current);
            }
            
            if !current.pop() {
                break;
            }
        }
        
        Err(crate::error::CargoCryptError::project_not_found())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_encrypted() {
        assert!(utils::is_encrypted("file.txt.enc"));
        assert!(!utils::is_encrypted("file.txt"));
        assert!(!utils::is_encrypted("file"));
    }

    #[test]
    fn test_original_filename() {
        assert_eq!(utils::original_filename("file.txt.enc"), Some("file.txt".to_string()));
        assert_eq!(utils::original_filename("secrets.rs.enc"), Some("secrets.rs".to_string()));
        assert_eq!(utils::original_filename("file.txt"), Some("file".to_string()));
    }

    #[test]
    fn test_default_config() {
        let config = default_config();
        // Should have sensible defaults
        assert!(!config.performance_profiles().is_empty());
    }
}
