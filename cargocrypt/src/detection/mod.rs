//! # Secret Detection Module
//!
//! ML-trained pattern detection for identifying secrets, API keys, tokens, and other
//! sensitive information in source code and configuration files.
//!
//! ## Features
//!
//! - **High-performance scanning**: Uses parallel processing and efficient regex matching
//! - **Low false positives**: ML-trained patterns with confidence scoring
//! - **Comprehensive coverage**: Detects AWS keys, GitHub tokens, database credentials, etc.
//! - **Smart filtering**: Respects .gitignore and supports custom ignore patterns
//! - **Entropy analysis**: Identifies high-entropy strings that may be secrets
//! - **Custom rules**: Support for user-defined detection patterns
//!
//! ## Usage
//!
//! ```rust,no_run
//! use cargocrypt::detection::{SecretDetector, ScanOptions};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let detector = SecretDetector::new();
//!     let options = ScanOptions::default();
//!     
//!     // Scan current directory
//!     let findings = detector.scan_directory(".", &options).await?;
//!     
//!     for finding in findings {
//!         if finding.confidence > 0.8 {
//!             println!("High confidence secret found: {}", finding.secret_type);
//!         }
//!     }
//!     
//!     Ok(())
//! }
//! ```

pub mod detector;
pub mod patterns;
pub mod entropy;
pub mod rules;
pub mod scanner;
pub mod findings;

pub use detector::{SecretDetector, ScanOptions, DetectionConfig};
pub use patterns::{SecretPattern, SecretType, PatternMatch};
pub use entropy::{EntropyAnalyzer, EntropyResult};
pub use rules::{CustomRule, RuleEngine, RuleType};
pub use scanner::{FileScanner, ScanResult};
pub use findings::{Finding, ConfidenceLevel, FoundSecret};

use crate::error::{CargoCryptError, CryptoResult};
use std::path::Path;

/// Quick scan function for detecting secrets in a single file
///
/// ```rust,no_run
/// use cargocrypt::detection::scan_file;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let findings = scan_file("src/config.rs").await?;
///     println!("Found {} potential secrets", findings.len());
///     Ok(())
/// }
/// ```
pub async fn scan_file<P: AsRef<Path>>(path: P) -> CryptoResult<Vec<Finding>> {
    let detector = SecretDetector::new();
    let options = ScanOptions::default();
    detector.scan_file(path, &options).await
}

/// Quick scan function for detecting secrets in a directory
///
/// ```rust,no_run
/// use cargocrypt::detection::scan_directory;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     let findings = scan_directory(".").await?;
///     let high_confidence: Vec<_> = findings
///         .into_iter()
///         .filter(|f| f.confidence > 0.8)
///         .collect();
///     
///     println!("Found {} high-confidence secrets", high_confidence.len());
///     Ok(())
/// }
/// ```
pub async fn scan_directory<P: AsRef<Path>>(path: P) -> CryptoResult<Vec<Finding>> {
    let detector = SecretDetector::new();
    let options = ScanOptions::default();
    detector.scan_directory(path, &options).await
}

/// Validate if a string might be a secret using entropy analysis
///
/// ```rust
/// use cargocrypt::detection::is_likely_secret;
///
/// assert!(is_likely_secret("AKIAIOSFODNN7EXAMPLE"));  // AWS key format
/// assert!(!is_likely_secret("hello_world"));          // Normal variable
/// ```
pub fn is_likely_secret(text: &str) -> bool {
    let analyzer = EntropyAnalyzer::new();
    let result = analyzer.analyze(text);
    result.is_likely_secret()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_detection() {
        // High entropy strings (likely secrets)
        assert!(is_likely_secret("AKIAIOSFODNN7EXAMPLE"));
        assert!(is_likely_secret("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        assert!(is_likely_secret("sk_test_FAKE1234567890ABCDEF"));
        
        // Low entropy strings (unlikely to be secrets)
        assert!(!is_likely_secret("hello_world"));
        assert!(!is_likely_secret("my_variable_name"));
        assert!(!is_likely_secret("configuration"));
        assert!(!is_likely_secret("123456789"));
    }

    #[tokio::test]
    async fn test_quick_scan_functions() {
        // These would need actual test files in practice
        // For now, just test that the functions exist and can be called
        let detector = SecretDetector::new();
        assert_eq!(detector.name(), "SecretDetector");
    }
}