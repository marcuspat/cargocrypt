//! Algorithm types and traits for cryptographic operations
//!
//! This module defines cryptographic algorithms with security best practices:
//! - Only authenticated encryption algorithms are supported
//! - Algorithms are evaluated for side-channel resistance
//! - Security properties are clearly documented

use std::fmt;

/// Supported cryptographic algorithms with security properties
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ChaCha20-Poly1305 authenticated encryption
    /// 
    /// Security properties:
    /// - Authenticated encryption with associated data (AEAD)
    /// - Resistant to timing attacks
    /// - No known cache-timing vulnerabilities
    /// - Post-quantum secure (against known algorithms)
    /// - Stream cipher with polynomial authenticator
    ChaCha20Poly1305,
    
    /// AES-256-GCM authenticated encryption (future implementation)
    /// 
    /// Security properties:
    /// - Authenticated encryption with associated data (AEAD)
    /// - Hardware acceleration on many platforms
    /// - Potential cache-timing vulnerabilities in software implementations
    /// - Post-quantum secure (against known algorithms)
    /// - Block cipher with galois counter mode
    Aes256Gcm,
}

/// Extension trait for algorithm properties and security characteristics
pub trait AlgorithmExt {
    /// Get the key length in bytes
    fn key_length(&self) -> usize;
    
    /// Get the nonce/IV length in bytes
    fn nonce_length(&self) -> usize;
    
    /// Get the authentication tag length in bytes
    fn tag_length(&self) -> usize;
    
    /// Check if this is an authenticated encryption algorithm
    fn is_authenticated(&self) -> bool;
    
    /// Get the security level in bits (minimum of key size and tag size)
    fn security_level_bits(&self) -> usize;
    
    /// Check if the algorithm is resistant to timing attacks
    fn is_timing_attack_resistant(&self) -> bool;
    
    /// Check if the algorithm is resistant to cache-timing attacks
    fn is_cache_timing_resistant(&self) -> bool;
    
    /// Check if the algorithm is believed to be post-quantum secure
    fn is_post_quantum_secure(&self) -> bool;
    
    /// Get algorithm family (stream cipher, block cipher, etc.)
    fn algorithm_family(&self) -> AlgorithmFamily;
    
}

/// Algorithm family classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgorithmFamily {
    /// Stream cipher with polynomial authenticator
    StreamCipher,
    /// Block cipher with authenticated mode
    BlockCipher,
}

impl AlgorithmExt for Algorithm {
    fn key_length(&self) -> usize {
        match self {
            Algorithm::ChaCha20Poly1305 => 32, // 256 bits
            Algorithm::Aes256Gcm => 32,        // 256 bits
        }
    }
    
    fn nonce_length(&self) -> usize {
        match self {
            Algorithm::ChaCha20Poly1305 => 12, // 96 bits
            Algorithm::Aes256Gcm => 12,        // 96 bits
        }
    }
    
    fn tag_length(&self) -> usize {
        match self {
            Algorithm::ChaCha20Poly1305 => 16, // 128 bits
            Algorithm::Aes256Gcm => 16,        // 128 bits
        }
    }
    
    fn is_authenticated(&self) -> bool {
        // All our algorithms are authenticated encryption
        true
    }
    
    fn security_level_bits(&self) -> usize {
        match self {
            Algorithm::ChaCha20Poly1305 => 128, // Limited by Poly1305 tag
            Algorithm::Aes256Gcm => 128,        // Limited by GCM tag
        }
    }
    
    fn is_timing_attack_resistant(&self) -> bool {
        match self {
            Algorithm::ChaCha20Poly1305 => true,  // Software implementation is constant-time
            Algorithm::Aes256Gcm => false,        // Software AES can have timing issues
        }
    }
    
    fn is_cache_timing_resistant(&self) -> bool {
        match self {
            Algorithm::ChaCha20Poly1305 => true,  // No lookup tables in ChaCha20
            Algorithm::Aes256Gcm => false,        // AES S-boxes can cause cache timing
        }
    }
    
    fn is_post_quantum_secure(&self) -> bool {
        match self {
            Algorithm::ChaCha20Poly1305 => true,  // Symmetric crypto is PQ-secure
            Algorithm::Aes256Gcm => true,         // Symmetric crypto is PQ-secure
        }
    }
    
    fn algorithm_family(&self) -> AlgorithmFamily {
        match self {
            Algorithm::ChaCha20Poly1305 => AlgorithmFamily::StreamCipher,
            Algorithm::Aes256Gcm => AlgorithmFamily::BlockCipher,
        }
    }
    
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::ChaCha20Poly1305 => write!(f, "ChaCha20-Poly1305"),
            Algorithm::Aes256Gcm => write!(f, "AES-256-GCM"),
        }
    }
}

impl Default for Algorithm {
    fn default() -> Self {
        // ChaCha20-Poly1305 is preferred due to better side-channel resistance
        Algorithm::ChaCha20Poly1305
    }
}

impl Algorithm {
    /// Get all supported algorithms
    pub fn all() -> &'static [Algorithm] {
        &[Algorithm::ChaCha20Poly1305, Algorithm::Aes256Gcm]
    }
    
    /// Get algorithms suitable for timing-attack resistance
    pub fn timing_resistant() -> Vec<Algorithm> {
        Self::all()
            .iter()
            .filter(|alg| alg.is_timing_attack_resistant())
            .copied()
            .collect()
    }
    
    /// Get the most secure algorithm for side-channel resistance
    pub fn most_secure() -> Algorithm {
        // Prefer ChaCha20-Poly1305 for its side-channel resistance
        Algorithm::ChaCha20Poly1305
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_algorithm_properties() {
        let alg = Algorithm::ChaCha20Poly1305;
        assert_eq!(alg.key_length(), 32);
        assert_eq!(alg.nonce_length(), 12);
        assert_eq!(alg.tag_length(), 16);
        assert!(alg.is_authenticated());
        assert_eq!(alg.security_level_bits(), 128);
        assert!(alg.is_timing_attack_resistant());
        assert!(alg.is_cache_timing_resistant());
        assert!(alg.is_post_quantum_secure());
        assert_eq!(alg.algorithm_family(), AlgorithmFamily::StreamCipher);
        assert_eq!(alg.to_string(), "ChaCha20-Poly1305");
    }
    
    #[test]
    fn test_algorithm_security_comparison() {
        let chacha = Algorithm::ChaCha20Poly1305;
        let aes = Algorithm::Aes256Gcm;
        
        // ChaCha20-Poly1305 should be more resistant to side-channel attacks
        assert!(chacha.is_timing_attack_resistant());
        assert!(chacha.is_cache_timing_resistant());
        
        // AES-GCM has potential vulnerabilities in software implementations
        assert!(!aes.is_timing_attack_resistant());
        assert!(!aes.is_cache_timing_resistant());
        
        // Both should be post-quantum secure (symmetric crypto)
        assert!(chacha.is_post_quantum_secure());
        assert!(aes.is_post_quantum_secure());
    }
    
    #[test]
    fn test_timing_resistance_selection() {
        // Test timing-resistant algorithms
        let resistant_algs = Algorithm::timing_resistant();
        assert!(resistant_algs.contains(&Algorithm::ChaCha20Poly1305));
        assert!(!resistant_algs.contains(&Algorithm::Aes256Gcm));
        
        // Most secure algorithm should be ChaCha20-Poly1305
        assert_eq!(Algorithm::most_secure(), Algorithm::ChaCha20Poly1305);
    }
    
    #[test]
    fn test_algorithm_security_properties() {
        let chacha = Algorithm::ChaCha20Poly1305;
        let aes = Algorithm::Aes256Gcm;
        
        // ChaCha20-Poly1305 should be timing attack resistant
        assert!(chacha.is_timing_attack_resistant());
        assert!(chacha.is_cache_timing_resistant());
        
        // AES-GCM has potential timing vulnerabilities
        assert!(!aes.is_timing_attack_resistant());
        assert!(!aes.is_cache_timing_resistant());
        
        // Both should be authenticated
        assert!(chacha.is_authenticated());
        assert!(aes.is_authenticated());
    }
}