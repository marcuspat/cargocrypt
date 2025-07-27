//! Security hardening utilities for cryptographic operations

use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// Timing defense mechanism to prevent timing attacks
pub struct TimingDefense {
    start_time: Instant,
    min_duration: Duration,
}

impl TimingDefense {
    pub fn new(start_time: Instant, min_duration: Duration) -> Self {
        Self {
            start_time,
            min_duration,
        }
    }
}

impl Drop for TimingDefense {
    fn drop(&mut self) {
        let elapsed = self.start_time.elapsed();
        if elapsed < self.min_duration {
            let sleep_duration = self.min_duration - elapsed;
            std::thread::sleep(sleep_duration);
        }
    }
}

/// Secure memory buffer that zeroizes on drop
#[derive(Clone)]
pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Zeroize for SecureBuffer {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Secure random number generation with validation
pub struct SecureRandom;

impl SecureRandom {
    /// Generate cryptographically secure random bytes with validation
    pub fn generate(size: usize) -> Result<Vec<u8>, String> {
        if size == 0 {
            return Err("Cannot generate zero bytes".to_string());
        }
        
        if size > 1024 * 1024 {
            return Err("Requested size too large for security".to_string());
        }
        
        use rand::RngCore;
        let mut rng = rand::rngs::OsRng;
        let mut bytes = vec![0u8; size];
        
        // Validate that we got random data (basic entropy check)
        rng.fill_bytes(&mut bytes);
        
        // Simple entropy validation - ensure not all zeros or all same value
        let first_byte = bytes[0];
        let all_same = bytes.iter().all(|&b| b == first_byte);
        if all_same && size > 1 {
            return Err("Generated data appears non-random".to_string());
        }
        
        Ok(bytes)
    }
    
    /// Generate a secure salt with validation
    pub fn generate_salt() -> Result<[u8; 32], String> {
        let bytes = Self::generate(32)?;
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes);
        Ok(salt)
    }
    
    /// Generate a secure nonce with validation
    pub fn generate_nonce() -> Result<[u8; 12], String> {
        let bytes = Self::generate(12)?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&bytes);
        Ok(nonce)
    }
}

/// Key derivation parameter validator and optimizer
pub struct KeyDerivationValidator;

impl KeyDerivationValidator {
    /// Validate and optimize Argon2 parameters for security
    pub fn validate_params(memory_cost: u32, time_cost: u32, parallelism: u32) -> Result<(), String> {
        // Security requirements based on OWASP recommendations
        if memory_cost < 47104 {  // ~46MB minimum
            return Err("Memory cost too low - minimum 47104 KiB (46MB) required for security".to_string());
        }
        
        if memory_cost > 2097152 {  // 2GB maximum for practical use
            return Err("Memory cost too high - maximum 2097152 KiB (2GB) for performance".to_string());
        }
        
        if time_cost < 2 {
            return Err("Time cost too low - minimum 2 iterations required".to_string());
        }
        
        if time_cost > 10 {
            return Err("Time cost too high - maximum 10 iterations for performance".to_string());
        }
        
        if parallelism < 1 {
            return Err("Parallelism must be at least 1".to_string());
        }
        
        if parallelism > 16 {
            return Err("Parallelism too high - maximum 16 threads for security".to_string());
        }
        
        Ok(())
    }
    
    /// Get optimized parameters based on available system resources
    pub fn optimize_for_system() -> (u32, u32, u32) {
        // Conservative secure defaults
        let memory_cost = 65536;  // 64MB
        let time_cost = 3;        // 3 iterations
        let parallelism = 4;      // 4 threads
        
        (memory_cost, time_cost, parallelism)
    }
}

/// Constant-time string comparison to prevent timing attacks
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    
    if a.len() != b.len() {
        return false;
    }
    
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_random_generation() {
        let data1 = SecureRandom::generate(32).unwrap();
        let data2 = SecureRandom::generate(32).unwrap();
        
        assert_eq!(data1.len(), 32);
        assert_eq!(data2.len(), 32);
        assert_ne!(data1, data2); // Should be different
    }
    
    #[test]
    fn test_key_derivation_validation() {
        // Valid parameters
        assert!(KeyDerivationValidator::validate_params(65536, 3, 4).is_ok());
        
        // Invalid parameters
        assert!(KeyDerivationValidator::validate_params(1024, 3, 4).is_err()); // Too low memory
        assert!(KeyDerivationValidator::validate_params(65536, 1, 4).is_err()); // Too low time
        assert!(KeyDerivationValidator::validate_params(65536, 3, 0).is_err()); // Invalid parallelism
    }
    
    #[test]
    fn test_constant_time_compare() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";
        
        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, b"hi")); // Different lengths
    }
    
    #[test]
    fn test_secure_buffer() {
        let mut buffer = SecureBuffer::new(vec![1, 2, 3, 4]);
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);
        
        buffer.zeroize();
        assert_eq!(buffer.as_slice(), &[0, 0, 0, 0]);
    }
}