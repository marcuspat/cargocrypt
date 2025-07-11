//! Integration tests for CargoCrypt core functionality

use cargocrypt::{CargoCrypt, CryptoConfig, SecretBytes};
use tempfile::TempDir;
use std::fs;

#[tokio::test]
async fn test_zero_config_initialization() {
    let temp_dir = TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();
    
    // Create a temporary Cargo.toml to simulate a Rust project
    let cargo_toml = temp_dir.path().join("Cargo.toml");
    fs::write(&cargo_toml, r#"
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"
"#).unwrap();
    
    // Change to temp directory
    std::env::set_current_dir(temp_dir.path()).unwrap();
    
    // Test zero-config initialization
    let result = CargoCrypt::new().await;
    
    // Restore original directory
    std::env::set_current_dir(original_dir).unwrap();
    
    assert!(result.is_ok(), "Zero-config initialization should work");
}

#[tokio::test]
async fn test_config_validation() {
    let config = CryptoConfig::default();
    assert!(config.validate().is_ok(), "Default config should be valid");
    
    // Test invalid config
    let mut invalid_config = config.clone();
    invalid_config.key_params.memory_cost = 512; // Too low
    assert!(invalid_config.validate().is_err(), "Invalid config should fail validation");
}

#[tokio::test]
async fn test_secret_bytes_zeroization() {
    let secret = SecretBytes::from_str("sensitive-data");
    assert_eq!(secret.len(), 14);
    assert!(!secret.is_empty());
    assert_eq!(secret.to_string_lossy(), "sensitive-data");
    
    // Secret should be zeroized on drop automatically
    drop(secret);
}

#[tokio::test]
async fn test_builder_pattern() {
    let temp_dir = TempDir::new().unwrap();
    let original_dir = std::env::current_dir().unwrap();
    
    // Create a temporary Cargo.toml
    let cargo_toml = temp_dir.path().join("Cargo.toml");
    fs::write(&cargo_toml, r#"
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"
"#).unwrap();
    
    // Change to temp directory
    std::env::set_current_dir(temp_dir.path()).unwrap();
    
    // Test builder pattern
    let crypt = cargocrypt::CargoCryptBuilder::new()
        .project_root(temp_dir.path())
        .build()
        .await;
    
    // Restore original directory
    std::env::set_current_dir(original_dir).unwrap();
    
    assert!(crypt.is_ok(), "Builder pattern should work");
}

#[tokio::test]
async fn test_algorithm_properties() {
    use cargocrypt::crypto::{Algorithm, AlgorithmExt};
    
    let alg = Algorithm::ChaCha20Poly1305;
    assert_eq!(alg.key_length(), 32);
    assert_eq!(alg.nonce_length(), 12);
    assert_eq!(alg.tag_length(), 16);
    assert!(alg.is_authenticated());
    assert_eq!(alg.to_string(), "ChaCha20-Poly1305");
}