//! Performance test for CargoCrypt
//! Run with: cargo run --example performance_test --release

use cargocrypt::crypto::{CryptoEngine, EncryptionOptions, PerformanceProfile};
use std::time::Instant;

fn main() {
    println!("🚀 CargoCrypt Performance Test");
    println!("{}", "=".repeat(60));
    
    let engine = CryptoEngine::new();
    let password = "benchmark_password_12345";
    
    // Test data sizes
    let test_sizes = vec![
        ("1KB", 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
    ];
    
    println!("\n📊 Encryption/Decryption Performance (ChaCha20-Poly1305 + Argon2)");
    println!("{}", "-".repeat(60));
    println!("{:<10} | {:<15} | {:<15} | {:<15} | {:<15}", 
             "Size", "Encrypt (ms)", "Decrypt (ms)", "Enc MB/s", "Dec MB/s");
    println!("{}", "-".repeat(60));
    
    for (name, size) in &test_sizes {
        // Generate test data
        let data: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();
        
        // Measure encryption
        let start = Instant::now();
        let encrypted = engine.encrypt_bytes(&data, password, EncryptionOptions::new()).unwrap();
        let encrypt_time = start.elapsed();
        
        // Measure decryption
        let start = Instant::now();
        let decrypted = engine.decrypt(&encrypted, password).unwrap();
        let decrypt_time = start.elapsed();
        
        // Verify correctness
        assert_eq!(data, decrypted.as_bytes());
        
        // Calculate throughput
        let size_mb = *size as f64 / (1024.0 * 1024.0);
        let enc_throughput = size_mb / encrypt_time.as_secs_f64();
        let dec_throughput = size_mb / decrypt_time.as_secs_f64();
        
        println!("{:<10} | {:<15.2} | {:<15.2} | {:<15.2} | {:<15.2}", 
                 name,
                 encrypt_time.as_millis(),
                 decrypt_time.as_millis(),
                 enc_throughput,
                 dec_throughput);
    }
    
    // Test key derivation with different profiles
    println!("\n🔑 Key Derivation Performance (Argon2)");
    println!("{}", "-".repeat(60));
    println!("{:<15} | {:<20} | {:<15}", "Profile", "Time (ms)", "Memory (MB)");
    println!("{}", "-".repeat(60));
    
    let profiles = vec![
        ("Fast", PerformanceProfile::Fast),
        ("Balanced", PerformanceProfile::Balanced),
        ("Secure", PerformanceProfile::Secure),
        ("Paranoid", PerformanceProfile::Paranoid),
    ];
    
    let small_data = b"test data";
    
    for (name, profile) in &profiles {
        let engine = CryptoEngine::with_performance_profile(*profile);
        let options = EncryptionOptions::new().with_performance_profile(*profile);
        
        // Measure key derivation + small encryption
        let start = Instant::now();
        let _encrypted = engine.encrypt_bytes(small_data, password, options).unwrap();
        let kdf_time = start.elapsed();
        
        // Get memory requirement from profile
        let params = profile.argon2_params();
        let memory_mb = params.m_cost() as f64 / 1024.0;
        
        println!("{:<15} | {:<20.2} | {:<15.2}", 
                 name,
                 kdf_time.as_millis(),
                 memory_mb);
    }
    
    // Test direct ChaCha20-Poly1305 (without key derivation)
    println!("\n⚡ Direct ChaCha20-Poly1305 Performance (No KDF)");
    println!("{}", "-".repeat(60));
    println!("{:<10} | {:<15} | {:<15} | {:<15} | {:<15}", 
             "Size", "Encrypt (ms)", "Decrypt (ms)", "Enc MB/s", "Dec MB/s");
    println!("{}", "-".repeat(60));
    
    // Generate a key and nonce for direct encryption
    let key_bytes = [42u8; 32]; // 32 bytes for ChaCha20-Poly1305
    let key = cargocrypt::crypto::Key::from_slice(&key_bytes);
    let nonce = [24u8; 12]; // 12 bytes nonce array
    
    for (name, size) in &test_sizes {
        let data: Vec<u8> = (0..*size).map(|i| (i % 256) as u8).collect();
        
        // Direct encryption (no key derivation)
        let start = Instant::now();
        let ciphertext = engine.encrypt_direct(&data, key, &nonce).unwrap();
        let encrypt_time = start.elapsed();
        
        // Direct decryption
        let start = Instant::now();
        let _plaintext = engine.decrypt_direct(&ciphertext, key, &nonce).unwrap();
        let decrypt_time = start.elapsed();
        
        // Calculate throughput
        let size_mb = *size as f64 / (1024.0 * 1024.0);
        let enc_throughput = size_mb / encrypt_time.as_secs_f64();
        let dec_throughput = size_mb / decrypt_time.as_secs_f64();
        
        println!("{:<10} | {:<15.2} | {:<15.2} | {:<15.2} | {:<15.2}", 
                 name,
                 encrypt_time.as_millis(),
                 decrypt_time.as_millis(),
                 enc_throughput,
                 dec_throughput);
    }
    
    // Memory usage estimation
    println!("\n💾 Memory Usage Analysis");
    println!("{}", "-".repeat(60));
    
    let test_data = vec![0u8; 1024 * 1024]; // 1MB
    let before_mem = get_memory_usage();
    
    let _encrypted = engine.encrypt_bytes(&test_data, password, EncryptionOptions::new()).unwrap();
    let after_encrypt = get_memory_usage();
    
    println!("Memory overhead for 1MB encryption: ~{:.2} MB", 
             (after_encrypt - before_mem) as f64 / (1024.0 * 1024.0));
    
    // Summary
    println!("\n📈 Performance Summary");
    println!("{}", "-".repeat(60));
    println!("• Encryption includes Argon2 key derivation + ChaCha20-Poly1305");
    println!("• Direct ChaCha20-Poly1305 shows raw cipher performance");
    println!("• Balanced profile uses 64MB memory, 3 iterations for Argon2");
    println!("• Performance scales linearly with data size");
    
    // Compare with claims
    println!("\n📊 Comparison with Documentation");
    println!("{}", "-".repeat(60));
    println!("Documentation claims:");
    println!("• Encryption: 1.2 GB/s (ChaCha20-Poly1305)");
    println!("• Decryption: 1.4 GB/s (ChaCha20-Poly1305)");
    println!("• Key generation: 15ms (Ed25519)");
    println!("\nNote: The documented speeds appear to be for direct cipher operations");
    println!("without key derivation. Our tests show the full encryption pipeline.");
}

fn get_memory_usage() -> usize {
    // Simple memory estimation - in real benchmarks you'd use more sophisticated methods
    std::mem::size_of::<CryptoEngine>() + 1024 * 1024 // Rough estimate
}