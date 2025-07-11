//! Comprehensive cryptographic benchmarks for CargoCrypt
//! 
//! This benchmark suite tests the performance of ChaCha20-Poly1305 encryption
//! and Argon2 key derivation across different performance profiles and data sizes.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use cargocrypt::crypto::{
    CryptoEngine, PerformanceProfile, EncryptionOptions, PlaintextSecret,
    SecretMetadata, SecretType, DerivedKey, defaults,
};

/// Generate test data of specified size
fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Benchmark key derivation with different performance profiles
fn bench_key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");
    
    let password = "benchmark_password_with_sufficient_entropy_12345";
    let salt = [42u8; defaults::SALT_LENGTH];
    
    let profiles = [
        ("fast", PerformanceProfile::Fast),
        ("balanced", PerformanceProfile::Balanced),
        ("secure", PerformanceProfile::Secure),
        ("paranoid", PerformanceProfile::Paranoid),
    ];

    for (name, profile) in profiles {
        group.bench_with_input(
            BenchmarkId::new("argon2", name),
            &profile,
            |b, &profile| {
                b.iter(|| {
                    let engine = CryptoEngine::with_performance_profile(profile);
                    // Use internal method through public API
                    let options = EncryptionOptions::new()
                        .with_performance_profile(profile)
                        .with_salt(salt);
                    
                    let plaintext = PlaintextSecret::from_string("test".to_string());
                    black_box(engine.encrypt(plaintext, password, options).unwrap());
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark encryption/decryption with different data sizes
fn bench_encryption_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption_by_size");
    
    let engine = CryptoEngine::new();
    let password = "benchmark_password";
    
    let sizes = [
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
        ("10MB", 10 * 1024 * 1024),
    ];

    for (name, size) in sizes {
        let data = generate_test_data(size);
        group.throughput(Throughput::Bytes(size as u64));
        
        // Benchmark encryption
        group.bench_with_input(
            BenchmarkId::new("encrypt", name),
            &data,
            |b, data| {
                b.iter(|| {
                    let options = EncryptionOptions::new();
                    black_box(engine.encrypt_bytes(data, password, options).unwrap());
                })
            },
        );
        
        // Pre-encrypt for decryption benchmark
        let encrypted = engine.encrypt_bytes(&data, password, EncryptionOptions::new()).unwrap();
        
        // Benchmark decryption
        group.bench_with_input(
            BenchmarkId::new("decrypt", name),
            &encrypted,
            |b, encrypted| {
                b.iter(|| {
                    black_box(engine.decrypt(encrypted, password).unwrap());
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark direct ChaCha20-Poly1305 operations (without key derivation)
fn bench_direct_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("direct_crypto");
    
    let engine = CryptoEngine::new();
    let key = CryptoEngine::generate_key().unwrap();
    let nonce = CryptoEngine::generate_nonce().unwrap();
    
    let sizes = [
        ("1KB", 1024),
        ("10KB", 10 * 1024),
        ("100KB", 100 * 1024),
        ("1MB", 1024 * 1024),
    ];

    for (name, size) in sizes {
        let data = generate_test_data(size);
        group.throughput(Throughput::Bytes(size as u64));
        
        // Benchmark direct encryption
        group.bench_with_input(
            BenchmarkId::new("direct_encrypt", name),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(engine.encrypt_direct(data, &key, &nonce).unwrap());
                })
            },
        );
        
        // Pre-encrypt for decryption benchmark
        let ciphertext = engine.encrypt_direct(&data, &key, &nonce).unwrap();
        
        // Benchmark direct decryption
        group.bench_with_input(
            BenchmarkId::new("direct_decrypt", name),
            &ciphertext,
            |b, ciphertext| {
                b.iter(|| {
                    black_box(engine.decrypt_direct(ciphertext, &key, &nonce).unwrap());
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark batch operations
fn bench_batch_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_operations");
    
    let engine = CryptoEngine::new();
    let password = "batch_password";
    
    let batch_sizes = [1, 10, 50, 100, 500];
    
    for &count in &batch_sizes {
        let secrets: Vec<(String, String)> = (0..count)
            .map(|i| (format!("secret_{}", i), format!("secret_data_{}_with_some_content", i)))
            .collect();
        
        group.bench_with_input(
            BenchmarkId::new("encrypt_batch", count),
            &secrets,
            |b, secrets| {
                b.iter(|| {
                    let options = EncryptionOptions::new();
                    black_box(engine.encrypt_batch(secrets.clone(), password, options));
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark password operations
fn bench_password_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("password_operations");
    
    let engine = CryptoEngine::new();
    let plaintext = "Test secret data for password operations";
    let password = "original_password";
    let new_password = "new_password";
    
    // Pre-encrypt secret for benchmarks
    let encrypted = engine.encrypt_string(plaintext, password, EncryptionOptions::new()).unwrap();
    
    // Benchmark password verification
    group.bench_function("verify_correct_password", |b| {
        b.iter(|| {
            black_box(engine.verify_password(&encrypted, password));
        })
    });
    
    group.bench_function("verify_wrong_password", |b| {
        b.iter(|| {
            black_box(engine.verify_password(&encrypted, "wrong_password"));
        })
    });
    
    // Benchmark password change
    group.bench_function("change_password", |b| {
        b.iter(|| {
            black_box(engine.change_password(&encrypted, password, new_password).unwrap());
        })
    });
    
    group.finish();
}

/// Benchmark serialization operations
fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");
    
    let engine = CryptoEngine::new();
    let plaintext = "Test data for serialization benchmarks";
    let password = "serialization_password";
    
    let metadata = SecretMetadata::new()
        .with_description("Benchmark secret")
        .with_type(SecretType::ApiKey);
    
    let options = EncryptionOptions::new().with_metadata(metadata);
    let encrypted = engine.encrypt_string(plaintext, password, options).unwrap();
    
    // Benchmark JSON serialization
    group.bench_function("to_json", |b| {
        b.iter(|| {
            black_box(encrypted.to_json().unwrap());
        })
    });
    
    let json = encrypted.to_json().unwrap();
    group.bench_function("from_json", |b| {
        b.iter(|| {
            black_box(cargocrypt::crypto::EncryptedSecret::from_json(&json).unwrap());
        })
    });
    
    // Benchmark binary serialization
    group.bench_function("to_bytes", |b| {
        b.iter(|| {
            black_box(encrypted.to_bytes().unwrap());
        })
    });
    
    let bytes = encrypted.to_bytes().unwrap();
    group.bench_function("from_bytes", |b| {
        b.iter(|| {
            black_box(cargocrypt::crypto::EncryptedSecret::from_bytes(&bytes).unwrap());
        })
    });
    
    group.finish();
}

/// Benchmark memory-intensive operations to test zeroization overhead
fn bench_memory_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_operations");
    
    let engine = CryptoEngine::new();
    let password = "memory_test_password";
    
    // Test with large data to see zeroization impact
    let large_data = generate_test_data(1024 * 1024); // 1MB
    
    group.bench_function("large_data_encrypt", |b| {
        b.iter(|| {
            let options = EncryptionOptions::new();
            black_box(engine.encrypt_bytes(&large_data, password, options).unwrap());
        })
    });
    
    let encrypted_large = engine.encrypt_bytes(&large_data, password, EncryptionOptions::new()).unwrap();
    
    group.bench_function("large_data_decrypt", |b| {
        b.iter(|| {
            black_box(engine.decrypt(&encrypted_large, password).unwrap());
        })
    });
    
    // Test many small operations (to test allocation patterns)
    group.bench_function("many_small_encryptions", |b| {
        b.iter(|| {
            for i in 0..100 {
                let data = format!("small_secret_{}", i);
                let options = EncryptionOptions::new();
                black_box(engine.encrypt_string(&data, password, options).unwrap());
            }
        })
    });
    
    group.finish();
}

/// Benchmark concurrent operations
fn bench_concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_operations");
    
    let engine = CryptoEngine::new();
    let password = "concurrent_password";
    let data = "Concurrent test data";
    
    // Pre-encrypt for concurrent decryption test
    let encrypted = engine.encrypt_string(data, password, EncryptionOptions::new()).unwrap();
    
    group.bench_function("concurrent_encryptions", |b| {
        b.iter(|| {
            use std::thread;
            let handles: Vec<_> = (0..4).map(|_| {
                let engine = engine.clone();
                let data = data.to_string();
                let password = password.to_string();
                thread::spawn(move || {
                    let options = EncryptionOptions::new();
                    engine.encrypt_string(&data, &password, options).unwrap()
                })
            }).collect();
            
            for handle in handles {
                black_box(handle.join().unwrap());
            }
        })
    });
    
    group.bench_function("concurrent_decryptions", |b| {
        b.iter(|| {
            use std::thread;
            let handles: Vec<_> = (0..4).map(|_| {
                let engine = engine.clone();
                let encrypted = encrypted.clone();
                let password = password.to_string();
                thread::spawn(move || {
                    engine.decrypt_to_string(&encrypted, &password).unwrap()
                })
            }).collect();
            
            for handle in handles {
                black_box(handle.join().unwrap());
            }
        })
    });
    
    group.finish();
}

/// Performance regression tests
fn bench_performance_targets(c: &mut Criterion) {
    let mut group = c.benchmark_group("performance_targets");
    group.significance_level(0.1).sample_size(100);
    
    let engine = CryptoEngine::new();
    let password = "target_password";
    let test_data = "Performance target test data";
    
    // Target: <1ms for encryption/decryption of small data
    group.bench_function("target_encrypt_small", |b| {
        b.iter(|| {
            let options = EncryptionOptions::new();
            black_box(engine.encrypt_string(test_data, password, options).unwrap());
        })
    });
    
    let encrypted = engine.encrypt_string(test_data, password, EncryptionOptions::new()).unwrap();
    
    group.bench_function("target_decrypt_small", |b| {
        b.iter(|| {
            black_box(engine.decrypt_to_string(&encrypted, password).unwrap());
        })
    });
    
    // Target: High throughput for large data
    let large_data = generate_test_data(10 * 1024 * 1024); // 10MB
    group.throughput(Throughput::Bytes(large_data.len() as u64));
    
    group.bench_function("target_encrypt_large", |b| {
        b.iter(|| {
            let options = EncryptionOptions::new();
            black_box(engine.encrypt_bytes(&large_data, password, options).unwrap());
        })
    });
    
    let encrypted_large = engine.encrypt_bytes(&large_data, password, EncryptionOptions::new()).unwrap();
    
    group.bench_function("target_decrypt_large", |b| {
        b.iter(|| {
            black_box(engine.decrypt(&encrypted_large, password).unwrap());
        })
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_key_derivation,
    bench_encryption_sizes,
    bench_direct_crypto,
    bench_batch_operations,
    bench_password_operations,
    bench_serialization,
    bench_memory_operations,
    bench_concurrent_operations,
    bench_performance_targets,
);

criterion_main!(benches);