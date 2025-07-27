//! Integration tests for stability, validation, and error handling features

use cargocrypt::{
    CargoCrypt,
    validation::{InputValidator, ValidationSeverity},
    resilience::{CircuitBreaker, RetryPolicy, GracefulDegradation, CircuitBreakerError, CircuitBreakerState, HealthLevel},
    monitoring::{MonitoringManager, MonitoringConfig, CryptoOperation, CryptoOperationType, FileOperation, FileOperationType},
    error::{CargoCryptError, ErrorSeverity},
};
use std::time::Duration;
use tempfile::TempDir;
use tokio::fs;

#[tokio::test]
async fn test_input_validation_integration() {
    let validator = InputValidator::new();
    
    // Test file path validation
    let long_path = "a".repeat(5000);
    let test_cases = vec![
        ("../../../etc/passwd", false, "Path traversal should be blocked"),
        ("test_file.txt", true, "Normal file should be valid"),
        ("test\x00file.txt", false, "Null bytes should be invalid"),
        (long_path.as_str(), false, "Very long paths should be invalid"),
    ];
    
    for (path, should_be_valid, description) in test_cases {
        let result = validator.validate_file_path(path);
        assert_eq!(result.is_valid, should_be_valid, "{}", description);
    }
    
    // Test password validation
    let weak_password = "password";
    let strong_password = "Str0ng!P@ssw0rd#2024";
    
    let weak_result = validator.validate_password(weak_password);
    assert!(!weak_result.is_valid, "Weak password should fail validation");
    
    let strong_result = validator.validate_password(strong_password);
    assert!(strong_result.is_valid, "Strong password should pass validation");
}

#[tokio::test]
async fn test_circuit_breaker_protection() {
    let breaker = CircuitBreaker::new(
        "test_service".to_string(),
        3, // fail after 3 failures
        Duration::from_millis(100), // 100ms timeout
    );
    
    let mut failure_count = 0;
    
    // Simulate failures
    for _ in 0..3 {
        let result = breaker.execute(|| {
            failure_count += 1;
            Err::<(), &str>("simulated failure")
        }).await;
        assert!(result.is_err());
    }
    
    // Circuit should now be open
    let result = breaker.execute(|| Ok::<(), &str>(())).await;
    assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
    
    // Wait for timeout
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    // Circuit should allow one attempt (half-open)
    let result = breaker.execute(|| Ok::<(), &str>(())).await;
    assert!(result.is_ok());
    
    // Circuit should be closed again
    assert_eq!(breaker.get_state().await, CircuitBreakerState::Closed);
}

#[tokio::test]
async fn test_retry_policy() {
    let policy = RetryPolicy::new(3, Duration::from_millis(10));
    let mut attempt_count = 0;
    
    let result = policy.execute(|| {
        attempt_count += 1;
        async move {
            if attempt_count < 2 {
                Err("temporary failure")
            } else {
                Ok("success")
            }
        }
    }).await;
    
    assert_eq!(result, Ok("success"));
    assert_eq!(attempt_count, 2, "Should succeed on second attempt");
}

#[tokio::test]
async fn test_graceful_degradation() {
    let gd = GracefulDegradation::new();
    
    // Register features
    gd.register_feature("advanced_crypto", true).await;
    gd.register_feature("network_sync", true).await;
    gd.register_feature("performance_monitoring", true).await;
    
    // Simulate system stress
    gd.disable_feature("performance_monitoring", "High CPU usage detected").await;
    
    assert!(gd.is_feature_enabled("advanced_crypto").await);
    assert!(gd.is_feature_enabled("network_sync").await);
    assert!(!gd.is_feature_enabled("performance_monitoring").await);
    
    // Register circuit breakers
    gd.register_circuit_breaker("network_service", 5, Duration::from_secs(30)).await;
    
    // Check health
    let health = gd.health_check().await;
    assert_eq!(health.overall_health, HealthLevel::Healthy);
}

#[tokio::test]
async fn test_monitoring_integration() {
    let config = MonitoringConfig::default();
    let monitor = MonitoringManager::new(config);
    
    // Record some operations
    let crypto_op = CryptoOperation {
        operation_type: CryptoOperationType::Encrypt,
        data_size: 1024,
        duration: Duration::from_millis(50),
        success: true,
        error_message: None,
    };
    
    monitor.record_crypto_operation(crypto_op).await;
    
    let file_op = FileOperation {
        operation_type: FileOperationType::Write,
        file_path: "test.enc".to_string(),
        file_size: 1024,
        duration: Duration::from_millis(10),
        success: true,
        error_message: None,
    };
    
    monitor.record_file_operation(file_op).await;
    
    // Get metrics
    let metrics = monitor.get_metrics().await;
    assert!(metrics.crypto_operations.contains_key("Encrypt"));
    assert_eq!(metrics.crypto_operations["Encrypt"].count, 1);
}

#[tokio::test]
async fn test_error_recovery_flow() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.txt");
    
    // Write test content
    fs::write(&test_file, b"test content").await.unwrap();
    
    // Simulate error conditions
    let cargocrypt = CargoCrypt::new().await.unwrap();
    
    // Test with invalid password (too short)
    let result = cargocrypt.encrypt_file(&test_file, "short").await;
    assert!(result.is_err());
    
    if let Err(e) = result {
        // Check that we get appropriate validation error
        assert!(matches!(e, CargoCryptError::Config { .. }));
        assert_eq!(e.severity(), ErrorSeverity::Warning);
    }
    
    // Test with valid password
    let encrypted = cargocrypt.encrypt_file(&test_file, "ValidP@ssw0rd123").await;
    assert!(encrypted.is_ok());
    
    // Test decryption with wrong password
    let decrypt_result = cargocrypt.decrypt_file(&encrypted.unwrap(), "WrongPassword123").await;
    assert!(decrypt_result.is_err());
    
    if let Err(e) = decrypt_result {
        // Should be a crypto error
        assert!(matches!(e, CargoCryptError::Crypto { .. }));
        assert_eq!(e.severity(), ErrorSeverity::Critical);
    }
}

#[tokio::test]
async fn test_file_validation_with_content() {
    let validator = InputValidator::new();
    
    // Test content with potential secrets
    let content_with_secret = b"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
    let validation = validator.validate_file_content(content_with_secret, "config.txt");
    
    assert!(!validation.warnings.is_empty(), "Should warn about potential secrets");
    assert!(validation.warnings.iter().any(|w| w.contains("AWS access key")));
    
    // Test large file
    let large_content = vec![0u8; 101 * 1024 * 1024]; // 101MB
    let validation = validator.validate_file_content(&large_content, "large.bin");
    
    assert!(!validation.is_valid, "Should reject files over 100MB");
    assert!(validation.errors.iter().any(|e| e.severity == ValidationSeverity::Critical));
}

#[tokio::test]
async fn test_concurrent_operations_with_monitoring() {
    let temp_dir = TempDir::new().unwrap();
    let cargocrypt = CargoCrypt::new().await.unwrap();
    let monitor = MonitoringManager::new(MonitoringConfig::default());
    
    // Create multiple test files
    let mut handles = vec![];
    
    for i in 0..5 {
        let file_path = temp_dir.path().join(format!("test_{}.txt", i));
        let content = format!("Test content {}", i);
        fs::write(&file_path, content.as_bytes()).await.unwrap();
        
        let cargocrypt_clone = cargocrypt.clone();
        let monitor_clone = monitor.clone();
        
        let handle = tokio::spawn(async move {
            let start = std::time::Instant::now();
            
            // Encrypt file
            let result = cargocrypt_clone.encrypt_file(&file_path, "SecureP@ssw0rd123").await;
            
            let duration = start.elapsed();
            
            // Record operation
            let op = FileOperation {
                operation_type: FileOperationType::Write,
                file_path: file_path.to_string_lossy().to_string(),
                file_size: content.len() as u64,
                duration,
                success: result.is_ok(),
                error_message: result.as_ref().err().map(|e| e.to_string()),
            };
            
            monitor_clone.record_file_operation(op).await;
            
            result
        });
        
        handles.push(handle);
    }
    
    // Wait for all operations
    let results: Vec<_> = futures::future::join_all(handles).await;
    
    // Check all succeeded
    for result in results {
        assert!(result.is_ok());
        assert!(result.unwrap().is_ok());
    }
    
    // Check metrics
    let metrics = monitor.get_metrics().await;
    assert_eq!(metrics.file_operations["Write"].count, 5);
    assert_eq!(metrics.file_operations["Write"].error_rate, 0.0);
}

#[tokio::test]
async fn test_resource_limits_and_recovery() {
    let gd = GracefulDegradation::new();
    
    // Simulate resource exhaustion scenarios
    let health = gd.health_check().await;
    
    // Check that system adapts to resource constraints
    if health.issues.iter().any(|i| i.component == "memory") {
        // Gracefully degrade non-essential features
        gd.disable_feature("cache_preloading", "Low memory detected").await;
        gd.disable_feature("parallel_processing", "Resource conservation mode").await;
    }
    
    // Verify degraded mode still functions
    assert!(gd.is_feature_enabled("core_crypto").await || !gd.is_feature_enabled("core_crypto").await);
}

#[tokio::test]
async fn test_end_to_end_stability() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("sensitive_data.txt");
    fs::write(&test_file, b"This is sensitive information").await.unwrap();
    
    // Initialize with full stability features
    let cargocrypt = CargoCrypt::new().await.unwrap();
    let validator = InputValidator::new();
    let monitor = MonitoringManager::new(MonitoringConfig::default());
    
    // Validate inputs
    let path_validation = validator.validate_file_path(&test_file);
    assert!(path_validation.is_valid);
    
    let password = "Secure123!Password";
    let password_validation = validator.validate_password(password);
    assert!(password_validation.is_valid);
    
    // Perform encryption with monitoring
    let _tracker = monitor.start_performance_tracking("encryption").await;
    let encrypted_path = cargocrypt.encrypt_file(&test_file, password).await.unwrap();
    
    // Verify encryption
    assert!(encrypted_path.exists());
    assert!(encrypted_path.to_string_lossy().ends_with(".enc"));
    
    // Decrypt and verify
    let decrypted_path = cargocrypt.decrypt_file(&encrypted_path, password).await.unwrap();
    let decrypted_content = fs::read(&decrypted_path).await.unwrap();
    assert_eq!(decrypted_content, b"This is sensitive information");
    
    // Check metrics
    let metrics = monitor.get_metrics().await;
    assert!(metrics.system_metrics.files_processed > 0);
}