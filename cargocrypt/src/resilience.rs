//! Resilience and graceful degradation module
//!
//! Provides robust error recovery, graceful degradation, and system stability
//! features to ensure CargoCrypt continues to function even when some
//! components or dependencies are unavailable.

use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, warn, info, debug};

/// Circuit breaker pattern for handling repeated failures
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    name: String,
    failure_count: Arc<RwLock<u32>>,
    last_failure: Arc<RwLock<Option<Instant>>>,
    failure_threshold: u32,
    timeout: Duration,
    state: Arc<RwLock<CircuitBreakerState>>,
}

/// States of a circuit breaker
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CircuitBreakerState {
    Closed,    // Normal operation
    Open,      // Failing, blocking calls
    HalfOpen,  // Testing if service has recovered
}

impl CircuitBreaker {
    pub fn new(name: String, failure_threshold: u32, timeout: Duration) -> Self {
        Self {
            name,
            failure_count: Arc::new(RwLock::new(0)),
            last_failure: Arc::new(RwLock::new(None)),
            failure_threshold,
            timeout,
            state: Arc::new(RwLock::new(CircuitBreakerState::Closed)),
        }
    }

    /// Execute a function with circuit breaker protection
    pub async fn execute<F, T, E>(&self, operation: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Result<T, E>,
        E: std::fmt::Debug,
    {
        // Check current state
        let state = *self.state.read().await;
        
        match state {
            CircuitBreakerState::Open => {
                // Check if timeout has elapsed
                let last_failure = *self.last_failure.read().await;
                if let Some(last_fail_time) = last_failure {
                    if last_fail_time.elapsed() > self.timeout {
                        // Move to half-open state
                        *self.state.write().await = CircuitBreakerState::HalfOpen;
                        debug!("Circuit breaker {} moving to half-open state", self.name);
                        // Continue to execute operation below
                    } else {
                        return Err(CircuitBreakerError::CircuitOpen);
                    }
                } else {
                    return Err(CircuitBreakerError::CircuitOpen);
                }
            }
            CircuitBreakerState::Closed | CircuitBreakerState::HalfOpen => {
                // Continue to execute operation below
            }
        }

        // Execute the operation (for Closed, HalfOpen, or Open->HalfOpen states)
        match operation() {
            Ok(result) => {
                // Success - reset failure count and close circuit
                *self.failure_count.write().await = 0;
                *self.state.write().await = CircuitBreakerState::Closed;
                Ok(result)
            }
            Err(error) => {
                // Failure - increment count and potentially open circuit
                let mut count = self.failure_count.write().await;
                *count += 1;
                *self.last_failure.write().await = Some(Instant::now());

                if *count >= self.failure_threshold {
                    *self.state.write().await = CircuitBreakerState::Open;
                    warn!("Circuit breaker {} opened after {} failures", self.name, count);
                    Err(CircuitBreakerError::CircuitOpened)
                } else {
                    Err(CircuitBreakerError::OperationFailed(error))
                }
            }
        }
    }

    pub async fn get_state(&self) -> CircuitBreakerState {
        self.state.read().await.clone()
    }

    pub async fn reset(&self) {
        *self.failure_count.write().await = 0;
        *self.last_failure.write().await = None;
        *self.state.write().await = CircuitBreakerState::Closed;
        info!("Circuit breaker {} manually reset", self.name);
    }
}

/// Errors from circuit breaker operations
#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    CircuitOpen,
    CircuitOpened,
    OperationFailed(E),
}

/// Retry policy for operations that may fail transiently
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    max_attempts: u32,
    base_delay: Duration,
    max_delay: Duration,
    backoff_multiplier: f64,
}

impl RetryPolicy {
    pub fn new(max_attempts: u32, base_delay: Duration) -> Self {
        Self {
            max_attempts,
            base_delay,
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
        }
    }

    pub fn with_max_delay(mut self, max_delay: Duration) -> Self {
        self.max_delay = max_delay;
        self
    }

    pub fn with_backoff_multiplier(mut self, multiplier: f64) -> Self {
        self.backoff_multiplier = multiplier;
        self
    }

    /// Execute an operation with retry logic
    pub async fn execute<F, Fut, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Debug,
    {
        let mut attempt = 1;
        let mut delay = self.base_delay;

        loop {
            match operation().await {
                Ok(result) => {
                    if attempt > 1 {
                        info!("Operation succeeded on attempt {}/{}", attempt, self.max_attempts);
                    }
                    return Ok(result);
                }
                Err(error) => {
                    if attempt >= self.max_attempts {
                        error!("Operation failed after {} attempts: {:?}", attempt, error);
                        return Err(error);
                    }

                    warn!("Operation failed on attempt {}/{}, retrying in {:?}: {:?}", 
                          attempt, self.max_attempts, delay, error);
                    
                    tokio::time::sleep(delay).await;
                    
                    // Calculate next delay with exponential backoff
                    delay = std::cmp::min(
                        Duration::from_millis((delay.as_millis() as f64 * self.backoff_multiplier) as u64),
                        self.max_delay
                    );
                    
                    attempt += 1;
                }
            }
        }
    }
}

/// Graceful degradation manager
pub struct GracefulDegradation {
    feature_flags: Arc<RwLock<std::collections::HashMap<String, bool>>>,
    circuit_breakers: Arc<RwLock<std::collections::HashMap<String, CircuitBreaker>>>,
}

impl GracefulDegradation {
    pub fn new() -> Self {
        Self {
            feature_flags: Arc::new(RwLock::new(std::collections::HashMap::new())),
            circuit_breakers: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Register a feature that can be disabled
    pub async fn register_feature(&self, name: &str, enabled: bool) {
        self.feature_flags.write().await.insert(name.to_string(), enabled);
    }

    /// Check if a feature is enabled
    pub async fn is_feature_enabled(&self, name: &str) -> bool {
        self.feature_flags.read().await.get(name).copied().unwrap_or(false)
    }

    /// Disable a feature (graceful degradation)
    pub async fn disable_feature(&self, name: &str, reason: &str) {
        self.feature_flags.write().await.insert(name.to_string(), false);
        warn!("Feature '{}' disabled: {}", name, reason);
    }

    /// Enable a feature
    pub async fn enable_feature(&self, name: &str) {
        self.feature_flags.write().await.insert(name.to_string(), true);
        info!("Feature '{}' enabled", name);
    }

    /// Register a circuit breaker for a service
    pub async fn register_circuit_breaker(&self, name: &str, failure_threshold: u32, timeout: Duration) {
        let breaker = CircuitBreaker::new(name.to_string(), failure_threshold, timeout);
        self.circuit_breakers.write().await.insert(name.to_string(), breaker);
    }

    /// Get a circuit breaker by name
    pub async fn get_circuit_breaker(&self, name: &str) -> Option<CircuitBreaker> {
        self.circuit_breakers.read().await.get(name).cloned()
    }

    /// Check system health and disable problematic features
    pub async fn health_check(&self) -> HealthStatus {
        let mut status = HealthStatus::new();
        
        // Check all circuit breakers
        let breakers = self.circuit_breakers.read().await;
        for (name, breaker) in breakers.iter() {
            let state = breaker.get_state().await;
            match state {
                CircuitBreakerState::Open => {
                    status.add_issue(name, "Circuit breaker is open", HealthSeverity::Critical);
                    self.disable_feature(name, "Circuit breaker protection").await;
                }
                CircuitBreakerState::HalfOpen => {
                    status.add_issue(name, "Circuit breaker is half-open", HealthSeverity::Warning);
                }
                CircuitBreakerState::Closed => {
                    status.add_healthy_component(name);
                }
            }
        }

        // Check system resources
        status.check_system_resources().await;
        
        status
    }
}

/// System health status
#[derive(Debug)]
pub struct HealthStatus {
    pub overall_health: HealthLevel,
    pub components: std::collections::HashMap<String, ComponentHealth>,
    pub issues: Vec<HealthIssue>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthLevel {
    Healthy,
    Degraded,
    Critical,
}

#[derive(Debug)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthLevel,
    pub last_check: Instant,
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct HealthIssue {
    pub component: String,
    pub message: String,
    pub severity: HealthSeverity,
    pub timestamp: Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HealthSeverity {
    Info,
    Warning,
    Critical,
}

impl HealthStatus {
    pub fn new() -> Self {
        Self {
            overall_health: HealthLevel::Healthy,
            components: std::collections::HashMap::new(),
            issues: Vec::new(),
        }
    }

    pub fn add_healthy_component(&mut self, name: &str) {
        self.components.insert(name.to_string(), ComponentHealth {
            name: name.to_string(),
            status: HealthLevel::Healthy,
            last_check: Instant::now(),
            message: None,
        });
    }

    pub fn add_issue(&mut self, component: &str, message: &str, severity: HealthSeverity) {
        self.issues.push(HealthIssue {
            component: component.to_string(),
            message: message.to_string(),
            severity: severity.clone(),
            timestamp: Instant::now(),
        });

        // Update component status
        let component_status = match severity {
            HealthSeverity::Critical => HealthLevel::Critical,
            HealthSeverity::Warning => HealthLevel::Degraded,
            HealthSeverity::Info => HealthLevel::Healthy,
        };

        self.components.insert(component.to_string(), ComponentHealth {
            name: component.to_string(),
            status: component_status,
            last_check: Instant::now(),
            message: Some(message.to_string()),
        });

        // Update overall health
        if severity == HealthSeverity::Critical {
            self.overall_health = HealthLevel::Critical;
        } else if severity == HealthSeverity::Warning && self.overall_health == HealthLevel::Healthy {
            self.overall_health = HealthLevel::Degraded;
        }
    }

    pub async fn check_system_resources(&mut self) {
        // Check available memory
        if let Ok(memory) = self.get_available_memory() {
            if memory < 100 * 1024 * 1024 { // Less than 100MB
                self.add_issue("memory", "Low available memory", HealthSeverity::Warning);
            } else {
                self.add_healthy_component("memory");
            }
        }

        // Check disk space for temp directory
        if let Ok(disk_space) = self.get_available_disk_space() {
            if disk_space < 500 * 1024 * 1024 { // Less than 500MB
                self.add_issue("disk", "Low disk space", HealthSeverity::Warning);
            } else {
                self.add_healthy_component("disk");
            }
        }
    }

    fn get_available_memory(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // This is a simplified check - in real implementation you'd use
        // platform-specific APIs to get actual available memory
        #[cfg(target_os = "linux")]
        {
            let meminfo = std::fs::read_to_string("/proc/meminfo")?;
            for line in meminfo.lines() {
                if line.starts_with("MemAvailable:") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let kb: u64 = parts[1].parse()?;
                        return Ok(kb * 1024); // Convert to bytes
                    }
                }
            }
        }
        
        // Fallback - assume we have enough memory
        Ok(1024 * 1024 * 1024) // 1GB
    }

    fn get_available_disk_space(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Simplified disk space check
        use std::fs;
        
        let temp_dir = std::env::temp_dir();
        if let Ok(_metadata) = fs::metadata(&temp_dir) {
            // This is a very rough estimate - real implementation would use statvfs or similar
            Ok(1024 * 1024 * 1024) // Assume 1GB available
        } else {
            Err("Cannot access temp directory".into())
        }
    }
}

impl Default for GracefulDegradation {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper macro to execute operations with error recovery
#[macro_export]
macro_rules! with_error_recovery {
    ($operation:expr, $fallback:expr, $context:expr) => {
        match $operation {
            Ok(result) => result,
            Err(error) => {
                tracing::warn!("Operation failed in {}: {:?}, using fallback", $context, error);
                $fallback
            }
        }
    };
}

/// Helper macro to execute operations with circuit breaker protection
#[macro_export]
macro_rules! with_circuit_breaker {
    ($breaker:expr, $operation:expr) => {
        match $breaker.execute(|| $operation).await {
            Ok(result) => Ok(result),
            Err(CircuitBreakerError::CircuitOpen) => {
                Err(CargoCryptError::ServiceUnavailable {
                    service: "protected operation".to_string(),
                    reason: "Circuit breaker is open".to_string(),
                })
            }
            Err(CircuitBreakerError::CircuitOpened) => {
                Err(CargoCryptError::ServiceUnavailable {
                    service: "protected operation".to_string(),
                    reason: "Circuit breaker opened due to failures".to_string(),
                })
            }
            Err(CircuitBreakerError::OperationFailed(error)) => Err(error),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_circuit_breaker() {
        let breaker = CircuitBreaker::new("test".to_string(), 2, Duration::from_millis(100));
        
        // Should start closed
        assert_eq!(breaker.get_state().await, CircuitBreakerState::Closed);
        
        // Fail twice to open circuit
        let _ = breaker.execute(|| Err::<(), &str>("test error")).await;
        let _ = breaker.execute(|| Err::<(), &str>("test error")).await;
        
        // Should now be open
        assert_eq!(breaker.get_state().await, CircuitBreakerState::Open);
        
        // Should fail fast
        let result = breaker.execute(|| Ok::<(), &str>(())).await;
        assert!(matches!(result, Err(CircuitBreakerError::CircuitOpen)));
        
        // Wait for timeout and try again
        sleep(Duration::from_millis(150)).await;
        let result = breaker.execute(|| Ok::<(), &str>(())).await;
        assert!(result.is_ok());
        
        // Should be closed again
        assert_eq!(breaker.get_state().await, CircuitBreakerState::Closed);
    }

    #[tokio::test]
    async fn test_retry_policy() {
        let policy = RetryPolicy::new(3, Duration::from_millis(10));
        let mut attempts = 0;
        
        let result = policy.execute(|| {
            attempts += 1;
            async move {
                if attempts < 3 {
                    Err("temporary failure")
                } else {
                    Ok("success")
                }
            }
        }).await;
        
        assert_eq!(result, Ok("success"));
        assert_eq!(attempts, 3);
    }

    #[tokio::test]
    async fn test_graceful_degradation() {
        let gd = GracefulDegradation::new();
        
        // Register features
        gd.register_feature("tui", true).await;
        gd.register_feature("git_integration", true).await;
        
        assert!(gd.is_feature_enabled("tui").await);
        
        // Disable feature
        gd.disable_feature("tui", "testing").await;
        assert!(!gd.is_feature_enabled("tui").await);
    }
}