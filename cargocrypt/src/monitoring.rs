//! Monitoring, logging, and telemetry module
//!
//! Provides comprehensive observability for CargoCrypt operations including:
//! - Structured logging with contextual information
//! - Performance metrics collection
//! - Operation tracing and debugging
//! - Security audit logging
//! - Real-time monitoring server
//! - Performance bottleneck detection

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};

/// Central monitoring and telemetry manager
#[derive(Debug, Clone)]
pub struct MonitoringManager {
    metrics: Arc<RwLock<MetricsCollector>>,
    audit_logger: Arc<AuditLogger>,
    performance_tracker: Arc<RwLock<PerformanceTracker>>,
    config: MonitoringConfig,
}

/// Configuration for monitoring and logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable detailed operation logging
    pub detailed_logging: bool,
    /// Enable performance metrics collection
    pub performance_metrics: bool,
    /// Enable security audit logging
    pub security_audit: bool,
    /// Log level for file operations
    pub file_log_level: String,
    /// Maximum log file size in bytes
    pub max_log_size: u64,
    /// Number of log files to retain
    pub log_retention_count: u32,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            detailed_logging: true,
            performance_metrics: true,
            security_audit: true,
            file_log_level: "info".to_string(),
            max_log_size: 10 * 1024 * 1024, // 10MB
            log_retention_count: 5,
        }
    }
}

impl MonitoringManager {
    pub fn new(config: MonitoringConfig) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(MetricsCollector::new())),
            audit_logger: Arc::new(AuditLogger::new()),
            performance_tracker: Arc::new(RwLock::new(PerformanceTracker::new())),
            config,
        }
    }

    /// Initialize logging subsystem
    pub fn initialize_logging(&self) -> Result<(), Box<dyn std::error::Error>> {
        use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(&self.config.file_log_level));

        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_target(false)
                    .with_thread_ids(true)
                    .with_file(true)
                    .with_line_number(true)
                    .compact()
            )
            .with(env_filter)
            .init();

        info!("CargoCrypt monitoring initialized");
        Ok(())
    }

    /// Record a cryptographic operation
    pub async fn record_crypto_operation(&self, operation: CryptoOperation) {
        let operation_type = operation.operation_type;
        
        if self.config.performance_metrics {
            self.metrics.write().await.record_crypto_operation(operation.clone());
        }

        if self.config.security_audit {
            self.audit_logger.log_crypto_operation(operation).await;
        }

        debug!("Crypto operation recorded: {:?}", operation_type);
    }

    /// Record file operation metrics
    pub async fn record_file_operation(&self, operation: FileOperation) {
        if self.config.performance_metrics {
            self.metrics.write().await.record_file_operation(operation.clone());
        }

        if self.config.detailed_logging {
            info!(
                operation = ?operation.operation_type,
                file_path = %operation.file_path,
                size_bytes = operation.file_size,
                duration_ms = operation.duration.as_millis(),
                "File operation completed"
            );
        }
    }

    /// Start performance tracking for an operation
    pub async fn start_performance_tracking(&self, operation: &str) -> PerformanceTracker {
        let mut tracker = self.performance_tracker.write().await;
        tracker.start_operation(operation.to_string())
    }
    
    /// End performance tracking for an operation
    pub async fn end_performance_tracking(&self, operation: &str) -> Option<Duration> {
        let mut tracker = self.performance_tracker.write().await;
        tracker.end_operation(operation)
    }

    /// Get current metrics snapshot
    pub async fn get_metrics(&self) -> MetricsSnapshot {
        self.metrics.read().await.get_snapshot()
    }

    /// Get performance statistics
    pub async fn get_performance_stats(&self) -> PerformanceStats {
        self.performance_tracker.read().await.get_stats()
    }

    /// Log a security event
    pub async fn log_security_event(&self, event: SecurityEvent) {
        self.audit_logger.log_security_event(event).await;
    }
}

/// Metrics collector for various operations
#[derive(Debug)]
pub struct MetricsCollector {
    crypto_operations: HashMap<CryptoOperationType, OperationMetrics>,
    file_operations: HashMap<FileOperationType, OperationMetrics>,
    system_metrics: SystemMetrics,
    start_time: Instant,
}

/// Metrics for a specific operation type
#[derive(Debug, Clone)]
pub struct OperationMetrics {
    pub count: u64,
    pub total_duration: Duration,
    pub min_duration: Duration,
    pub max_duration: Duration,
    pub avg_duration: Duration,
    pub error_count: u64,
    pub last_operation: Option<Instant>,
}

/// System-wide metrics
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub memory_usage_peak: usize,
    pub total_bytes_encrypted: u64,
    pub total_bytes_decrypted: u64,
    pub total_files_processed: u64,
    pub uptime: Duration,
}

/// Snapshot of current metrics
#[derive(Debug, Clone, Serialize)]
pub struct MetricsSnapshot {
    pub crypto_operations: HashMap<String, OperationSummary>,
    pub file_operations: HashMap<String, OperationSummary>,
    pub system_metrics: SystemMetricsSummary,
    pub timestamp: u64,
}

/// Summary of operation metrics
#[derive(Debug, Clone, Serialize)]
pub struct OperationSummary {
    pub count: u64,
    pub avg_duration_ms: u64,
    pub error_rate: f64,
    pub throughput_ops_per_sec: f64,
}

/// System metrics summary
#[derive(Debug, Clone, Serialize)]
pub struct SystemMetricsSummary {
    pub uptime_seconds: u64,
    pub memory_peak_mb: f64,
    pub total_encrypted_mb: f64,
    pub total_decrypted_mb: f64,
    pub files_processed: u64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            crypto_operations: HashMap::new(),
            file_operations: HashMap::new(),
            system_metrics: SystemMetrics {
                memory_usage_peak: 0,
                total_bytes_encrypted: 0,
                total_bytes_decrypted: 0,
                total_files_processed: 0,
                uptime: Duration::from_secs(0),
            },
            start_time: Instant::now(),
        }
    }

    pub fn record_crypto_operation(&mut self, operation: CryptoOperation) {
        let metrics = self.crypto_operations
            .entry(operation.operation_type)
            .or_insert_with(|| OperationMetrics {
                count: 0,
                total_duration: Duration::from_secs(0),
                min_duration: Duration::from_secs(u64::MAX),
                max_duration: Duration::from_secs(0),
                avg_duration: Duration::from_secs(0),
                error_count: 0,
                last_operation: None,
            });

        metrics.count += 1;
        metrics.total_duration += operation.duration;
        metrics.min_duration = metrics.min_duration.min(operation.duration);
        metrics.max_duration = metrics.max_duration.max(operation.duration);
        metrics.avg_duration = metrics.total_duration / metrics.count as u32;
        metrics.last_operation = Some(Instant::now());

        if operation.success {
            match operation.operation_type {
                CryptoOperationType::Encrypt => {
                    self.system_metrics.total_bytes_encrypted += operation.data_size;
                }
                CryptoOperationType::Decrypt => {
                    self.system_metrics.total_bytes_decrypted += operation.data_size;
                }
                _ => {}
            }
        } else {
            metrics.error_count += 1;
        }
    }

    pub fn record_file_operation(&mut self, operation: FileOperation) {
        let metrics = self.file_operations
            .entry(operation.operation_type)
            .or_insert_with(|| OperationMetrics {
                count: 0,
                total_duration: Duration::from_secs(0),
                min_duration: Duration::from_secs(u64::MAX),
                max_duration: Duration::from_secs(0),
                avg_duration: Duration::from_secs(0),
                error_count: 0,
                last_operation: None,
            });

        metrics.count += 1;
        metrics.total_duration += operation.duration;
        metrics.min_duration = metrics.min_duration.min(operation.duration);
        metrics.max_duration = metrics.max_duration.max(operation.duration);
        metrics.avg_duration = metrics.total_duration / metrics.count as u32;
        metrics.last_operation = Some(Instant::now());

        if !operation.success {
            metrics.error_count += 1;
        } else {
            self.system_metrics.total_files_processed += 1;
        }
    }

    pub fn get_snapshot(&self) -> MetricsSnapshot {
        let mut crypto_ops = HashMap::new();
        for (op_type, metrics) in &self.crypto_operations {
            crypto_ops.insert(
                format!("{:?}", op_type),
                OperationSummary {
                    count: metrics.count,
                    avg_duration_ms: metrics.avg_duration.as_millis() as u64,
                    error_rate: if metrics.count > 0 {
                        metrics.error_count as f64 / metrics.count as f64
                    } else {
                        0.0
                    },
                    throughput_ops_per_sec: if metrics.total_duration.as_secs() > 0 {
                        metrics.count as f64 / metrics.total_duration.as_secs() as f64
                    } else {
                        0.0
                    },
                }
            );
        }

        let mut file_ops = HashMap::new();
        for (op_type, metrics) in &self.file_operations {
            file_ops.insert(
                format!("{:?}", op_type),
                OperationSummary {
                    count: metrics.count,
                    avg_duration_ms: metrics.avg_duration.as_millis() as u64,
                    error_rate: if metrics.count > 0 {
                        metrics.error_count as f64 / metrics.count as f64
                    } else {
                        0.0
                    },
                    throughput_ops_per_sec: if metrics.total_duration.as_secs() > 0 {
                        metrics.count as f64 / metrics.total_duration.as_secs() as f64
                    } else {
                        0.0
                    },
                }
            );
        }

        MetricsSnapshot {
            crypto_operations: crypto_ops,
            file_operations: file_ops,
            system_metrics: SystemMetricsSummary {
                uptime_seconds: self.start_time.elapsed().as_secs(),
                memory_peak_mb: self.system_metrics.memory_usage_peak as f64 / (1024.0 * 1024.0),
                total_encrypted_mb: self.system_metrics.total_bytes_encrypted as f64 / (1024.0 * 1024.0),
                total_decrypted_mb: self.system_metrics.total_bytes_decrypted as f64 / (1024.0 * 1024.0),
                files_processed: self.system_metrics.total_files_processed,
            },
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

/// Performance tracker for individual operations
#[derive(Debug, Clone)]
pub struct PerformanceTracker {
    active_operations: HashMap<String, Instant>,
    completed_operations: Vec<CompletedOperation>,
    stats: PerformanceStats,
    bottleneck_detector: BottleneckDetector,
    memory_tracker: MemoryTracker,
}

/// Statistics about performance
#[derive(Debug, Clone, Serialize)]
pub struct PerformanceStats {
    pub average_operation_time: Duration,
    pub slowest_operation: Option<String>,
    pub fastest_operation: Option<String>,
    pub operations_per_minute: f64,
    pub current_active_operations: usize,
}

/// Record of a completed operation
#[derive(Debug, Clone)]
pub struct CompletedOperation {
    pub name: String,
    pub duration: Duration,
    pub timestamp: Instant,
}

impl PerformanceTracker {
    pub fn new() -> Self {
        Self {
            active_operations: HashMap::new(),
            completed_operations: Vec::new(),
            stats: PerformanceStats {
                average_operation_time: Duration::from_secs(0),
                slowest_operation: None,
                fastest_operation: None,
                operations_per_minute: 0.0,
                current_active_operations: 0,
            },
            bottleneck_detector: BottleneckDetector::new(),
            memory_tracker: MemoryTracker::new(),
        }
    }

    pub fn start_operation(&mut self, name: String) -> PerformanceTracker {
        self.active_operations.insert(name.clone(), Instant::now());
        self.update_stats();
        self.clone()
    }

    pub fn end_operation(&mut self, name: &str) -> Option<Duration> {
        if let Some(start_time) = self.active_operations.remove(name) {
            let duration = start_time.elapsed();
            self.completed_operations.push(CompletedOperation {
                name: name.to_string(),
                duration,
                timestamp: Instant::now(),
            });
            self.update_stats();
            Some(duration)
        } else {
            None
        }
    }

    fn update_stats(&mut self) {
        self.stats.current_active_operations = self.active_operations.len();

        if !self.completed_operations.is_empty() {
            let total_duration: Duration = self.completed_operations
                .iter()
                .map(|op| op.duration)
                .sum();
            
            self.stats.average_operation_time = total_duration / self.completed_operations.len() as u32;

            if let Some(slowest) = self.completed_operations
                .iter()
                .max_by_key(|op| op.duration) {
                self.stats.slowest_operation = Some(slowest.name.clone());
            }

            if let Some(fastest) = self.completed_operations
                .iter()
                .min_by_key(|op| op.duration) {
                self.stats.fastest_operation = Some(fastest.name.clone());
            }

            // Calculate operations per minute (last 10 minutes)
            let ten_minutes_ago = Instant::now() - Duration::from_secs(600);
            let recent_ops = self.completed_operations
                .iter()
                .filter(|op| op.timestamp > ten_minutes_ago)
                .count();
            
            self.stats.operations_per_minute = recent_ops as f64 / 10.0;
        }
    }

    pub fn get_stats(&self) -> PerformanceStats {
        self.stats.clone()
    }
    
    /// Detect performance bottlenecks based on operation history
    pub fn detect_bottlenecks(&self) -> Vec<BottleneckAlert> {
        self.bottleneck_detector.analyze(&self.completed_operations)
    }
    
    /// Get current memory usage statistics
    pub fn get_memory_stats(&self) -> MemoryStats {
        self.memory_tracker.get_stats()
    }
    
    /// Update memory usage tracking
    pub fn update_memory_usage(&mut self, usage: usize) {
        self.memory_tracker.update(usage);
    }
}

/// Audit logger for security events
#[derive(Debug)]
pub struct AuditLogger {
    // In a real implementation, this would write to secure audit logs
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn log_crypto_operation(&self, operation: CryptoOperation) {
        info!(
            target: "security_audit",
            operation_type = ?operation.operation_type,
            data_size = operation.data_size,
            duration_ms = operation.duration.as_millis(),
            success = operation.success,
            "Cryptographic operation performed"
        );
    }

    pub async fn log_security_event(&self, event: SecurityEvent) {
        match event.severity {
            SecuritySeverity::Critical => error!(
                target: "security_audit",
                event_type = ?event.event_type,
                message = %event.message,
                context = ?event.context,
                "Critical security event"
            ),
            SecuritySeverity::Warning => warn!(
                target: "security_audit",
                event_type = ?event.event_type,
                message = %event.message,
                context = ?event.context,
                "Security warning"
            ),
            SecuritySeverity::Info => info!(
                target: "security_audit",
                event_type = ?event.event_type,
                message = %event.message,
                context = ?event.context,
                "Security event"
            ),
        }
    }
}

/// Cryptographic operation record
#[derive(Debug, Clone)]
pub struct CryptoOperation {
    pub operation_type: CryptoOperationType,
    pub data_size: u64,
    pub duration: Duration,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Types of cryptographic operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CryptoOperationType {
    Encrypt,
    Decrypt,
    KeyDerivation,
    SecretGeneration,
}

/// File operation record
#[derive(Debug, Clone)]
pub struct FileOperation {
    pub operation_type: FileOperationType,
    pub file_path: String,
    pub file_size: u64,
    pub duration: Duration,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Types of file operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileOperationType {
    Read,
    Write,
    Delete,
    Copy,
    Move,
}

/// Security event record
#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub event_type: SecurityEventType,
    pub message: String,
    pub severity: SecuritySeverity,
    pub context: Option<HashMap<String, String>>,
    pub timestamp: SystemTime,
}

/// Types of security events
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityEventType {
    SecretDetected,
    WeakPassword,
    UnauthorizedAccess,
    SuspiciousActivity,
    ConfigurationChange,
}

/// Security event severity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecuritySeverity {
    Info,
    Warning,
    Critical,
}

/// Helper macro to trace function execution
#[macro_export]
macro_rules! trace_operation {
    ($name:expr, $operation:expr) => {{
        let _span = tracing::span!(tracing::Level::DEBUG, "operation", name = $name).entered();
        let start = std::time::Instant::now();
        let result = $operation;
        let duration = start.elapsed();
        
        match &result {
            Ok(_) => {
                tracing::debug!(
                    operation = $name,
                    duration_ms = duration.as_millis(),
                    "Operation completed successfully"
                );
            }
            Err(e) => {
                tracing::error!(
                    operation = $name,
                    duration_ms = duration.as_millis(),
                    error = ?e,
                    "Operation failed"
                );
            }
        }
        
        result
    }};
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for PerformanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Bottleneck detector for identifying performance issues
#[derive(Debug, Clone)]
pub struct BottleneckDetector {
    thresholds: PerformanceThresholds,
}

/// Performance thresholds for bottleneck detection
#[derive(Debug, Clone)]
pub struct PerformanceThresholds {
    pub slow_operation_threshold: Duration,
    pub memory_usage_threshold: usize,
    pub error_rate_threshold: f64,
    pub throughput_threshold: f64,
}

/// Alert for detected performance bottlenecks
#[derive(Debug, Clone, Serialize)]
pub struct BottleneckAlert {
    pub alert_type: BottleneckType,
    pub severity: AlertSeverity,
    pub message: String,
    pub operation_name: String,
    pub metrics: HashMap<String, f64>,
    pub timestamp: SystemTime,
}

/// Types of performance bottlenecks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BottleneckType {
    SlowOperation,
    HighMemoryUsage,
    HighErrorRate,
    LowThroughput,
    CpuBound,
    IoBound,
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

/// Memory usage tracker
#[derive(Debug, Clone)]
pub struct MemoryTracker {
    current_usage: usize,
    peak_usage: usize,
    history: Vec<MemorySnapshot>,
    start_time: Instant,
}

/// Memory usage statistics
#[derive(Debug, Clone, Serialize)]
pub struct MemoryStats {
    pub current_mb: f64,
    pub peak_mb: f64,
    pub average_mb: f64,
    pub growth_rate_mb_per_sec: f64,
    pub uptime_seconds: u64,
}

/// Memory usage snapshot
#[derive(Debug, Clone)]
pub struct MemorySnapshot {
    pub usage: usize,
    pub timestamp: Instant,
}

/// Health check endpoint data
#[derive(Debug, Clone, Serialize)]
pub struct HealthCheck {
    pub status: HealthStatus,
    pub timestamp: SystemTime,
    pub metrics: MetricsSnapshot,
    pub alerts: Vec<BottleneckAlert>,
    pub memory_stats: MemoryStats,
    pub uptime_seconds: u64,
}

/// Health status levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Critical,
    Unknown,
}

impl Default for PerformanceThresholds {
    fn default() -> Self {
        Self {
            slow_operation_threshold: Duration::from_millis(1000), // 1 second
            memory_usage_threshold: 100 * 1024 * 1024, // 100 MB
            error_rate_threshold: 0.05, // 5%
            throughput_threshold: 10.0, // 10 ops/sec minimum
        }
    }
}

impl BottleneckDetector {
    pub fn new() -> Self {
        Self {
            thresholds: PerformanceThresholds::default(),
        }
    }
    
    pub fn with_thresholds(thresholds: PerformanceThresholds) -> Self {
        Self { thresholds }
    }
    
    /// Analyze operations for bottlenecks
    pub fn analyze(&self, operations: &[CompletedOperation]) -> Vec<BottleneckAlert> {
        let mut alerts = Vec::new();
        
        if operations.is_empty() {
            return alerts;
        }
        
        // Analyze operation durations
        let slow_ops = operations.iter()
            .filter(|op| op.duration > self.thresholds.slow_operation_threshold)
            .collect::<Vec<_>>();
        
        if !slow_ops.is_empty() {
            let avg_slow_duration = slow_ops.iter()
                .map(|op| op.duration.as_millis() as f64)
                .sum::<f64>() / slow_ops.len() as f64;
            
            let mut metrics = HashMap::new();
            metrics.insert("average_duration_ms".to_string(), avg_slow_duration);
            metrics.insert("slow_operation_count".to_string(), slow_ops.len() as f64);
            
            alerts.push(BottleneckAlert {
                alert_type: BottleneckType::SlowOperation,
                severity: if avg_slow_duration > 5000.0 { AlertSeverity::Critical } else { AlertSeverity::Warning },
                message: format!("Detected {} slow operations with average duration {:.2}ms", 
                                slow_ops.len(), avg_slow_duration),
                operation_name: "multiple".to_string(),
                metrics,
                timestamp: SystemTime::now(),
            });
        }
        
        // Analyze throughput
        let recent_ops = operations.iter()
            .filter(|op| op.timestamp.elapsed() < Duration::from_secs(60))
            .count();
        
        let throughput = recent_ops as f64 / 60.0; // ops per second
        
        if throughput < self.thresholds.throughput_threshold {
            let mut metrics = HashMap::new();
            metrics.insert("throughput_ops_per_sec".to_string(), throughput);
            metrics.insert("threshold".to_string(), self.thresholds.throughput_threshold);
            
            alerts.push(BottleneckAlert {
                alert_type: BottleneckType::LowThroughput,
                severity: AlertSeverity::Warning,
                message: format!("Low throughput detected: {:.2} ops/sec (threshold: {:.2})", 
                                throughput, self.thresholds.throughput_threshold),
                operation_name: "system".to_string(),
                metrics,
                timestamp: SystemTime::now(),
            });
        }
        
        alerts
    }
}

impl MemoryTracker {
    pub fn new() -> Self {
        Self {
            current_usage: 0,
            peak_usage: 0,
            history: Vec::new(),
            start_time: Instant::now(),
        }
    }
    
    pub fn update(&mut self, usage: usize) {
        self.current_usage = usage;
        if usage > self.peak_usage {
            self.peak_usage = usage;
        }
        
        self.history.push(MemorySnapshot {
            usage,
            timestamp: Instant::now(),
        });
        
        // Keep only last hour of data
        let cutoff = Instant::now() - Duration::from_secs(3600);
        self.history.retain(|snapshot| snapshot.timestamp > cutoff);
    }
    
    pub fn get_stats(&self) -> MemoryStats {
        let uptime = self.start_time.elapsed().as_secs();
        
        let average_mb = if !self.history.is_empty() {
            let total: usize = self.history.iter().map(|s| s.usage).sum();
            (total as f64 / self.history.len() as f64) / (1024.0 * 1024.0)
        } else {
            0.0
        };
        
        let growth_rate = if self.history.len() > 1 && uptime > 0 {
            let initial = self.history[0].usage as f64;
            let current = self.current_usage as f64;
            ((current - initial) / (1024.0 * 1024.0)) / uptime as f64
        } else {
            0.0
        };
        
        MemoryStats {
            current_mb: self.current_usage as f64 / (1024.0 * 1024.0),
            peak_mb: self.peak_usage as f64 / (1024.0 * 1024.0),
            average_mb,
            growth_rate_mb_per_sec: growth_rate,
            uptime_seconds: uptime,
        }
    }
}

impl MonitoringManager {
    /// Get comprehensive health check
    pub async fn health_check(&self) -> HealthCheck {
        let metrics = self.get_metrics().await;
        let performance_stats = self.get_performance_stats().await;
        let performance_tracker = self.performance_tracker.read().await;
        
        let alerts = performance_tracker.detect_bottlenecks();
        let memory_stats = performance_tracker.get_memory_stats();
        
        // Determine overall health status
        let status = if alerts.iter().any(|a| a.severity == AlertSeverity::Critical) {
            HealthStatus::Critical
        } else if alerts.iter().any(|a| a.severity == AlertSeverity::Warning) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };
        
        HealthCheck {
            status,
            timestamp: SystemTime::now(),
            uptime_seconds: metrics.system_metrics.uptime_seconds,
            metrics,
            alerts,
            memory_stats,
        }
    }
    
    /// Check for performance degradation and trigger alerts
    pub async fn check_performance_alerts(&self) -> Vec<BottleneckAlert> {
        let performance_tracker = self.performance_tracker.read().await;
        performance_tracker.detect_bottlenecks()
    }
    
    /// Update memory usage for tracking
    pub async fn update_memory_usage(&self, usage: usize) {
        let mut tracker = self.performance_tracker.write().await;
        tracker.update_memory_usage(usage);
        
        // Update system metrics
        let mut metrics = self.metrics.write().await;
        if usage > metrics.system_metrics.memory_usage_peak {
            metrics.system_metrics.memory_usage_peak = usage;
        }
    }
    
    /// Get real-time throughput metrics
    pub async fn get_realtime_throughput(&self) -> HashMap<String, f64> {
        let metrics = self.metrics.read().await;
        let mut throughput = HashMap::new();
        
        // Calculate throughput for each operation type
        for (op_type, op_metrics) in &metrics.crypto_operations {
            if op_metrics.total_duration.as_secs() > 0 {
                let ops_per_sec = op_metrics.count as f64 / op_metrics.total_duration.as_secs() as f64;
                throughput.insert(format!("crypto_{:?}", op_type), ops_per_sec);
            }
        }
        
        for (op_type, op_metrics) in &metrics.file_operations {
            if op_metrics.total_duration.as_secs() > 0 {
                let ops_per_sec = op_metrics.count as f64 / op_metrics.total_duration.as_secs() as f64;
                throughput.insert(format!("file_{:?}", op_type), ops_per_sec);
            }
        }
        
        throughput
    }
    
    /// Export metrics in JSON format for external monitoring
    pub async fn export_metrics_json(&self) -> String {
        let health = self.health_check().await;
        serde_json::to_string_pretty(&health).unwrap_or_else(|_| "{\"error\": \"failed_to_serialize\"}".to_string())
    }
}

impl Default for BottleneckDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for MemoryTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_collection() {
        let mut collector = MetricsCollector::new();
        
        let operation = CryptoOperation {
            operation_type: CryptoOperationType::Encrypt,
            data_size: 1024,
            duration: Duration::from_millis(100),
            success: true,
            error_message: None,
        };
        
        collector.record_crypto_operation(operation);
        
        let snapshot = collector.get_snapshot();
        assert!(snapshot.crypto_operations.contains_key("Encrypt"));
    }

    #[tokio::test]
    async fn test_performance_tracking() {
        let mut tracker = PerformanceTracker::new();
        
        tracker.start_operation("test_op".to_string());
        tokio::time::sleep(Duration::from_millis(10)).await;
        let duration = tracker.end_operation("test_op");
        
        assert!(duration.is_some());
        assert!(duration.unwrap() >= Duration::from_millis(10));
    }

    #[test]
    fn test_monitoring_config() {
        let config = MonitoringConfig::default();
        assert!(config.detailed_logging);
        assert!(config.performance_metrics);
        assert!(config.security_audit);
    }
    
    #[test]
    fn test_bottleneck_detection() {
        let detector = BottleneckDetector::new();
        let operations = vec![
            CompletedOperation {
                name: "slow_op".to_string(),
                duration: Duration::from_secs(2), // Above threshold
                timestamp: Instant::now(),
            }
        ];
        
        let alerts = detector.analyze(&operations);
        assert!(!alerts.is_empty());
        assert_eq!(alerts[0].alert_type, BottleneckType::SlowOperation);
    }
    
    #[test]
    fn test_memory_tracking() {
        let mut tracker = MemoryTracker::new();
        tracker.update(1024 * 1024); // 1 MB
        tracker.update(2 * 1024 * 1024); // 2 MB
        
        let stats = tracker.get_stats();
        assert_eq!(stats.current_mb, 2.0);
        assert_eq!(stats.peak_mb, 2.0);
    }
}

/// HTTP monitoring server module
pub mod server {
    use super::{MonitoringManager, HealthCheck};
    use std::sync::Arc;
    use std::net::SocketAddr;
    use tokio::net::TcpListener;
    use serde_json;
    use tracing::{info, warn, error};

    /// HTTP monitoring server
    pub struct MonitoringServer {
        monitoring: Arc<MonitoringManager>,
        addr: SocketAddr,
    }

    impl MonitoringServer {
        /// Create a new monitoring server
        pub fn new(monitoring: Arc<MonitoringManager>, addr: SocketAddr) -> Self {
            Self { monitoring, addr }
        }
        
        /// Start the monitoring server
        pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let listener = TcpListener::bind(&self.addr).await?;
            info!("Monitoring server listening on {}", self.addr);
            
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let monitoring = Arc::clone(&self.monitoring);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, monitoring).await {
                                warn!("Error handling connection from {}: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        }
    }

    /// Handle a single HTTP connection
    async fn handle_connection(
        mut stream: tokio::net::TcpStream,
        monitoring: Arc<MonitoringManager>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        
        let mut buffer = [0; 1024];
        let bytes_read = stream.read(&mut buffer).await?;
        
        let request = String::from_utf8_lossy(&buffer[..bytes_read]);
        
        if request.contains("GET /health") {
            let health = monitoring.health_check().await;
            let json = serde_json::to_string_pretty(&health)?;
            send_json_response(&mut stream, 200, &json).await?;
        } else if request.contains("GET /metrics") {
            let metrics = monitoring.get_metrics().await;
            let json = serde_json::to_string_pretty(&metrics)?;
            send_json_response(&mut stream, 200, &json).await?;
        } else {
            send_response(&mut stream, 404, "Not Found", "Endpoint not found").await?;
        }
        
        Ok(())
    }

    async fn send_response(
        stream: &mut tokio::net::TcpStream,
        status_code: u16,
        status_text: &str,
        body: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::AsyncWriteExt;
        
        let response = format!(
            "HTTP/1.1 {} {}\r\n\r\n{}",
            status_code, status_text, body
        );
        
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn send_json_response(
        stream: &mut tokio::net::TcpStream,
        status_code: u16,
        json: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::io::AsyncWriteExt;
        
        let status_text = match status_code {
            200 => "OK",
            _ => "Error",
        };
        
        let response = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            status_code, status_text, json.len(), json
        );
        
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
        Ok(())
    }
}