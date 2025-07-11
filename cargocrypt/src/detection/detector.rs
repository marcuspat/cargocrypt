//! Main secret detector interface
//!
//! This module provides the high-level SecretDetector interface that coordinates
//! all detection components (patterns, entropy analysis, custom rules, and file scanning).

use crate::detection::{
    Finding, 
    findings::FindingCollection, 
    patterns::PatternRegistry, 
    entropy::EntropyAnalyzer, 
    rules::RuleEngine, 
    scanner::{FileScanner, ScanConfig},
};
use crate::error::{CargoCryptError, CryptoResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{info, warn, debug};

/// Configuration for the secret detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Enable pattern-based detection
    pub enable_patterns: bool,
    /// Enable entropy-based detection
    pub enable_entropy: bool,
    /// Enable custom rules
    pub enable_custom_rules: bool,
    /// Minimum confidence threshold for reporting (0.0 to 1.0)
    pub min_confidence: f64,
    /// Whether to analyze high-entropy strings
    pub analyze_entropy: bool,
    /// Custom ignore patterns
    pub ignore_patterns: Vec<String>,
    /// Custom whitelist patterns (these reduce false positives)
    pub whitelist_patterns: Vec<String>,
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enable_patterns: true,
            enable_entropy: true,
            enable_custom_rules: true,
            min_confidence: 0.3,
            analyze_entropy: true,
            ignore_patterns: vec![
                // Common test patterns
                "example".to_string(),
                "test".to_string(),
                "placeholder".to_string(),
                "your_.*_here".to_string(),
                "insert_.*_here".to_string(),
                // Common dummy values
                "12345".to_string(),
                "password123".to_string(),
                "changeme".to_string(),
                "dummy".to_string(),
                "fake".to_string(),
            ],
            whitelist_patterns: vec![
                // Comments and documentation
                r"//.*".to_string(),
                r"#.*".to_string(),
                r"/\*.*\*/".to_string(),
                // Common safe patterns
                r"localhost".to_string(),
                r"127\.0\.0\.1".to_string(),
                r"example\.com".to_string(),
            ],
        }
    }
}

/// Options for scanning operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOptions {
    /// Detection configuration
    pub detection_config: DetectionConfig,
    /// File scanning configuration
    pub scan_config: ScanConfig,
    /// Whether to include low-confidence findings
    pub include_low_confidence: bool,
    /// Maximum number of findings to return (0 = unlimited)
    pub max_findings: usize,
    /// Whether to sort findings by confidence
    pub sort_by_confidence: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            detection_config: DetectionConfig::default(),
            scan_config: ScanConfig::default(),
            include_low_confidence: false,
            max_findings: 0,
            sort_by_confidence: true,
        }
    }
}

impl ScanOptions {
    /// Create options optimized for source code scanning
    pub fn for_source_code() -> Self {
        Self {
            detection_config: DetectionConfig::default(),
            scan_config: ScanConfig::for_source_code(),
            include_low_confidence: false,
            max_findings: 100,
            sort_by_confidence: true,
        }
    }

    /// Create options optimized for configuration file scanning
    pub fn for_config_files() -> Self {
        Self {
            detection_config: DetectionConfig {
                min_confidence: 0.5, // Higher threshold for config files
                ..DetectionConfig::default()
            },
            scan_config: ScanConfig::for_config_files(),
            include_low_confidence: false,
            max_findings: 50,
            sort_by_confidence: true,
        }
    }

    /// Create options for comprehensive scanning (all files, all patterns)
    pub fn comprehensive() -> Self {
        Self {
            detection_config: DetectionConfig {
                min_confidence: 0.2, // Lower threshold for comprehensive scan
                ..DetectionConfig::default()
            },
            scan_config: ScanConfig::default().scan_all_files(),
            include_low_confidence: true,
            max_findings: 500,
            sort_by_confidence: true,
        }
    }

    /// Set minimum confidence threshold
    pub fn with_min_confidence(mut self, confidence: f64) -> Self {
        self.detection_config.min_confidence = confidence;
        self
    }

    /// Enable or disable parallel processing
    pub fn with_parallel(mut self, parallel: bool) -> Self {
        self.scan_config.parallel = parallel;
        self
    }

    /// Set maximum number of findings
    pub fn with_max_findings(mut self, max: usize) -> Self {
        self.max_findings = max;
        self
    }
}

/// Main secret detector
pub struct SecretDetector {
    pattern_registry: PatternRegistry,
    entropy_analyzer: EntropyAnalyzer,
    rule_engine: RuleEngine,
    config: DetectionConfig,
}

impl SecretDetector {
    /// Create a new secret detector with default configuration
    pub fn new() -> Self {
        Self::with_config(DetectionConfig::default())
    }

    /// Create a secret detector with custom configuration
    pub fn with_config(config: DetectionConfig) -> Self {
        let pattern_registry = PatternRegistry::new()
            .expect("Failed to create pattern registry");
        let entropy_analyzer = EntropyAnalyzer::new();
        let rule_engine = RuleEngine::new();

        Self {
            pattern_registry,
            entropy_analyzer,
            rule_engine,
            config,
        }
    }

    /// Get the detector name
    pub fn name(&self) -> &'static str {
        "SecretDetector"
    }

    /// Get the current configuration
    pub fn config(&self) -> &DetectionConfig {
        &self.config
    }

    /// Update the configuration
    pub fn update_config(&mut self, config: DetectionConfig) {
        self.config = config;
    }

    /// Add a custom rule to the rule engine
    pub fn add_custom_rule(&mut self, rule: crate::detection::rules::CustomRule) {
        self.rule_engine.add_rule(rule);
    }

    /// Scan a single file for secrets
    pub async fn scan_file<P: AsRef<Path>>(&self, path: P, options: &ScanOptions) -> CryptoResult<Vec<Finding>> {
        let start_time = Instant::now();
        let path = path.as_ref();
        
        info!("Scanning file: {}", path.display());
        
        // Create file scanner
        let scanner = FileScanner::with_components(
            self.pattern_registry.clone(),
            self.entropy_analyzer.clone(),
            self.rule_engine.clone(),
            options.scan_config.clone(),
        );

        // Scan the file
        let scan_result = scanner.scan_file(path)?;
        
        if scan_result.skipped {
            warn!("Skipped file {}: {}", path.display(), 
                  scan_result.skip_reason.unwrap_or_else(|| "Unknown reason".to_string()));
            return Ok(Vec::new());
        }

        // Process findings
        let mut findings = scan_result.findings;
        self.post_process_findings(&mut findings, options);

        let scan_time = start_time.elapsed();
        debug!("Scanned {} in {:.2}ms, found {} findings", 
               path.display(), scan_time.as_millis(), findings.len());

        Ok(findings)
    }

    /// Scan a directory for secrets
    pub async fn scan_directory<P: AsRef<Path>>(&self, path: P, options: &ScanOptions) -> CryptoResult<Vec<Finding>> {
        let start_time = Instant::now();
        let path = path.as_ref();
        
        info!("Scanning directory: {}", path.display());

        // Create file scanner
        let scanner = FileScanner::with_components(
            self.pattern_registry.clone(),
            self.entropy_analyzer.clone(),
            self.rule_engine.clone(),
            options.scan_config.clone(),
        );

        // Scan the directory
        let scan_results = scanner.scan_directory(path)?;
        
        // Collect all findings
        let mut all_findings = Vec::new();
        let mut files_scanned = 0;
        let mut files_skipped = 0;

        for result in scan_results {
            if result.skipped {
                files_skipped += 1;
                if let Some(reason) = &result.skip_reason {
                    debug!("Skipped {}: {}", result.file_path.display(), reason);
                }
            } else {
                files_scanned += 1;
                all_findings.extend(result.findings);
            }
        }

        // Post-process findings
        self.post_process_findings(&mut all_findings, options);

        let scan_time = start_time.elapsed();
        info!("Scanned {} files ({} skipped) in {:.2}s, found {} findings",
              files_scanned, files_skipped, scan_time.as_secs_f64(), all_findings.len());

        Ok(all_findings)
    }

    /// Scan text content directly
    pub fn scan_content(&self, content: &str, source_name: &str) -> CryptoResult<Vec<Finding>> {
        let start_time = Instant::now();
        
        debug!("Scanning content from: {}", source_name);

        // Create a temporary file scanner
        let scanner = FileScanner::with_components(
            self.pattern_registry.clone(),
            self.entropy_analyzer.clone(),
            self.rule_engine.clone(),
            ScanConfig::default(),
        );

        // Scan the content
        let findings = scanner.scan_content(content, Path::new(source_name))?;

        let scan_time = start_time.elapsed();
        debug!("Scanned content in {:.2}ms, found {} findings", 
               scan_time.as_millis(), findings.len());

        Ok(findings)
    }

    /// Generate a comprehensive scan report
    pub async fn generate_report<P: AsRef<Path>>(&self, path: P, options: &ScanOptions) -> CryptoResult<DetectionReport> {
        let start_time = Instant::now();
        let path = path.as_ref();

        let findings = if path.is_file() {
            self.scan_file(path, options).await?
        } else {
            self.scan_directory(path, options).await?
        };

        let mut collection = FindingCollection::new();
        for finding in findings {
            collection.add_finding(finding);
        }

        let total_time = start_time.elapsed();

        Ok(DetectionReport {
            scanned_path: path.to_path_buf(),
            findings: collection,
            scan_time_ms: total_time.as_millis() as u64,
            detector_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_options: options.clone(),
        })
    }

    /// Post-process findings (filtering, sorting, etc.)
    fn post_process_findings(&self, findings: &mut Vec<Finding>, options: &ScanOptions) {
        // Filter by confidence threshold
        findings.retain(|f| f.confidence >= options.detection_config.min_confidence);

        // Filter low confidence if not requested
        if !options.include_low_confidence {
            findings.retain(|f| f.confidence >= 0.5);
        }

        // Apply ignore patterns
        for pattern in &options.detection_config.ignore_patterns {
            if let Ok(regex) = regex::Regex::new(pattern) {
                findings.retain(|f| !regex.is_match(&f.secret.value));
            }
        }

        // Sort by confidence if requested
        if options.sort_by_confidence {
            findings.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
        }

        // Limit number of findings
        if options.max_findings > 0 && findings.len() > options.max_findings {
            findings.truncate(options.max_findings);
        }

        // Remove duplicates (same secret value in same file)
        findings.dedup_by(|a, b| {
            a.file_path == b.file_path && a.secret.value == b.secret.value
        });
    }

    /// Validate a potential secret (can be extended with API calls, etc.)
    pub async fn validate_secret(&self, secret: &Finding) -> CryptoResult<bool> {
        // Basic validation based on patterns and entropy
        let is_valid = match secret.secret.secret_type.as_str() {
            "AWS Access Key" => self.validate_aws_key(&secret.secret.value).await,
            "GitHub Token" => self.validate_github_token(&secret.secret.value).await,
            _ => {
                // For unknown types, rely on confidence score
                secret.confidence > 0.8
            }
        };

        Ok(is_valid)
    }

    /// AWS key validation (basic format check)
    async fn validate_aws_key(&self, _key: &str) -> bool {
        // In a real implementation, you might:
        // 1. Check key format more thoroughly
        // 2. Make an AWS API call to validate (if safe to do so)
        // 3. Check against known invalid patterns
        
        // For now, just return true as this is handled by patterns
        true
    }

    /// GitHub token validation (basic format check)
    async fn validate_github_token(&self, _token: &str) -> bool {
        // In a real implementation, you might:
        // 1. Make a GitHub API call to validate (if safe to do so)
        // 2. Check token format more thoroughly
        
        // For now, just return true as this is handled by patterns
        true
    }
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Comprehensive detection report
#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionReport {
    /// Path that was scanned
    pub scanned_path: PathBuf,
    /// All findings with statistics
    pub findings: FindingCollection,
    /// Total scan time in milliseconds
    pub scan_time_ms: u64,
    /// Version of the detector used
    pub detector_version: String,
    /// Scan options used
    pub scan_options: ScanOptions,
}

impl DetectionReport {
    /// Get a summary of the report
    pub fn summary(&self) -> String {
        format!(
            "Scanned {} in {:.2}s - {}",
            self.scanned_path.display(),
            self.scan_time_ms as f64 / 1000.0,
            self.findings.summary()
        )
    }

    /// Get high-confidence findings only
    pub fn high_confidence_findings(&self) -> Vec<&Finding> {
        self.findings.high_confidence_findings(0.7)
    }

    /// Get critical findings (very high confidence or high severity)
    pub fn critical_findings(&self) -> Vec<&Finding> {
        self.findings
            .findings
            .iter()
            .filter(|f| f.confidence >= 0.9 || f.secret.secret_type.contains("AWS") || f.secret.secret_type.contains("Private Key"))
            .collect()
    }

    /// Export report to JSON
    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CargoCryptError::detection_error(&format!("Failed to serialize report: {}", e)))
    }

    /// Export report to CSV (findings only)
    pub fn to_csv(&self) -> CryptoResult<String> {
        let mut csv = String::new();
        csv.push_str("File,Type,Line,Confidence,Value\n");
        
        for finding in &self.findings.findings {
            csv.push_str(&format!(
                "{},{},{},{:.2},{}\n",
                finding.file_path.display(),
                finding.secret.secret_type,
                finding.secret.line_number,
                finding.confidence * 100.0,
                finding.secret.value
            ));
        }

        Ok(csv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_detector_creation() {
        let detector = SecretDetector::new();
        assert_eq!(detector.name(), "SecretDetector");
    }

    #[test]
    fn test_scan_options() {
        let options = ScanOptions::default();
        assert!(options.sort_by_confidence);
        assert_eq!(options.detection_config.min_confidence, 0.3);

        let source_options = ScanOptions::for_source_code();
        assert_eq!(source_options.max_findings, 100);

        let config_options = ScanOptions::for_config_files();
        assert_eq!(config_options.detection_config.min_confidence, 0.5);
    }

    #[tokio::test]
    async fn test_scan_content() {
        let detector = SecretDetector::new();
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\npassword=very_secret_password";
        
        let findings = detector.scan_content(content, "test.env").unwrap();
        assert!(!findings.is_empty());
        
        // Should find the AWS key
        assert!(findings.iter().any(|f| f.secret.value.contains("AKIA")));
    }

    #[test]
    fn test_detection_config() {
        let config = DetectionConfig::default();
        assert!(config.enable_patterns);
        assert!(config.enable_entropy);
        assert!(config.enable_custom_rules);
        assert_eq!(config.min_confidence, 0.3);
    }

    #[tokio::test]
    async fn test_comprehensive_workflow() {
        // Create a temporary directory with test files
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("config.env");
        
        fs::write(&test_file, "SECRET_KEY=sk_test_1234567890abcdef1234567890abcdef").unwrap();
        
        let detector = SecretDetector::new();
        let options = ScanOptions::for_config_files();
        
        // Test file scanning
        let findings = detector.scan_file(&test_file, &options).await.unwrap();
        assert!(!findings.is_empty());
        
        // Test directory scanning
        let findings = detector.scan_directory(temp_dir.path(), &options).await.unwrap();
        assert!(!findings.is_empty());
        
        // Test report generation
        let report = detector.generate_report(temp_dir.path(), &options).await.unwrap();
        assert!(!report.findings.findings.is_empty());
        assert!(report.scan_time_ms > 0);
    }
}