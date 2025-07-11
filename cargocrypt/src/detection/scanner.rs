//! High-performance file scanning for secret detection
//!
//! This module provides efficient file scanning capabilities with support for
//! parallel processing, smart filtering, and various file type handling.

use crate::detection::{
    Finding, FoundSecret, 
    patterns::PatternRegistry, 
    entropy::EntropyAnalyzer, 
    rules::RuleEngine
};
use crate::error::{CargoCryptError, CryptoResult};
use ignore::{Walk, WalkBuilder};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

/// Configuration for file scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Maximum file size to scan (in bytes)
    pub max_file_size: u64,
    /// Whether to follow symbolic links
    pub follow_links: bool,
    /// Whether to scan hidden files
    pub scan_hidden: bool,
    /// File extensions to include (empty = all)
    pub include_extensions: Vec<String>,
    /// File extensions to exclude
    pub exclude_extensions: Vec<String>,
    /// Paths to exclude
    pub exclude_paths: Vec<String>,
    /// Whether to use parallel processing
    pub parallel: bool,
    /// Number of threads for parallel processing
    pub num_threads: Option<usize>,
    /// Whether to respect .gitignore files
    pub respect_gitignore: bool,
    /// Maximum depth to scan
    pub max_depth: Option<usize>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            max_file_size: 10 * 1024 * 1024, // 10MB
            follow_links: false,
            scan_hidden: false,
            include_extensions: Vec::new(),
            exclude_extensions: vec![
                // Binary files
                "exe".to_string(), "dll".to_string(), "so".to_string(), "dylib".to_string(),
                "bin".to_string(), "obj".to_string(), "lib".to_string(), "a".to_string(),
                // Images
                "png".to_string(), "jpg".to_string(), "jpeg".to_string(), "gif".to_string(),
                "bmp".to_string(), "svg".to_string(), "ico".to_string(),
                // Videos
                "mp4".to_string(), "avi".to_string(), "mov".to_string(), "wmv".to_string(),
                // Archives
                "zip".to_string(), "tar".to_string(), "gz".to_string(), "rar".to_string(),
                "7z".to_string(), "bz2".to_string(),
                // Documents
                "pdf".to_string(), "doc".to_string(), "docx".to_string(), "xls".to_string(),
                "xlsx".to_string(), "ppt".to_string(), "pptx".to_string(),
            ],
            exclude_paths: vec![
                "node_modules".to_string(),
                "target".to_string(),
                ".git".to_string(),
                ".svn".to_string(),
                ".hg".to_string(),
                "build".to_string(),
                "dist".to_string(),
                "vendor".to_string(),
                ".cargo".to_string(),
            ],
            parallel: true,
            num_threads: None, // Use default from rayon
            respect_gitignore: true,
            max_depth: None,
        }
    }
}

impl ScanConfig {
    /// Create a configuration optimized for source code scanning
    pub fn for_source_code() -> Self {
        let mut config = Self::default();
        config.include_extensions = vec![
            // Common source code extensions
            "rs".to_string(), "py".to_string(), "js".to_string(), "ts".to_string(),
            "go".to_string(), "java".to_string(), "c".to_string(), "cpp".to_string(),
            "h".to_string(), "hpp".to_string(), "cs".to_string(), "php".to_string(),
            "rb".to_string(), "swift".to_string(), "kt".to_string(), "scala".to_string(),
            // Configuration files
            "json".to_string(), "yaml".to_string(), "yml".to_string(), "toml".to_string(),
            "ini".to_string(), "cfg".to_string(), "conf".to_string(), "config".to_string(),
            // Environment and script files
            "env".to_string(), "sh".to_string(), "bash".to_string(), "zsh".to_string(),
            "ps1".to_string(), "bat".to_string(), "cmd".to_string(),
        ];
        config
    }

    /// Create a configuration for configuration files only
    pub fn for_config_files() -> Self {
        let mut config = Self::default();
        config.include_extensions = vec![
            "env".to_string(), "json".to_string(), "yaml".to_string(), "yml".to_string(),
            "toml".to_string(), "ini".to_string(), "cfg".to_string(), "conf".to_string(),
            "config".to_string(), "properties".to_string(),
        ];
        config.scan_hidden = true; // Often config files are hidden
        config
    }

    /// Enable scanning of all file types (use with caution)
    pub fn scan_all_files(mut self) -> Self {
        self.include_extensions.clear();
        self.exclude_extensions.clear();
        self
    }

    /// Set maximum file size
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Enable or disable parallel processing
    pub fn with_parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Set number of threads for parallel processing
    pub fn with_threads(mut self, threads: usize) -> Self {
        self.num_threads = Some(threads);
        self
    }
}

/// Result of scanning a single file
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Path of the scanned file
    pub file_path: PathBuf,
    /// Findings from the scan
    pub findings: Vec<Finding>,
    /// Time taken to scan this file (milliseconds)
    pub scan_time_ms: u64,
    /// Size of the file in bytes
    pub file_size: u64,
    /// Whether the file was skipped
    pub skipped: bool,
    /// Reason for skipping (if applicable)
    pub skip_reason: Option<String>,
}

impl ScanResult {
    /// Create a new scan result
    pub fn new(file_path: PathBuf) -> Self {
        Self {
            file_path,
            findings: Vec::new(),
            scan_time_ms: 0,
            file_size: 0,
            skipped: false,
            skip_reason: None,
        }
    }

    /// Mark as skipped with reason
    pub fn skipped_with_reason(mut self, reason: String) -> Self {
        self.skipped = true;
        self.skip_reason = Some(reason);
        self
    }

    /// Add findings to the result
    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }

    /// Set scan time
    pub fn with_scan_time(mut self, time_ms: u64) -> Self {
        self.scan_time_ms = time_ms;
        self
    }

    /// Set file size
    pub fn with_file_size(mut self, size: u64) -> Self {
        self.file_size = size;
        self
    }
}

/// High-performance file scanner
pub struct FileScanner {
    pattern_registry: Arc<PatternRegistry>,
    entropy_analyzer: Arc<EntropyAnalyzer>,
    rule_engine: Arc<RuleEngine>,
    config: ScanConfig,
}

impl FileScanner {
    /// Create a new file scanner
    pub fn new(config: ScanConfig) -> CryptoResult<Self> {
        let pattern_registry = Arc::new(PatternRegistry::new()
            .map_err(|e| CargoCryptError::detection_error(&format!("Failed to create pattern registry: {}", e)))?);
        let entropy_analyzer = Arc::new(EntropyAnalyzer::new());
        let rule_engine = Arc::new(RuleEngine::new());

        Ok(Self {
            pattern_registry,
            entropy_analyzer,
            rule_engine,
            config,
        })
    }

    /// Create a scanner with custom components
    pub fn with_components(
        pattern_registry: PatternRegistry,
        entropy_analyzer: EntropyAnalyzer,
        rule_engine: RuleEngine,
        config: ScanConfig,
    ) -> Self {
        Self {
            pattern_registry: Arc::new(pattern_registry),
            entropy_analyzer: Arc::new(entropy_analyzer),
            rule_engine: Arc::new(rule_engine),
            config,
        }
    }

    /// Scan a single file
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> CryptoResult<ScanResult> {
        let path = path.as_ref();
        let start_time = Instant::now();
        
        // Check if file should be scanned
        if let Some(skip_reason) = self.should_skip_file(path)? {
            return Ok(ScanResult::new(path.to_path_buf())
                .skipped_with_reason(skip_reason));
        }

        // Read file content
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => {
                return Ok(ScanResult::new(path.to_path_buf())
                    .skipped_with_reason(format!("Failed to read file: {}", e)));
            }
        };

        let file_size = content.len() as u64;

        // Scan for secrets
        let findings = self.scan_content(&content, path)?;
        
        let scan_time_ms = start_time.elapsed().as_millis() as u64;

        Ok(ScanResult::new(path.to_path_buf())
            .with_findings(findings)
            .with_scan_time(scan_time_ms)
            .with_file_size(file_size))
    }

    /// Scan a directory
    pub fn scan_directory<P: AsRef<Path>>(&self, path: P) -> CryptoResult<Vec<ScanResult>> {
        let start_time = Instant::now();
        
        // Build the walker
        let mut builder = WalkBuilder::new(path.as_ref());
        builder
            .follow_links(self.config.follow_links)
            .hidden(!self.config.scan_hidden)
            .ignore(self.config.respect_gitignore)
            .git_ignore(self.config.respect_gitignore);

        if let Some(max_depth) = self.config.max_depth {
            builder.max_depth(Some(max_depth));
        }

        // Collect files to scan
        let files: Vec<PathBuf> = builder
            .build()
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                
                if path.is_file() {
                    Some(path.to_path_buf())
                } else {
                    None
                }
            })
            .collect();

        // Scan files
        let results = if self.config.parallel {
            // Configure rayon thread pool if specified
            if let Some(num_threads) = self.config.num_threads {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(num_threads)
                    .build()
                    .map_err(|e| CargoCryptError::detection_error(&format!("Failed to create thread pool: {}", e)))?
                    .install(|| {
                        files.par_iter()
                            .map(|file| self.scan_file(file))
                            .collect::<Result<Vec<_>, _>>()
                    })?
            } else {
                files.par_iter()
                    .map(|file| self.scan_file(file))
                    .collect::<Result<Vec<_>, _>>()?
            }
        } else {
            files.iter()
                .map(|file| self.scan_file(file))
                .collect::<Result<Vec<_>, _>>()?
        };

        tracing::info!(
            "Scanned {} files in {:.2}s",
            results.len(),
            start_time.elapsed().as_secs_f64()
        );

        Ok(results)
    }

    /// Scan content for secrets
    pub fn scan_content(&self, content: &str, file_path: &Path) -> CryptoResult<Vec<Finding>> {
        let mut findings = Vec::new();

        // 1. Pattern-based detection
        let pattern_matches = self.pattern_registry.find_all_matches(content);
        for pattern_match in pattern_matches {
            let line_info = self.get_line_info(content, pattern_match.start);
            let context_lines = self.get_context_lines(content, line_info.line_number, 2);
            
            let secret = FoundSecret::new(
                pattern_match.matched_text.clone(),
                pattern_match.secret_type.to_string(),
                pattern_match.start,
                pattern_match.end,
                line_info.line_number,
                line_info.column_number,
            );

            // Adjust confidence based on context
            let context_text = context_lines.join(" ");
            let adjusted_confidence = self.adjust_confidence_with_context(
                pattern_match.base_confidence,
                &pattern_match.matched_text,
                &context_text,
            );

            let finding = Finding::new(
                file_path.to_path_buf(),
                secret,
                adjusted_confidence,
                "pattern_matcher".to_string(),
            )
            .with_context_lines(context_lines)
            .with_entropy_score(
                self.entropy_analyzer.analyze(&pattern_match.matched_text).shannon_entropy
            );

            findings.push(finding);
        }

        // 2. Custom rule-based detection
        let rule_matches = self.rule_engine.execute_rules(content, Some(&file_path.to_string_lossy()))?;
        for rule_match in rule_matches {
            let line_info = self.get_line_info(content, rule_match.start);
            let context_lines = self.get_context_lines(content, line_info.line_number, 2);
            
            let secret = FoundSecret::new(
                rule_match.matched_text.clone(),
                "custom_rule".to_string(),
                rule_match.start,
                rule_match.end,
                line_info.line_number,
                line_info.column_number,
            );

            let finding = Finding::new(
                file_path.to_path_buf(),
                secret,
                rule_match.confidence,
                rule_match.rule_id,
            )
            .with_context_lines(context_lines);

            findings.push(finding);
        }

        // 3. High-entropy string detection
        let entropy_candidates = self.entropy_analyzer.extract_high_entropy_substrings(content, 12);
        for (substring, entropy_result) in entropy_candidates {
            // Skip if already found by pattern matching
            if findings.iter().any(|f| f.secret.value.contains(&substring)) {
                continue;
            }

            if let Some(start) = content.find(&substring) {
                let line_info = self.get_line_info(content, start);
                let context_lines = self.get_context_lines(content, line_info.line_number, 2);
                
                let secret = FoundSecret::new(
                    substring.clone(),
                    "high_entropy".to_string(),
                    start,
                    start + substring.len(),
                    line_info.line_number,
                    line_info.column_number,
                );

                let finding = Finding::new(
                    file_path.to_path_buf(),
                    secret,
                    entropy_result.confidence,
                    "entropy_analyzer".to_string(),
                )
                .with_context_lines(context_lines)
                .with_entropy_score(entropy_result.shannon_entropy);

                findings.push(finding);
            }
        }

        // Sort findings by confidence (highest first)
        findings.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());

        Ok(findings)
    }

    /// Check if a file should be skipped
    fn should_skip_file(&self, path: &Path) -> CryptoResult<Option<String>> {
        // Check file size
        let metadata = fs::metadata(path)?;
        if metadata.len() > self.config.max_file_size {
            return Ok(Some(format!("File too large: {} bytes", metadata.len())));
        }

        // Check if it's a regular file
        if !metadata.is_file() {
            return Ok(Some("Not a regular file".to_string()));
        }

        // Check extension
        if let Some(extension) = path.extension().and_then(|ext| ext.to_str()) {
            let extension = extension.to_lowercase();
            
            // Check include list (if specified)
            if !self.config.include_extensions.is_empty() &&
               !self.config.include_extensions.contains(&extension) {
                return Ok(Some(format!("Extension not in include list: {}", extension)));
            }
            
            // Check exclude list
            if self.config.exclude_extensions.contains(&extension) {
                return Ok(Some(format!("Extension in exclude list: {}", extension)));
            }
        }

        // Check path exclusions
        let path_str = path.to_string_lossy().to_lowercase();
        for exclude_path in &self.config.exclude_paths {
            if path_str.contains(&exclude_path.to_lowercase()) {
                return Ok(Some(format!("Path contains excluded component: {}", exclude_path)));
            }
        }

        Ok(None)
    }

    /// Get line and column information for a position
    fn get_line_info(&self, content: &str, position: usize) -> LineInfo {
        let mut line_number = 1;
        let mut column_number = 1;
        let mut current_pos = 0;

        for ch in content.chars() {
            if current_pos >= position {
                break;
            }

            if ch == '\n' {
                line_number += 1;
                column_number = 1;
            } else {
                column_number += 1;
            }

            current_pos += ch.len_utf8();
        }

        LineInfo {
            line_number,
            column_number,
        }
    }

    /// Get context lines around a specific line
    fn get_context_lines(&self, content: &str, line_number: usize, context: usize) -> Vec<String> {
        let lines: Vec<&str> = content.lines().collect();
        let start = line_number.saturating_sub(context + 1);
        let end = std::cmp::min(line_number + context, lines.len());

        lines[start..end]
            .iter()
            .map(|&line| line.to_string())
            .collect()
    }

    /// Adjust confidence based on context
    fn adjust_confidence_with_context(
        &self,
        base_confidence: f64,
        matched_text: &str,
        context: &str,
    ) -> f64 {
        let mut confidence = base_confidence;
        let context_lower = context.to_lowercase();
        let matched_lower = matched_text.to_lowercase();

        // Decrease confidence for test/example content
        let test_indicators = [
            "test", "example", "sample", "placeholder", "dummy", "fake",
            "mock", "demo", "todo", "fixme", "changeme",
        ];

        for indicator in &test_indicators {
            if context_lower.contains(indicator) || matched_lower.contains(indicator) {
                confidence -= 0.2;
            }
        }

        // Decrease confidence for comments
        if context.trim_start().starts_with("//") ||
           context.trim_start().starts_with("#") ||
           context.trim_start().starts_with("/*") {
            confidence -= 0.1;
        }

        // Increase confidence for configuration-like contexts
        let config_indicators = [
            "config", "settings", "env", "environment", "production", "prod",
            "staging", "live", "secret", "key", "token", "password",
        ];

        for indicator in &config_indicators {
            if context_lower.contains(indicator) {
                confidence += 0.1;
            }
        }

        confidence.max(0.0).min(1.0)
    }
}

/// Line information for positioning
#[derive(Debug, Clone)]
struct LineInfo {
    line_number: usize,
    column_number: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_scan_config_creation() {
        let config = ScanConfig::default();
        assert!(config.parallel);
        assert!(config.respect_gitignore);
        assert!(!config.scan_hidden);

        let source_config = ScanConfig::for_source_code();
        assert!(source_config.include_extensions.contains(&"rs".to_string()));
        assert!(source_config.include_extensions.contains(&"py".to_string()));
    }

    #[test]
    fn test_should_skip_file() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        
        // This test would need actual files to be meaningful
        // In practice, we'd create temporary files with different extensions
    }

    #[tokio::test]
    async fn test_scan_content() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSECRET=my_secret_value";
        let path = Path::new("test.env");
        
        let findings = scanner.scan_content(content, path).unwrap();
        assert!(!findings.is_empty());
        
        // Should find the AWS key
        assert!(findings.iter().any(|f| f.secret.value.contains("AKIA")));
    }

    #[test]
    fn test_line_info_calculation() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        let content = "line 1\nline 2\nline 3 with secret";
        
        let line_info = scanner.get_line_info(content, content.find("secret").unwrap());
        assert_eq!(line_info.line_number, 3);
        assert!(line_info.column_number > 10);
    }

    #[test]
    fn test_context_lines() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        let content = "line 1\nline 2\nline 3\nline 4\nline 5";
        
        let context = scanner.get_context_lines(content, 3, 1);
        assert_eq!(context.len(), 3); // line 2, 3, 4
        assert_eq!(context[1], "line 3");
    }

    #[test]
    fn test_confidence_adjustment() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        
        // Should decrease confidence for test content
        let adjusted = scanner.adjust_confidence_with_context(
            0.9,
            "test_secret",
            "this is a test example",
        );
        assert!(adjusted < 0.9);

        // Should increase confidence for config content
        let adjusted = scanner.adjust_confidence_with_context(
            0.7,
            "real_secret",
            "production config secret",
        );
        assert!(adjusted > 0.7);
    }
}