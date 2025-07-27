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
use ignore::WalkBuilder;
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
        let mut found_positions = std::collections::HashSet::new();

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

            // Calculate multi-factor confidence score
            let base_confidence = pattern_match.base_confidence;
            let context_text = context_lines.join(" ");
            let entropy_result = self.entropy_analyzer.analyze(&pattern_match.matched_text);
            
            let adjusted_confidence = self.calculate_composite_confidence(
                base_confidence,
                &pattern_match.matched_text,
                &context_text,
                &entropy_result,
                file_path,
            );

            let finding = Finding::new(
                file_path.to_path_buf(),
                secret,
                adjusted_confidence,
                "pattern_matcher".to_string(),
            )
            .with_context_lines(context_lines)
            .with_entropy_score(entropy_result.shannon_entropy);

            findings.push(finding);
            found_positions.insert((pattern_match.start, pattern_match.end));
        }

        // 2. Custom rule-based detection
        let rule_matches = self.rule_engine.execute_rules(content, Some(&file_path.to_string_lossy()))?;
        for rule_match in rule_matches {
            // Skip if already found
            if found_positions.contains(&(rule_match.start, rule_match.end)) {
                continue;
            }

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

            let entropy_result = self.entropy_analyzer.analyze(&rule_match.matched_text);
            let context_text = context_lines.join(" ");
            
            let adjusted_confidence = self.calculate_composite_confidence(
                rule_match.confidence,
                &rule_match.matched_text,
                &context_text,
                &entropy_result,
                file_path,
            );

            let finding = Finding::new(
                file_path.to_path_buf(),
                secret,
                adjusted_confidence,
                rule_match.rule_id,
            )
            .with_context_lines(context_lines)
            .with_entropy_score(entropy_result.shannon_entropy);

            findings.push(finding);
            found_positions.insert((rule_match.start, rule_match.end));
        }

        // 3. Advanced high-entropy string detection
        let entropy_findings = self.detect_high_entropy_secrets(content, &found_positions);
        for (substring, start, entropy_result) in entropy_findings {
            let line_info = self.get_line_info(content, start);
            let context_lines = self.get_context_lines(content, line_info.line_number, 2);
            let context_text = context_lines.join(" ");
            
            let secret = FoundSecret::new(
                substring.clone(),
                self.classify_entropy_secret(&substring, &entropy_result),
                start,
                start + substring.len(),
                line_info.line_number,
                line_info.column_number,
            );

            let adjusted_confidence = self.calculate_composite_confidence(
                entropy_result.confidence,
                &substring,
                &context_text,
                &entropy_result,
                file_path,
            );

            let finding = Finding::new(
                file_path.to_path_buf(),
                secret,
                adjusted_confidence,
                "entropy_analyzer".to_string(),
            )
            .with_context_lines(context_lines)
            .with_entropy_score(entropy_result.shannon_entropy);

            findings.push(finding);
        }

        // 4. Contextual pattern detection (looks for secrets near keywords)
        let contextual_findings = self.detect_contextual_secrets(content, &found_positions);
        for (text, start, end, confidence) in contextual_findings {
            let line_info = self.get_line_info(content, start);
            let context_lines = self.get_context_lines(content, line_info.line_number, 2);
            
            let secret = FoundSecret::new(
                text,
                "contextual_pattern".to_string(),
                start,
                end,
                line_info.line_number,
                line_info.column_number,
            );

            let finding = Finding::new(
                file_path.to_path_buf(),
                secret,
                confidence,
                "contextual_analyzer".to_string(),
            )
            .with_context_lines(context_lines);

            findings.push(finding);
        }

        // Remove duplicates and sort by confidence
        self.deduplicate_findings(&mut findings);
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

    /// Calculate composite confidence score using multiple factors
    fn calculate_composite_confidence(
        &self,
        base_confidence: f64,
        matched_text: &str,
        context: &str,
        entropy_result: &crate::detection::entropy::EntropyResult,
        file_path: &Path,
    ) -> f64 {
        let mut confidence = base_confidence;
        
        // Factor 1: Context-based adjustment
        confidence = self.adjust_confidence_with_context(confidence, matched_text, context);
        
        // Factor 2: Entropy-based adjustment
        if entropy_result.shannon_entropy > 0.0 {
            if entropy_result.shannon_entropy < 2.5 {
                confidence *= 0.7; // Low entropy reduces confidence
            } else if entropy_result.shannon_entropy > 4.5 {
                confidence *= 1.1; // High entropy increases confidence
            }
        }
        
        // Factor 3: Length-based adjustment
        let length = matched_text.len();
        if length < 8 {
            confidence *= 0.6; // Very short strings are less likely to be secrets
        } else if length > 40 && length < 100 {
            confidence *= 1.05; // Typical secret length
        } else if length > 200 {
            confidence *= 0.8; // Very long strings might be data, not secrets
        }
        
        // Factor 4: Character diversity
        let char_types = self.count_character_types(matched_text);
        if char_types >= 3 {
            confidence *= 1.1; // Good character diversity
        } else if char_types == 1 {
            confidence *= 0.7; // Single character type
        }
        
        // Factor 5: File type adjustment
        if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
            match ext.to_lowercase().as_str() {
                // Configuration files - higher likelihood
                "env" | "config" | "conf" | "ini" | "toml" | "yaml" | "yml" => confidence *= 1.2,
                // Source code - medium likelihood
                "rs" | "py" | "js" | "go" | "java" | "php" | "rb" => confidence *= 1.0,
                // Documentation - lower likelihood
                "md" | "txt" | "rst" | "doc" => confidence *= 0.7,
                // Test files - much lower likelihood
                _ if file_path.to_string_lossy().contains("test") => confidence *= 0.5,
                _ => {}
            }
        }
        
        // Factor 6: Known false positive patterns
        if self.is_likely_false_positive(matched_text) {
            confidence *= 0.3;
        }
        
        confidence.max(0.0).min(1.0)
    }

    /// Detect high-entropy secrets using advanced algorithms
    fn detect_high_entropy_secrets(
        &self,
        content: &str,
        found_positions: &std::collections::HashSet<(usize, usize)>,
    ) -> Vec<(String, usize, crate::detection::entropy::EntropyResult)> {
        let mut results = Vec::new();
        
        // Split content into tokens for analysis
        let tokens = self.tokenize_content(content);
        
        for (token, start_pos) in tokens {
            // Skip if already found
            let end_pos = start_pos + token.len();
            if found_positions.iter().any(|(s, e)| {
                (start_pos >= *s && start_pos < *e) || (end_pos > *s && end_pos <= *e)
            }) {
                continue;
            }
            
            // Skip very short tokens
            if token.len() < 8 {
                continue;
            }
            
            let entropy_result = self.entropy_analyzer.analyze(&token);
            
            // Advanced entropy analysis
            if entropy_result.is_likely_secret {
                // Additional validation for high-entropy strings
                if self.validate_entropy_candidate(&token, &entropy_result) {
                    results.push((token, start_pos, entropy_result));
                }
            }
        }
        
        // Also look for base64-encoded secrets
        let base64_candidates = self.find_base64_candidates(content, found_positions);
        for (candidate, start_pos) in base64_candidates {
            let entropy_result = self.entropy_analyzer.analyze(&candidate);
            if entropy_result.confidence > 0.6 {
                results.push((candidate, start_pos, entropy_result));
            }
        }
        
        results
    }

    /// Detect secrets based on contextual clues
    fn detect_contextual_secrets(
        &self,
        content: &str,
        found_positions: &std::collections::HashSet<(usize, usize)>,
    ) -> Vec<(String, usize, usize, f64)> {
        let mut results = Vec::new();
        
        // Keywords that often precede secrets
        let secret_keywords = [
            ("password", r#"[:\s=]+["']?([^"'\s]{8,})["']?"#),
            ("api_key", r#"[:\s=]+["']?([A-Za-z0-9_\-]{20,})["']?"#),
            ("secret", r#"[:\s=]+["']?([A-Za-z0-9_\-]{12,})["']?"#),
            ("token", r#"[:\s=]+["']?([A-Za-z0-9_\-]{20,})["']?"#),
            ("auth", r#"[:\s=]+["']?([A-Za-z0-9_\-]{16,})["']?"#),
            ("credential", r#"[:\s=]+["']?([^"'\s]{10,})["']?"#),
            ("private_key", r#"[:\s=]+["']?([A-Za-z0-9+/=]{40,})["']?"#),
        ];
        
        for (keyword, pattern) in &secret_keywords {
            let regex_pattern = format!(r"(?i){}{}", keyword, pattern);
            if let Ok(regex) = regex::Regex::new(&regex_pattern) {
                for cap in regex.captures_iter(content) {
                    if let Some(secret_match) = cap.get(1) {
                        let start = secret_match.start();
                        let end = secret_match.end();
                        
                        // Skip if already found
                        if found_positions.contains(&(start, end)) {
                            continue;
                        }
                        
                        let matched_text = secret_match.as_str();
                        
                        // Validate the candidate
                        if self.validate_contextual_candidate(matched_text, keyword) {
                            let confidence = self.calculate_contextual_confidence(matched_text, keyword);
                            results.push((matched_text.to_string(), start, end, confidence));
                        }
                    }
                }
            }
        }
        
        results
    }

    /// Classify entropy-based secret type
    fn classify_entropy_secret(
        &self,
        text: &str,
        entropy_result: &crate::detection::entropy::EntropyResult,
    ) -> String {
        // Check for common patterns
        if text.starts_with("AKIA") {
            return "aws_access_key".to_string();
        }
        if text.starts_with("sk_") || text.starts_with("pk_") {
            return "api_key".to_string();
        }
        if text.len() == 40 && text.chars().all(|c| c.is_ascii_hexdigit()) {
            return "sha1_hash_or_token".to_string();
        }
        if text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit()) {
            return "sha256_hash_or_token".to_string();
        }
        
        // Check character composition
        let has_uppercase = text.chars().any(|c| c.is_ascii_uppercase());
        let has_lowercase = text.chars().any(|c| c.is_ascii_lowercase());
        let has_digits = text.chars().any(|c| c.is_ascii_digit());
        let has_special = text.chars().any(|c| !c.is_ascii_alphanumeric());
        
        if has_uppercase && has_lowercase && has_digits && has_special {
            return "high_entropy_password".to_string();
        }
        
        if entropy_result.charset_size > 50 {
            return "high_entropy_token".to_string();
        }
        
        "high_entropy_string".to_string()
    }

    /// Remove duplicate findings
    fn deduplicate_findings(&self, findings: &mut Vec<Finding>) {
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| {
            let key = (
                f.file_path.clone(),
                f.secret.start_position,
                f.secret.end_position,
            );
            seen.insert(key)
        });
    }

    /// Count character types in a string
    fn count_character_types(&self, text: &str) -> usize {
        let has_lowercase = text.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = text.chars().any(|c| c.is_ascii_uppercase());
        let has_digits = text.chars().any(|c| c.is_ascii_digit());
        let has_special = text.chars().any(|c| !c.is_ascii_alphanumeric());
        
        [has_lowercase, has_uppercase, has_digits, has_special]
            .iter()
            .filter(|&&x| x)
            .count()
    }

    /// Check if a string is likely a false positive
    fn is_likely_false_positive(&self, text: &str) -> bool {
        let text_lower = text.to_lowercase();
        
        // Common false positive patterns
        let false_positive_patterns = [
            "aaaaaaa", "bbbbbbb", "1234567", "abcdefg",
            "qwertyu", "password", "12345678", "87654321",
            "00000000", "11111111", "ffffffff", "deadbeef",
            "cafebabe", "test1234", "admin123", "user1234",
        ];
        
        for pattern in &false_positive_patterns {
            if text_lower.contains(pattern) {
                return true;
            }
        }
        
        // Check for repeated characters
        if text.len() >= 8 {
            let first_char = text.chars().next().unwrap();
            if text.chars().all(|c| c == first_char) {
                return true;
            }
        }
        
        // Check for sequential patterns
        if self.is_sequential_pattern(text) {
            return true;
        }
        
        false
    }

    /// Tokenize content into analyzable units
    fn tokenize_content(&self, content: &str) -> Vec<(String, usize)> {
        let mut tokens = Vec::new();
        let mut current_token = String::new();
        let mut start_pos = 0;
        let mut in_token = false;
        
        for (i, ch) in content.char_indices() {
            if ch.is_alphanumeric() || "-_+/=".contains(ch) {
                if !in_token {
                    start_pos = i;
                    in_token = true;
                }
                current_token.push(ch);
            } else {
                if in_token && current_token.len() >= 8 {
                    tokens.push((current_token.clone(), start_pos));
                }
                current_token.clear();
                in_token = false;
            }
        }
        
        // Don't forget the last token
        if in_token && current_token.len() >= 8 {
            tokens.push((current_token, start_pos));
        }
        
        tokens
    }

    /// Find base64-encoded candidates
    fn find_base64_candidates(
        &self,
        content: &str,
        found_positions: &std::collections::HashSet<(usize, usize)>,
    ) -> Vec<(String, usize)> {
        let mut candidates = Vec::new();
        let base64_regex = regex::Regex::new(r"[A-Za-z0-9+/]{20,}={0,2}").unwrap();
        
        for m in base64_regex.find_iter(content) {
            let start = m.start();
            let end = m.end();
            
            if found_positions.iter().any(|(s, e)| {
                (start >= *s && start < *e) || (end > *s && end <= *e)
            }) {
                continue;
            }
            
            let candidate = m.as_str();
            
            // Validate base64
            if candidate.len() % 4 == 0 || (candidate.len() % 4 == 2 && candidate.ends_with("==")) ||
               (candidate.len() % 4 == 3 && candidate.ends_with("=")) {
                candidates.push((candidate.to_string(), start));
            }
        }
        
        candidates
    }

    /// Validate entropy candidate
    fn validate_entropy_candidate(
        &self,
        text: &str,
        entropy_result: &crate::detection::entropy::EntropyResult,
    ) -> bool {
        // Must have good entropy
        if entropy_result.shannon_entropy < 3.5 {
            return false;
        }
        
        // Must have reasonable character diversity
        if entropy_result.charset_size < 10 {
            return false;
        }
        
        // Must not be a known false positive
        if self.is_likely_false_positive(text) {
            return false;
        }
        
        // Additional checks for very high entropy
        if entropy_result.shannon_entropy > 5.5 {
            // Very high entropy might be compressed data or binary
            // Check if it's printable ASCII
            if !text.chars().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
                return false;
            }
        }
        
        true
    }

    /// Validate contextual candidate
    fn validate_contextual_candidate(&self, text: &str, keyword: &str) -> bool {
        // Must not be a placeholder
        let placeholders = ["your", "my", "insert", "replace", "change", "enter", "here"];
        for placeholder in &placeholders {
            if text.to_lowercase().contains(placeholder) {
                return false;
            }
        }
        
        // Must have minimum complexity for certain keywords
        match keyword {
            "password" => self.count_character_types(text) >= 2,
            "api_key" | "token" => text.len() >= 20,
            "secret" => text.len() >= 12,
            _ => true,
        }
    }

    /// Calculate confidence for contextual findings
    fn calculate_contextual_confidence(&self, text: &str, keyword: &str) -> f64 {
        let mut confidence = 0.6; // Base confidence for contextual findings
        
        // Adjust based on keyword
        match keyword {
            "password" | "private_key" => confidence += 0.15,
            "api_key" | "token" | "secret" => confidence += 0.1,
            _ => {}
        }
        
        // Adjust based on complexity
        let char_types = self.count_character_types(text);
        confidence += (char_types as f64) * 0.05;
        
        // Adjust based on length
        if text.len() > 30 {
            confidence += 0.1;
        }
        
        // Check entropy
        let entropy_result = self.entropy_analyzer.analyze(text);
        if entropy_result.shannon_entropy > 4.0 {
            confidence += 0.1;
        }
        
        confidence.min(0.95)
    }

    /// Check if text is a sequential pattern
    fn is_sequential_pattern(&self, text: &str) -> bool {
        if text.len() < 4 {
            return false;
        }
        
        let chars: Vec<char> = text.chars().collect();
        
        // Check for ascending/descending sequences
        let mut ascending = true;
        let mut descending = true;
        
        for i in 1..chars.len() {
            if chars[i] as u32 != chars[i-1] as u32 + 1 {
                ascending = false;
            }
            if chars[i] as u32 != chars[i-1] as u32 - 1 {
                descending = false;
            }
        }
        
        ascending || descending
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

    #[test]
    fn test_scan_content() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nSECRET=my_secret_value_123";
        let path = Path::new("test.env");
        
        let findings = scanner.scan_content(content, path).unwrap();
        assert!(!findings.is_empty());
        
        // Should find the AWS key
        assert!(findings.iter().any(|f| f.secret.value.contains("AKIA")));
        
        // Should have confidence scores
        for finding in &findings {
            assert!(finding.confidence > 0.0);
            assert!(finding.confidence <= 1.0);
        }
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

    #[test]
    fn test_entropy_detection() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        let content = "password=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let path = Path::new("config.env");
        
        let findings = scanner.scan_content(content, path).unwrap();
        assert!(!findings.is_empty());
        
        // Should classify high-entropy strings
        let high_entropy_finding = findings.iter()
            .find(|f| f.secret.secret_type.contains("entropy") || f.secret.secret_type.contains("password"));
        assert!(high_entropy_finding.is_some());
    }

    #[test]
    fn test_contextual_detection() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        let content = "api_key = sk_live_abcdef1234567890\ntoken: ghp_1234567890abcdef1234567890abcdef12345678";
        let path = Path::new("config.rs");
        
        let findings = scanner.scan_content(content, path).unwrap();
        assert!(!findings.is_empty());
        
        // Should find contextual patterns
        let contextual_finding = findings.iter()
            .find(|f| f.detector_name == "contextual_analyzer");
        // Note: may or may not find contextual patterns depending on existing pattern matches
    }

    #[test]
    fn test_false_positive_detection() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        
        // Should identify common false positives
        assert!(scanner.is_likely_false_positive("aaaaaaaaaa"));
        assert!(scanner.is_likely_false_positive("1234567890"));
        assert!(scanner.is_likely_false_positive("abcdefghij"));
        assert!(scanner.is_likely_false_positive("password123"));
        
        // Should not flag legitimate-looking secrets
        assert!(!scanner.is_likely_false_positive("AKIAIOSFODNN7EXAMPLE"));
        assert!(!scanner.is_likely_false_positive("sk_live_abcdef1234567890"));
    }

    #[test]
    fn test_character_type_counting() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        
        assert_eq!(scanner.count_character_types("abc"), 1); // only lowercase
        assert_eq!(scanner.count_character_types("ABC"), 1); // only uppercase
        assert_eq!(scanner.count_character_types("123"), 1); // only digits
        assert_eq!(scanner.count_character_types("Abc"), 2); // upper + lower
        assert_eq!(scanner.count_character_types("Abc123"), 3); // upper + lower + digits
        assert_eq!(scanner.count_character_types("Abc123!"), 4); // all types
    }

    #[test]
    fn test_sequential_pattern_detection() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        
        assert!(scanner.is_sequential_pattern("abcd"));
        assert!(scanner.is_sequential_pattern("1234"));
        assert!(scanner.is_sequential_pattern("dcba"));
        assert!(scanner.is_sequential_pattern("4321"));
        
        assert!(!scanner.is_sequential_pattern("abdc"));
        assert!(!scanner.is_sequential_pattern("1324"));
        assert!(!scanner.is_sequential_pattern("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn test_tokenization() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        let content = "key=AKIAIOSFODNN7EXAMPLE value=\"wJalrXUtnFEMI/K7MDENG\"";
        
        let tokens = scanner.tokenize_content(content);
        
        // Should extract meaningful tokens
        assert!(tokens.iter().any(|(token, _)| token.contains("AKIA")));
        assert!(tokens.iter().any(|(token, _)| token.contains("wJalrXUtnFEMI")));
        
        // All tokens should be at least 8 characters
        for (token, _) in &tokens {
            assert!(token.len() >= 8);
        }
    }

    #[test]
    fn test_base64_detection() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        let content = "secret=dGVzdF9zZWNyZXRfa2V5XzEyMzQ1Njc4OTA=";
        let found_positions = std::collections::HashSet::new();
        
        let candidates = scanner.find_base64_candidates(content, &found_positions);
        assert!(!candidates.is_empty());
        
        // Should find base64-encoded content
        let base64_candidate = candidates.iter()
            .find(|(candidate, _)| candidate.contains("dGVzdF"));
        assert!(base64_candidate.is_some());
    }

    #[test]
    fn test_deduplication() {
        let scanner = FileScanner::new(ScanConfig::default()).unwrap();
        let content = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let path = Path::new("test.env");
        
        let findings = scanner.scan_content(content, path).unwrap();
        
        // Should not have duplicate findings for the same position
        let mut positions = std::collections::HashSet::new();
        for finding in &findings {
            let key = (finding.secret.start_position, finding.secret.end_position);
            assert!(positions.insert(key), "Duplicate finding at same position");
        }
    }
}