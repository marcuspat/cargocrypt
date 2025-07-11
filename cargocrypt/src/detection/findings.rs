//! Detection findings and result types

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Confidence level for detection results
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// Very low confidence (0.0-0.3) - likely false positive
    VeryLow,
    /// Low confidence (0.3-0.5) - needs review
    Low,
    /// Medium confidence (0.5-0.7) - probable secret
    Medium,
    /// High confidence (0.7-0.9) - very likely secret
    High,
    /// Very high confidence (0.9-1.0) - almost certainly secret
    VeryHigh,
}

impl ConfidenceLevel {
    /// Convert a confidence score to a confidence level
    pub fn from_score(score: f64) -> Self {
        match score {
            s if s < 0.3 => ConfidenceLevel::VeryLow,
            s if s < 0.5 => ConfidenceLevel::Low,
            s if s < 0.7 => ConfidenceLevel::Medium,
            s if s < 0.9 => ConfidenceLevel::High,
            _ => ConfidenceLevel::VeryHigh,
        }
    }

    /// Get the numeric range for this confidence level
    pub fn score_range(&self) -> (f64, f64) {
        match self {
            ConfidenceLevel::VeryLow => (0.0, 0.3),
            ConfidenceLevel::Low => (0.3, 0.5),
            ConfidenceLevel::Medium => (0.5, 0.7),
            ConfidenceLevel::High => (0.7, 0.9),
            ConfidenceLevel::VeryHigh => (0.9, 1.0),
        }
    }
}

/// A detected secret with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundSecret {
    /// The detected secret value (may be truncated for security)
    pub value: String,
    /// Type of secret detected
    pub secret_type: String,
    /// Start position in the file content
    pub start_position: usize,
    /// End position in the file content
    pub end_position: usize,
    /// Line number where the secret was found
    pub line_number: usize,
    /// Column number where the secret starts
    pub column_number: usize,
    /// Whether the value was truncated for security
    pub is_truncated: bool,
}

impl FoundSecret {
    /// Create a new found secret
    pub fn new(
        value: String,
        secret_type: String,
        start_position: usize,
        end_position: usize,
        line_number: usize,
        column_number: usize,
    ) -> Self {
        let is_truncated = value.len() > 50;
        let value = if is_truncated {
            format!("{}...", &value[..47])
        } else {
            value
        };

        Self {
            value,
            secret_type,
            start_position,
            end_position,
            line_number,
            column_number,
            is_truncated,
        }
    }

    /// Get the length of the original secret
    pub fn length(&self) -> usize {
        self.end_position - self.start_position
    }
}

/// A detection finding with confidence scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// The file where the secret was found
    pub file_path: PathBuf,
    /// The detected secret
    pub secret: FoundSecret,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Confidence level
    pub confidence_level: ConfidenceLevel,
    /// Rule or pattern that detected this secret
    pub detector_name: String,
    /// Additional context about the detection
    pub context: Option<String>,
    /// Whether this finding should be ignored
    pub is_ignored: bool,
    /// Entropy score of the detected value
    pub entropy_score: Option<f64>,
    /// Surrounding context lines for review
    pub context_lines: Vec<String>,
}

impl Finding {
    /// Create a new finding
    pub fn new(
        file_path: PathBuf,
        secret: FoundSecret,
        confidence: f64,
        detector_name: String,
    ) -> Self {
        let confidence_level = ConfidenceLevel::from_score(confidence);
        
        Self {
            file_path,
            secret,
            confidence,
            confidence_level,
            detector_name,
            context: None,
            is_ignored: false,
            entropy_score: None,
            context_lines: Vec::new(),
        }
    }

    /// Set additional context for this finding
    pub fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
    }

    /// Set entropy score
    pub fn with_entropy_score(mut self, entropy: f64) -> Self {
        self.entropy_score = Some(entropy);
        self
    }

    /// Set context lines
    pub fn with_context_lines(mut self, lines: Vec<String>) -> Self {
        self.context_lines = lines;
        self
    }

    /// Mark this finding as ignored
    pub fn ignore(mut self) -> Self {
        self.is_ignored = true;
        self
    }

    /// Check if this is a high-confidence finding
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.7
    }

    /// Check if this finding should be reported
    pub fn should_report(&self) -> bool {
        !self.is_ignored && self.confidence >= 0.3
    }

    /// Get a summary string for this finding
    pub fn summary(&self) -> String {
        format!(
            "{} in {} (line {}, confidence: {:.1}%)",
            self.secret.secret_type,
            self.file_path.display(),
            self.secret.line_number,
            self.confidence * 100.0
        )
    }

    /// Get a detailed description
    pub fn description(&self) -> String {
        let mut desc = format!(
            "Found {} in {} at line {} (confidence: {:.1}%)",
            self.secret.secret_type,
            self.file_path.display(),
            self.secret.line_number,
            self.confidence * 100.0
        );

        if let Some(entropy) = self.entropy_score {
            desc.push_str(&format!(", entropy: {:.2}", entropy));
        }

        if let Some(context) = &self.context {
            desc.push_str(&format!(", context: {}", context));
        }

        desc
    }
}

/// Collection of findings with utility methods
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FindingCollection {
    /// All findings
    pub findings: Vec<Finding>,
    /// Scan statistics
    pub stats: ScanStats,
}

/// Statistics about a scan operation
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ScanStats {
    /// Number of files scanned
    pub files_scanned: usize,
    /// Number of files skipped
    pub files_skipped: usize,
    /// Total time taken (milliseconds)
    pub scan_time_ms: u64,
    /// Number of findings by confidence level
    pub findings_by_confidence: std::collections::HashMap<String, usize>,
    /// Number of findings by secret type
    pub findings_by_type: std::collections::HashMap<String, usize>,
}

impl FindingCollection {
    /// Create a new empty collection
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a finding to the collection
    pub fn add_finding(&mut self, finding: Finding) {
        // Update statistics
        let confidence_key = format!("{:?}", finding.confidence_level);
        *self.stats.findings_by_confidence.entry(confidence_key).or_insert(0) += 1;
        *self.stats.findings_by_type.entry(finding.secret.secret_type.clone()).or_insert(0) += 1;
        
        self.findings.push(finding);
    }

    /// Get findings above a certain confidence threshold
    pub fn high_confidence_findings(&self, threshold: f64) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.confidence >= threshold)
            .collect()
    }

    /// Get findings of a specific type
    pub fn findings_by_type(&self, secret_type: &str) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.secret.secret_type == secret_type)
            .collect()
    }

    /// Get findings that should be reported
    pub fn reportable_findings(&self) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.should_report())
            .collect()
    }

    /// Sort findings by confidence (highest first)
    pub fn sort_by_confidence(&mut self) {
        self.findings.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap());
    }

    /// Get summary statistics
    pub fn summary(&self) -> String {
        let total = self.findings.len();
        let high_confidence = self.high_confidence_findings(0.7).len();
        let reportable = self.reportable_findings().len();

        format!(
            "Found {} potential secrets ({} high confidence, {} reportable) in {} files",
            total, high_confidence, reportable, self.stats.files_scanned
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_confidence_level_from_score() {
        assert_eq!(ConfidenceLevel::from_score(0.1), ConfidenceLevel::VeryLow);
        assert_eq!(ConfidenceLevel::from_score(0.4), ConfidenceLevel::Low);
        assert_eq!(ConfidenceLevel::from_score(0.6), ConfidenceLevel::Medium);
        assert_eq!(ConfidenceLevel::from_score(0.8), ConfidenceLevel::High);
        assert_eq!(ConfidenceLevel::from_score(0.95), ConfidenceLevel::VeryHigh);
    }

    #[test]
    fn test_found_secret_truncation() {
        let long_secret = "a".repeat(100);
        let secret = FoundSecret::new(
            long_secret.clone(),
            "test".to_string(),
            0,
            100,
            1,
            1,
        );
        
        assert!(secret.is_truncated);
        assert!(secret.value.ends_with("..."));
        assert_eq!(secret.length(), 100);
    }

    #[test]
    fn test_finding_confidence_methods() {
        let secret = FoundSecret::new(
            "test_secret".to_string(),
            "api_key".to_string(),
            0,
            11,
            1,
            1,
        );
        
        let finding = Finding::new(
            PathBuf::from("test.rs"),
            secret,
            0.8,
            "test_detector".to_string(),
        );

        assert!(finding.is_high_confidence());
        assert!(finding.should_report());
        assert_eq!(finding.confidence_level, ConfidenceLevel::High);
    }

    #[test]
    fn test_finding_collection() {
        let mut collection = FindingCollection::new();
        
        let secret1 = FoundSecret::new("secret1".to_string(), "api_key".to_string(), 0, 7, 1, 1);
        let finding1 = Finding::new(PathBuf::from("test1.rs"), secret1, 0.9, "detector1".to_string());
        
        let secret2 = FoundSecret::new("secret2".to_string(), "token".to_string(), 0, 7, 1, 1);
        let finding2 = Finding::new(PathBuf::from("test2.rs"), secret2, 0.5, "detector2".to_string());

        collection.add_finding(finding1);
        collection.add_finding(finding2);

        assert_eq!(collection.findings.len(), 2);
        assert_eq!(collection.high_confidence_findings(0.7).len(), 1);
        assert_eq!(collection.findings_by_type("api_key").len(), 1);
        assert_eq!(collection.reportable_findings().len(), 2);
    }
}