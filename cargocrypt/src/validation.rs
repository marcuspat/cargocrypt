//! Input validation and sanitization module
//!
//! Provides comprehensive validation for all user inputs, file paths,
//! configuration values, and cryptographic parameters to ensure system stability.

use crate::error::{CargoCryptError, CryptoResult};
use std::path::{Path, PathBuf};
use regex::Regex;
use std::fs;

/// Validation result with detailed error information
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

/// Specific validation error types
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub severity: ValidationSeverity,
    pub suggestion: Option<String>,
}

/// Severity levels for validation errors
#[derive(Debug, Clone, PartialEq)]
pub enum ValidationSeverity {
    Critical,  // Will prevent operation
    Warning,   // Should be addressed but won't block
    Info,      // Informational only
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, field: &str, message: &str, severity: ValidationSeverity) {
        self.errors.push(ValidationError {
            field: field.to_string(),
            message: message.to_string(),
            severity: severity.clone(),
            suggestion: None,
        });
        
        if severity == ValidationSeverity::Critical {
            self.is_valid = false;
        }
    }

    pub fn add_error_with_suggestion(&mut self, field: &str, message: &str, severity: ValidationSeverity, suggestion: &str) {
        let is_critical = severity == ValidationSeverity::Critical;
        self.errors.push(ValidationError {
            field: field.to_string(),
            message: message.to_string(),
            severity,
            suggestion: Some(suggestion.to_string()),
        });
        
        if is_critical {
            self.is_valid = false;
        }
    }

    pub fn add_warning(&mut self, warning: &str) {
        self.warnings.push(warning.to_string());
    }

    pub fn has_critical_errors(&self) -> bool {
        self.errors.iter().any(|e| e.severity == ValidationSeverity::Critical)
    }
}

/// Input validator for various types of data
#[derive(Debug, Clone)]
pub struct InputValidator {
    file_path_regex: Regex,
    password_regex: Regex,
    config_key_regex: Regex,
}

impl InputValidator {
    pub fn new() -> Self {
        Self {
            // Validate file paths (allow most characters but prevent path traversal)
            file_path_regex: Regex::new(r"^[^<>:|?*\x00-\x1f]*$").unwrap(),
            // Password requirements: 8+ chars, complexity optional but recommended
            password_regex: Regex::new(r"^.{8,}$").unwrap(),
            // Configuration keys: alphanumeric with underscores and dots
            config_key_regex: Regex::new(r"^[a-zA-Z0-9_.]+$").unwrap(),
        }
    }

    /// Validate a file path for safety and accessibility
    pub fn validate_file_path<P: AsRef<Path>>(&self, path: P) -> ValidationResult {
        let mut result = ValidationResult::new();
        let path = path.as_ref();
        let path_str = path.to_string_lossy();

        // Check for empty path
        if path_str.is_empty() {
            result.add_error("path", "File path cannot be empty", ValidationSeverity::Critical);
            return result;
        }

        // Check for path traversal attempts
        if path_str.contains("..") {
            result.add_error(
                "path", 
                "Path traversal detected (..)", 
                ValidationSeverity::Critical
            );
        }

        // Check for invalid characters
        if !self.file_path_regex.is_match(&path_str) {
            result.add_error(
                "path",
                "Path contains invalid characters",
                ValidationSeverity::Critical
            );
        }

        // Check path length (reasonable limit)
        if path_str.len() > 4096 {
            result.add_error(
                "path",
                "Path too long (max 4096 characters)",
                ValidationSeverity::Critical
            );
        }

        // Check if path exists and is accessible
        match fs::metadata(path) {
            Ok(metadata) => {
                if metadata.is_dir() && !path_str.ends_with('/') && !path_str.ends_with('\\') {
                    result.add_warning("Directory path should end with separator");
                }
            }
            Err(_) => {
                // Path doesn't exist - check if parent directory exists
                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        result.add_error(
                            "path",
                            "Parent directory does not exist",
                            ValidationSeverity::Critical
                        );
                    }
                }
            }
        }

        result
    }

    /// Validate a password for strength and security
    pub fn validate_password(&self, password: &str) -> ValidationResult {
        let mut result = ValidationResult::new();

        // Check minimum length
        if !self.password_regex.is_match(password) {
            result.add_error_with_suggestion(
                "password",
                "Password must be at least 8 characters long",
                ValidationSeverity::Critical,
                "Use a longer password with mixed case, numbers, and symbols"
            );
        }

        // Check for common weak passwords
        let weak_passwords = ["password", "12345678", "qwerty123", "admin123"];
        if weak_passwords.iter().any(|&weak| password.to_lowercase().contains(weak)) {
            result.add_error(
                "password",
                "Password appears to contain common weak patterns",
                ValidationSeverity::Warning
            );
        }

        // Strength recommendations
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        let strength_score = [has_upper, has_lower, has_digit, has_special]
            .iter()
            .map(|&b| if b { 1 } else { 0 })
            .sum::<i32>();

        match strength_score {
            0..=1 => result.add_error(
                "password",
                "Password is very weak",
                ValidationSeverity::Warning
            ),
            2 => result.add_warning("Password is weak - consider adding more character types"),
            3 => result.add_warning("Password is moderate strength"),
            4 => {} // Strong password
            _ => unreachable!(),
        }

        result
    }

    /// Validate configuration values
    pub fn validate_config_value(&self, key: &str, value: &str) -> ValidationResult {
        let mut result = ValidationResult::new();

        // Validate key format
        if !self.config_key_regex.is_match(key) {
            result.add_error(
                "config_key",
                "Configuration key contains invalid characters",
                ValidationSeverity::Critical
            );
        }

        // Validate specific configuration values
        match key {
            "memory_cost" => {
                if let Ok(cost) = value.parse::<u32>() {
                    if cost < 1024 {
                        result.add_error_with_suggestion(
                            key,
                            "Memory cost too low for security",
                            ValidationSeverity::Critical,
                            "Use at least 1024 KiB (1 MB) for security"
                        );
                    } else if cost > 1048576 {
                        result.add_error(
                            key,
                            "Memory cost extremely high - may cause system issues",
                            ValidationSeverity::Warning
                        );
                    }
                } else {
                    result.add_error(key, "Memory cost must be a valid number", ValidationSeverity::Critical);
                }
            }
            "time_cost" => {
                if let Ok(cost) = value.parse::<u32>() {
                    if cost < 1 {
                        result.add_error(key, "Time cost must be at least 1", ValidationSeverity::Critical);
                    } else if cost > 100 {
                        result.add_error(key, "Time cost very high - operations will be slow", ValidationSeverity::Warning);
                    }
                } else {
                    result.add_error(key, "Time cost must be a valid number", ValidationSeverity::Critical);
                }
            }
            "parallelism" => {
                if let Ok(par) = value.parse::<u32>() {
                    let cpu_count = num_cpus::get() as u32;
                    if par < 1 {
                        result.add_error(key, "Parallelism must be at least 1", ValidationSeverity::Critical);
                    } else if par > cpu_count * 2 {
                        result.add_warning(&format!(
                            "Parallelism ({}) higher than recommended ({})",
                            par, cpu_count
                        ));
                    }
                } else {
                    result.add_error(key, "Parallelism must be a valid number", ValidationSeverity::Critical);
                }
            }
            _ => {
                // Generic validation for unknown keys
                if value.len() > 1000 {
                    result.add_error(key, "Configuration value too long", ValidationSeverity::Warning);
                }
            }
        }

        result
    }

    /// Validate file content for potential issues
    pub fn validate_file_content(&self, content: &[u8], filename: &str) -> ValidationResult {
        let mut result = ValidationResult::new();

        // Check file size limits
        const MAX_FILE_SIZE: usize = 100 * 1024 * 1024; // 100MB
        if content.len() > MAX_FILE_SIZE {
            result.add_error(
                "file_size",
                "File too large for encryption (>100MB)",
                ValidationSeverity::Critical
            );
        }

        // Check for binary vs text content
        let null_bytes = content.iter().filter(|&&b| b == 0).count();
        if null_bytes > content.len() / 100 {
            result.add_warning("File appears to be binary - ensure this is intended");
        }

        // Check for potential secrets in the content (basic check)
        if let Ok(text_content) = std::str::from_utf8(content) {
            self.check_for_potential_secrets(text_content, &mut result);
        }

        // Check filename for suspicious patterns
        let filename_lower = filename.to_lowercase();
        let suspicious_names = ["password", "secret", "key", "token", "credential"];
        if suspicious_names.iter().any(|&pattern| filename_lower.contains(pattern)) {
            result.add_warning("Filename suggests this file may contain sensitive data");
        }

        result
    }

    /// Check text content for potential secrets
    fn check_for_potential_secrets(&self, content: &str, result: &mut ValidationResult) {
        // Basic patterns for common secret types
        let patterns = [
            (r"(?i)password\s*[=:]\s*[\w@#$%^&*!]+", "Potential password"),
            (r"(?i)api[_-]?key\s*[=:]\s*[\w-]+", "Potential API key"),
            (r"(?i)secret[_-]?key\s*[=:]\s*[\w-]+", "Potential secret key"),
            (r"AKIA[0-9A-Z]{16}", "Potential AWS access key"),
            (r"sk_live_[0-9a-zA-Z]{24,}", "Potential Stripe secret key"),
            (r"ghp_[0-9a-zA-Z]{36}", "Potential GitHub personal access token"),
        ];

        for (pattern, description) in &patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(content) {
                    result.add_warning(&format!("{} detected in file content", description));
                }
            }
        }

        // Check for high entropy strings
        for line in content.lines().take(100) { // Check first 100 lines only
            if line.len() > 20 && self.has_high_entropy(line) {
                result.add_warning("High entropy string detected - may be encoded secret");
                break; // Only warn once
            }
        }
    }

    /// Simple entropy check for strings
    fn has_high_entropy(&self, s: &str) -> bool {
        if s.len() < 20 {
            return false;
        }

        let mut char_counts = std::collections::HashMap::new();
        for c in s.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }

        let len = s.len() as f64;
        let entropy: f64 = char_counts
            .values()
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum();

        // High entropy threshold (adjust based on testing)
        entropy > 4.0
    }
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new()
    }
}

/// Sanitize user input by removing dangerous characters
pub fn sanitize_input(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect::<String>()
        .trim()
        .to_string()
}

/// Validate and sanitize a file path
pub fn validate_and_sanitize_path(path: &str) -> CryptoResult<PathBuf> {
    let validator = InputValidator::new();
    let sanitized = sanitize_input(path);
    let path_buf = PathBuf::from(&sanitized);
    
    let validation = validator.validate_file_path(&path_buf);
    if !validation.is_valid {
        let error_messages: Vec<String> = validation.errors
            .iter()
            .filter(|e| e.severity == ValidationSeverity::Critical)
            .map(|e| e.message.clone())
            .collect();
        
        return Err(CargoCryptError::Config {
            message: format!("Invalid file path: {}", error_messages.join(", ")),
            suggestion: Some("Please provide a valid file path without dangerous characters".to_string()),
        });
    }
    
    Ok(path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_validation() {
        let validator = InputValidator::new();

        // Weak password
        let result = validator.validate_password("weak");
        assert!(!result.is_valid);

        // Strong password
        let result = validator.validate_password("StrongP@ssw0rd123");
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_path_validation() {
        let validator = InputValidator::new();

        // Path traversal attempt
        let result = validator.validate_file_path("../../etc/passwd");
        assert!(!result.is_valid);

        // Valid relative path
        let result = validator.validate_file_path("./test/file.txt");
        assert!(result.is_valid || result.warnings.len() > 0); // May have warnings but should be valid
    }

    #[test]
    fn test_config_validation() {
        let validator = InputValidator::new();

        // Invalid memory cost
        let result = validator.validate_config_value("memory_cost", "512");
        assert!(!result.is_valid);

        // Valid memory cost
        let result = validator.validate_config_value("memory_cost", "65536");
        assert!(result.is_valid);
    }

    #[test]
    fn test_input_sanitization() {
        let malicious_input = "test\x00\x01\x02file.txt";
        let sanitized = sanitize_input(malicious_input);
        assert_eq!(sanitized, "testfile.txt");
    }
}