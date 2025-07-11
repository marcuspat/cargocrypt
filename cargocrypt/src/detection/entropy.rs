//! Entropy analysis for detecting high-entropy strings that may be secrets
//!
//! This module uses Shannon entropy and other statistical measures to identify
//! strings that have high randomness, which is characteristic of secrets, keys,
//! and tokens.

use std::collections::HashMap;

/// Result of entropy analysis
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// Shannon entropy score (0.0 to log2(charset_size))
    pub shannon_entropy: f64,
    /// Normalized entropy (0.0 to 1.0)
    pub normalized_entropy: f64,
    /// Character set size used in the string
    pub charset_size: usize,
    /// Length of the analyzed string
    pub length: usize,
    /// Character frequency distribution
    pub char_frequencies: HashMap<char, f64>,
    /// Whether this looks like a secret based on entropy
    pub is_likely_secret: bool,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
}

impl EntropyResult {
    /// Check if this string is likely a secret based on entropy analysis
    pub fn is_likely_secret(&self) -> bool {
        self.is_likely_secret
    }

    /// Get a detailed analysis description
    pub fn description(&self) -> String {
        format!(
            "Entropy: {:.2}, Normalized: {:.2}, Charset: {}, Length: {}, Confidence: {:.2}",
            self.shannon_entropy,
            self.normalized_entropy,
            self.charset_size,
            self.length,
            self.confidence
        )
    }
}

/// Entropy analyzer for secret detection
#[derive(Debug, Clone)]
pub struct EntropyAnalyzer {
    /// Minimum length to consider for analysis
    pub min_length: usize,
    /// Maximum length to consider for analysis
    pub max_length: usize,
    /// Minimum entropy threshold for secret detection
    pub min_entropy_threshold: f64,
    /// Minimum normalized entropy threshold
    pub min_normalized_entropy: f64,
    /// Minimum character set size
    pub min_charset_size: usize,
}

impl Default for EntropyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyAnalyzer {
    /// Create a new entropy analyzer with default settings
    pub fn new() -> Self {
        Self {
            min_length: 8,          // Don't analyze very short strings
            max_length: 1000,       // Don't analyze very long strings
            min_entropy_threshold: 3.5,  // Minimum Shannon entropy
            min_normalized_entropy: 0.6, // Minimum normalized entropy
            min_charset_size: 8,    // Minimum character variety
        }
    }

    /// Create an analyzer optimized for API keys
    pub fn for_api_keys() -> Self {
        Self {
            min_length: 10,
            max_length: 200,
            min_entropy_threshold: 4.0,
            min_normalized_entropy: 0.7,
            min_charset_size: 10,
        }
    }

    /// Create an analyzer optimized for tokens
    pub fn for_tokens() -> Self {
        Self {
            min_length: 20,
            max_length: 500,
            min_entropy_threshold: 4.5,
            min_normalized_entropy: 0.75,
            min_charset_size: 16,
        }
    }

    /// Analyze the entropy of a string
    pub fn analyze(&self, text: &str) -> EntropyResult {
        // Skip if length is out of bounds
        if text.len() < self.min_length || text.len() > self.max_length {
            return EntropyResult {
                shannon_entropy: 0.0,
                normalized_entropy: 0.0,
                charset_size: 0,
                length: text.len(),
                char_frequencies: HashMap::new(),
                is_likely_secret: false,
                confidence: 0.0,
            };
        }

        let char_frequencies = self.calculate_char_frequencies(text);
        let charset_size = char_frequencies.len();
        let shannon_entropy = self.calculate_shannon_entropy(&char_frequencies, text.len());
        let max_possible_entropy = (charset_size as f64).log2();
        let normalized_entropy = if max_possible_entropy > 0.0 {
            shannon_entropy / max_possible_entropy
        } else {
            0.0
        };

        // Determine if this looks like a secret
        let is_likely_secret = self.is_likely_secret_by_entropy(
            shannon_entropy,
            normalized_entropy,
            charset_size,
            text,
        );

        // Calculate confidence score
        let confidence = self.calculate_confidence(
            shannon_entropy,
            normalized_entropy,
            charset_size,
            text,
        );

        EntropyResult {
            shannon_entropy,
            normalized_entropy,
            charset_size,
            length: text.len(),
            char_frequencies,
            is_likely_secret,
            confidence,
        }
    }

    /// Analyze multiple strings and return only those likely to be secrets
    pub fn analyze_candidates(&self, candidates: &[&str]) -> Vec<(String, EntropyResult)> {
        candidates
            .iter()
            .map(|&text| (text.to_string(), self.analyze(text)))
            .filter(|(_, result)| result.is_likely_secret)
            .collect()
    }

    /// Extract high-entropy substrings from text
    pub fn extract_high_entropy_substrings(&self, text: &str, min_length: usize) -> Vec<(String, EntropyResult)> {
        let mut results = Vec::new();
        
        // Try different substring lengths
        for len in min_length..=std::cmp::min(text.len(), self.max_length) {
            for start in 0..=(text.len().saturating_sub(len)) {
                let substring = &text[start..start + len];
                
                // Skip if it contains whitespace or common delimiters
                if substring.chars().any(|c| c.is_whitespace() || "\"'(){}[]<>".contains(c)) {
                    continue;
                }
                
                let result = self.analyze(substring);
                if result.is_likely_secret && result.confidence > 0.7 {
                    results.push((substring.to_string(), result));
                }
            }
        }

        // Remove duplicates and sort by confidence
        results.sort_by(|a, b| b.1.confidence.partial_cmp(&a.1.confidence).unwrap());
        results.dedup_by(|a, b| a.0 == b.0);
        
        results
    }

    /// Calculate character frequencies
    fn calculate_char_frequencies(&self, text: &str) -> HashMap<char, f64> {
        let mut frequencies = HashMap::new();
        let total_chars = text.len() as f64;

        for ch in text.chars() {
            *frequencies.entry(ch).or_insert(0.0) += 1.0;
        }

        // Convert counts to frequencies
        for frequency in frequencies.values_mut() {
            *frequency /= total_chars;
        }

        frequencies
    }

    /// Calculate Shannon entropy
    fn calculate_shannon_entropy(&self, frequencies: &HashMap<char, f64>, _total_length: usize) -> f64 {
        frequencies
            .values()
            .filter(|&&freq| freq > 0.0)
            .map(|&freq| -freq * freq.log2())
            .sum()
    }

    /// Determine if a string is likely a secret based on entropy metrics
    fn is_likely_secret_by_entropy(
        &self,
        shannon_entropy: f64,
        normalized_entropy: f64,
        charset_size: usize,
        text: &str,
    ) -> bool {
        // Basic entropy thresholds
        if shannon_entropy < self.min_entropy_threshold {
            return false;
        }

        if normalized_entropy < self.min_normalized_entropy {
            return false;
        }

        if charset_size < self.min_charset_size {
            return false;
        }

        // Additional heuristics
        
        // Reject if it looks like natural language
        if self.looks_like_natural_language(text) {
            return false;
        }

        // Reject if it's all the same character type
        if self.is_single_character_type(text) {
            return false;
        }

        // Reject common patterns that aren't secrets
        if self.is_common_non_secret_pattern(text) {
            return false;
        }

        true
    }

    /// Calculate confidence score based on various factors
    fn calculate_confidence(
        &self,
        shannon_entropy: f64,
        normalized_entropy: f64,
        charset_size: usize,
        text: &str,
    ) -> f64 {
        let mut confidence = 0.0;

        // Shannon entropy contribution (0.0 to 0.4)
        confidence += (shannon_entropy / 6.0).min(0.4);

        // Normalized entropy contribution (0.0 to 0.3)
        confidence += normalized_entropy * 0.3;

        // Character set diversity (0.0 to 0.2)
        confidence += (charset_size as f64 / 62.0).min(0.2); // 62 = a-z + A-Z + 0-9

        // Length bonus (0.0 to 0.1)
        if text.len() >= 20 {
            confidence += 0.1;
        } else if text.len() >= 12 {
            confidence += 0.05;
        }

        // Pattern bonuses and penalties
        if self.has_secret_like_patterns(text) {
            confidence += 0.1;
        }

        if self.looks_like_natural_language(text) {
            confidence -= 0.3;
        }

        if self.is_common_non_secret_pattern(text) {
            confidence -= 0.4;
        }

        confidence.max(0.0).min(1.0)
    }

    /// Check if text looks like natural language
    fn looks_like_natural_language(&self, text: &str) -> bool {
        let lowercase_text = text.to_lowercase();
        
        // Check for common English words
        let common_words = [
            "the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "was", "one",
            "our", "out", "day", "get", "has", "him", "his", "how", "its", "may", "new", "now",
            "old", "see", "two", "way", "who", "boy", "did", "man", "car", "dog", "cat", "run",
        ];

        let word_count = common_words
            .iter()
            .filter(|&&word| lowercase_text.contains(word))
            .count();

        // If it contains multiple common words, it's likely natural language
        word_count >= 2
    }

    /// Check if string is all the same character type (all digits, all uppercase, etc.)
    fn is_single_character_type(&self, text: &str) -> bool {
        text.chars().all(|c| c.is_ascii_digit()) ||
        text.chars().all(|c| c.is_ascii_uppercase()) ||
        text.chars().all(|c| c.is_ascii_lowercase())
    }

    /// Check for common non-secret patterns
    fn is_common_non_secret_pattern(&self, text: &str) -> bool {
        let lowercase_text = text.to_lowercase();
        
        // Common non-secret patterns
        let non_secret_patterns = [
            "localhost", "127.0.0.1", "example.com", "test.com",
            "placeholder", "your_key_here", "insert_key_here",
            "todo", "fixme", "changeme", "password123",
            "abcdefgh", "12345678", "qwertyui",
        ];

        non_secret_patterns
            .iter()
            .any(|&pattern| lowercase_text.contains(pattern))
    }

    /// Check for patterns that suggest this might be a secret
    fn has_secret_like_patterns(&self, text: &str) -> bool {
        // Mixed case with numbers and special characters
        let has_lowercase = text.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = text.chars().any(|c| c.is_ascii_uppercase());
        let has_digits = text.chars().any(|c| c.is_ascii_digit());
        let has_special = text.chars().any(|c| !c.is_ascii_alphanumeric());

        // Count character type variety
        let variety_count = [has_lowercase, has_uppercase, has_digits, has_special]
            .iter()
            .filter(|&&x| x)
            .count();

        // Secrets often have good character variety
        variety_count >= 3
    }
}

/// Utility functions for entropy analysis
pub mod utils {
    use super::*;

    /// Quick check if a string has high entropy
    pub fn has_high_entropy(text: &str) -> bool {
        if text.len() < 8 {
            return false;
        }

        let analyzer = EntropyAnalyzer::new();
        let result = analyzer.analyze(text);
        result.is_likely_secret
    }

    /// Calculate basic Shannon entropy for a string
    pub fn shannon_entropy(text: &str) -> f64 {
        let analyzer = EntropyAnalyzer::new();
        let frequencies = analyzer.calculate_char_frequencies(text);
        analyzer.calculate_shannon_entropy(&frequencies, text.len())
    }

    /// Extract the highest entropy substring of minimum length
    pub fn highest_entropy_substring(text: &str, min_length: usize) -> Option<String> {
        let analyzer = EntropyAnalyzer::new();
        let candidates = analyzer.extract_high_entropy_substrings(text, min_length);
        
        candidates
            .into_iter()
            .max_by(|a, b| a.1.shannon_entropy.partial_cmp(&b.1.shannon_entropy).unwrap())
            .map(|(substring, _)| substring)
    }

    /// Analyze text and return entropy statistics
    pub fn entropy_stats(text: &str) -> (f64, f64, usize) {
        let analyzer = EntropyAnalyzer::new();
        let result = analyzer.analyze(text);
        (result.shannon_entropy, result.normalized_entropy, result.charset_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_analysis() {
        let analyzer = EntropyAnalyzer::new();
        
        // High entropy string (AWS key format)
        let high_entropy = analyzer.analyze("AKIAIOSFODNN7EXAMPLE");
        assert!(high_entropy.shannon_entropy > 3.0);
        assert!(high_entropy.normalized_entropy > 0.5);
        
        // Low entropy string
        let low_entropy = analyzer.analyze("aaaaaaaaaaaaa");
        assert!(low_entropy.shannon_entropy < 1.0);
        assert!(low_entropy.normalized_entropy < 0.3);
    }

    #[test]
    fn test_secret_detection() {
        let analyzer = EntropyAnalyzer::new();
        
        // Should detect as likely secret
        assert!(analyzer.analyze("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").is_likely_secret);
        assert!(analyzer.analyze("sk_test_26PHem9AhJZvU623DfE1x4sd").is_likely_secret);
        
        // Should not detect as secret
        assert!(!analyzer.analyze("hello_world_example").is_likely_secret);
        assert!(!analyzer.analyze("12345678901234567890").is_likely_secret);
        assert!(!analyzer.analyze("configuration_value").is_likely_secret);
    }

    #[test]
    fn test_natural_language_detection() {
        let analyzer = EntropyAnalyzer::new();
        
        assert!(analyzer.looks_like_natural_language("the quick brown fox"));
        assert!(analyzer.looks_like_natural_language("you can see the dog"));
        assert!(!analyzer.looks_like_natural_language("xk2j9mL4nQ8pR7vS"));
    }

    #[test]
    fn test_pattern_recognition() {
        let analyzer = EntropyAnalyzer::new();
        
        // Should recognize secret-like patterns
        assert!(analyzer.has_secret_like_patterns("Aa1@"));
        assert!(analyzer.has_secret_like_patterns("MyS3cr3t!"));
        
        // Should not recognize simple patterns
        assert!(!analyzer.has_secret_like_patterns("hello"));
        assert!(!analyzer.has_secret_like_patterns("12345"));
    }

    #[test]
    fn test_utility_functions() {
        use super::utils::*;
        
        assert!(has_high_entropy("AKIAIOSFODNN7EXAMPLE"));
        assert!(!has_high_entropy("hello"));
        
        let entropy = shannon_entropy("AKIAIOSFODNN7EXAMPLE");
        assert!(entropy > 3.0);
        
        let highest = highest_entropy_substring("hello AKIAIOSFODNN7EXAMPLE world", 8);
        assert!(highest.is_some());
        assert!(highest.unwrap().contains("AKIA"));
    }

    #[test]
    fn test_confidence_scoring() {
        let analyzer = EntropyAnalyzer::new();
        
        // High confidence for good secrets
        let aws_key = analyzer.analyze("AKIAIOSFODNN7EXAMPLE");
        assert!(aws_key.confidence > 0.7);
        
        // Low confidence for non-secrets
        let simple = analyzer.analyze("hello_world");
        assert!(simple.confidence < 0.3);
    }
}