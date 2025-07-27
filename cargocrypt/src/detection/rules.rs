//! Custom rule engine for extensible secret detection
//!
//! This module allows users to define their own detection rules using various
//! rule types including regex patterns, entropy thresholds, and composite rules.

use crate::detection::SecretType;
use crate::error::{CargoCryptError, CryptoResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Types of custom rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleType {
    /// Simple regex pattern matching
    Regex {
        pattern: String,
        case_sensitive: bool,
    },
    /// Entropy-based detection
    Entropy {
        min_entropy: f64,
        min_length: usize,
        max_length: usize,
    },
    /// Keyword-based detection with context
    Keyword {
        keywords: Vec<String>,
        context_radius: usize,
        require_high_entropy: bool,
    },
    /// Composite rule combining multiple conditions
    Composite {
        rules: Vec<RuleCondition>,
        operator: LogicalOperator,
    },
    /// File-based rules (specific to certain file types)
    FileSpecific {
        file_patterns: Vec<String>,
        rule: Box<RuleType>,
    },
}

/// Logical operators for composite rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogicalOperator {
    And,
    Or,
    Not,
}

/// A condition within a composite rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub rule_type: RuleType,
    pub weight: f64, // Weight for scoring (0.0 to 1.0)
}

/// A custom detection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRule {
    /// Unique identifier for the rule
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this rule detects
    pub description: String,
    /// The rule type and configuration
    pub rule_type: RuleType,
    /// Secret type this rule detects
    pub secret_type: SecretType,
    /// Base confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Whether this rule is enabled
    pub enabled: bool,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Whether to validate matches
    pub validate: bool,
}

impl CustomRule {
    /// Create a new custom rule
    pub fn new(
        id: String,
        name: String,
        description: String,
        rule_type: RuleType,
        secret_type: SecretType,
        confidence: f64,
    ) -> Self {
        Self {
            id,
            name,
            description,
            rule_type,
            secret_type,
            confidence,
            enabled: true,
            tags: Vec::new(),
            validate: false,
        }
    }

    /// Add tags to the rule
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Enable validation for this rule
    pub fn with_validation(mut self) -> Self {
        self.validate = true;
        self
    }

    /// Disable this rule
    pub fn disable(mut self) -> Self {
        self.enabled = false;
        self
    }

    /// Check if this rule matches the given text
    pub fn matches(&self, text: &str, file_path: Option<&str>) -> CryptoResult<Vec<RuleMatch>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        self.check_rule_matches(&self.rule_type, text, file_path)
    }

    /// Internal method to check rule matches
    fn check_rule_matches(
        &self,
        rule_type: &RuleType,
        text: &str,
        file_path: Option<&str>,
    ) -> CryptoResult<Vec<RuleMatch>> {
        match rule_type {
            RuleType::Regex { pattern, case_sensitive } => {
                self.check_regex_matches(pattern, text, *case_sensitive)
            }
            RuleType::Entropy { min_entropy, min_length, max_length } => {
                self.check_entropy_matches(text, *min_entropy, *min_length, *max_length)
            }
            RuleType::Keyword { keywords, context_radius, require_high_entropy } => {
                self.check_keyword_matches(text, keywords, *context_radius, *require_high_entropy)
            }
            RuleType::Composite { rules, operator } => {
                self.check_composite_matches(text, rules, operator, file_path)
            }
            RuleType::FileSpecific { file_patterns, rule } => {
                self.check_file_specific_matches(text, file_patterns, rule, file_path)
            }
        }
    }

    fn check_regex_matches(
        &self,
        pattern: &str,
        text: &str,
        case_sensitive: bool,
    ) -> CryptoResult<Vec<RuleMatch>> {
        let regex_pattern = if case_sensitive {
            pattern.to_string()
        } else {
            format!("(?i){}", pattern)
        };

        let regex = Regex::new(&regex_pattern)
            .map_err(|e| CargoCryptError::detection_error(&format!("Invalid regex pattern: {}", e)))?;

        let matches = regex
            .find_iter(text)
            .map(|m| RuleMatch {
                matched_text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                confidence: self.confidence,
                rule_id: self.id.clone(),
                match_type: MatchType::Regex,
                metadata: HashMap::new(),
            })
            .collect();

        Ok(matches)
    }

    fn check_entropy_matches(
        &self,
        text: &str,
        min_entropy: f64,
        min_length: usize,
        max_length: usize,
    ) -> CryptoResult<Vec<RuleMatch>> {
        use crate::detection::entropy::EntropyAnalyzer;
        
        let analyzer = EntropyAnalyzer::new();
        let candidates = analyzer.extract_high_entropy_substrings(text, min_length);

        let matches = candidates
            .into_iter()
            .filter(|(substring, result)| {
                substring.len() <= max_length && result.shannon_entropy >= min_entropy
            })
            .map(|(substring, entropy_result)| {
                let start = text.find(&substring).unwrap_or(0);
                let end = start + substring.len();
                
                let mut metadata = HashMap::new();
                metadata.insert("shannon_entropy".to_string(), entropy_result.shannon_entropy.to_string());
                metadata.insert("normalized_entropy".to_string(), entropy_result.normalized_entropy.to_string());
                metadata.insert("charset_size".to_string(), entropy_result.charset_size.to_string());

                RuleMatch {
                    matched_text: substring,
                    start,
                    end,
                    confidence: self.confidence * entropy_result.confidence,
                    rule_id: self.id.clone(),
                    match_type: MatchType::Entropy,
                    metadata,
                }
            })
            .collect();

        Ok(matches)
    }

    fn check_keyword_matches(
        &self,
        text: &str,
        keywords: &[String],
        context_radius: usize,
        require_high_entropy: bool,
    ) -> CryptoResult<Vec<RuleMatch>> {
        use crate::detection::entropy::utils::has_high_entropy;
        
        let mut matches = Vec::new();
        let text_lower = text.to_lowercase();

        for keyword in keywords {
            let keyword_lower = keyword.to_lowercase();
            let mut start_pos = 0;

            while let Some(pos) = text_lower[start_pos..].find(&keyword_lower) {
                let actual_pos = start_pos + pos;
                let context_start = actual_pos.saturating_sub(context_radius);
                let context_end = std::cmp::min(actual_pos + keyword.len() + context_radius, text.len());
                let context = &text[context_start..context_end];

                // Check if high entropy is required
                if require_high_entropy && !has_high_entropy(context) {
                    start_pos = actual_pos + 1;
                    continue;
                }

                let mut metadata = HashMap::new();
                metadata.insert("keyword".to_string(), keyword.clone());
                metadata.insert("context".to_string(), context.to_string());

                matches.push(RuleMatch {
                    matched_text: context.to_string(),
                    start: context_start,
                    end: context_end,
                    confidence: self.confidence,
                    rule_id: self.id.clone(),
                    match_type: MatchType::Keyword,
                    metadata,
                });

                start_pos = actual_pos + 1;
            }
        }

        Ok(matches)
    }

    fn check_composite_matches(
        &self,
        text: &str,
        rules: &[RuleCondition],
        operator: &LogicalOperator,
        file_path: Option<&str>,
    ) -> CryptoResult<Vec<RuleMatch>> {
        let mut all_matches = Vec::new();
        let mut rule_results = Vec::new();

        // Collect matches from all sub-rules
        for rule_condition in rules {
            let matches = self.check_rule_matches(&rule_condition.rule_type, text, file_path)?;
            rule_results.push((matches.clone(), rule_condition.weight));
            all_matches.extend(matches);
        }

        // Apply logical operator
        let filtered_matches = match operator {
            LogicalOperator::And => {
                // All rules must have matches
                if rule_results.iter().all(|(matches, _)| !matches.is_empty()) {
                    all_matches
                } else {
                    Vec::new()
                }
            }
            LogicalOperator::Or => {
                // Any rule can have matches
                all_matches
            }
            LogicalOperator::Not => {
                // No rules should have matches (useful for exclusions)
                if all_matches.is_empty() {
                    // Create a dummy match to indicate this rule fired
                    vec![RuleMatch {
                        matched_text: "negative_match".to_string(),
                        start: 0,
                        end: 0,
                        confidence: self.confidence,
                        rule_id: self.id.clone(),
                        match_type: MatchType::Composite,
                        metadata: HashMap::new(),
                    }]
                } else {
                    Vec::new()
                }
            }
        };

        Ok(filtered_matches)
    }

    fn check_file_specific_matches(
        &self,
        text: &str,
        file_patterns: &[String],
        rule: &RuleType,
        file_path: Option<&str>,
    ) -> CryptoResult<Vec<RuleMatch>> {
        // Check if file path matches any of the patterns
        if let Some(path) = file_path {
            let matches_pattern = file_patterns.iter().any(|pattern| {
                // Simple glob-like matching
                if pattern.contains('*') {
                    let pattern_regex = pattern.replace("*", ".*");
                    Regex::new(&pattern_regex)
                        .map(|r| r.is_match(path))
                        .unwrap_or(false)
                } else {
                    path.ends_with(pattern)
                }
            });

            if matches_pattern {
                self.check_rule_matches(rule, text, Some(path))
            } else {
                Ok(Vec::new())
            }
        } else {
            Ok(Vec::new())
        }
    }
}

/// A match result from a custom rule
#[derive(Debug, Clone)]
pub struct RuleMatch {
    /// The matched text
    pub matched_text: String,
    /// Start position in the source
    pub start: usize,
    /// End position in the source
    pub end: usize,
    /// Confidence score for this match
    pub confidence: f64,
    /// ID of the rule that produced this match
    pub rule_id: String,
    /// Type of match
    pub match_type: MatchType,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Types of rule matches
#[derive(Debug, Clone)]
pub enum MatchType {
    Regex,
    Entropy,
    Keyword,
    Composite,
    FileSpecific,
}

/// Rule engine for managing and executing custom rules
#[derive(Debug, Default, Clone)]
pub struct RuleEngine {
    rules: HashMap<String, CustomRule>,
    enabled: bool,
}

impl RuleEngine {
    /// Create a new rule engine
    pub fn new() -> Self {
        Self {
            rules: HashMap::new(),
            enabled: true,
        }
    }

    /// Add a rule to the engine
    pub fn add_rule(&mut self, rule: CustomRule) {
        self.rules.insert(rule.id.clone(), rule);
    }

    /// Remove a rule from the engine
    pub fn remove_rule(&mut self, rule_id: &str) -> Option<CustomRule> {
        self.rules.remove(rule_id)
    }

    /// Get a rule by ID
    pub fn get_rule(&self, rule_id: &str) -> Option<&CustomRule> {
        self.rules.get(rule_id)
    }

    /// Get all rules
    pub fn rules(&self) -> Vec<&CustomRule> {
        self.rules.values().collect()
    }

    /// Get enabled rules only
    pub fn enabled_rules(&self) -> Vec<&CustomRule> {
        self.rules
            .values()
            .filter(|rule| rule.enabled)
            .collect()
    }

    /// Execute all enabled rules against text
    pub fn execute_rules(&self, text: &str, file_path: Option<&str>) -> CryptoResult<Vec<RuleMatch>> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        let mut all_matches = Vec::new();

        for rule in self.enabled_rules() {
            let matches = rule.matches(text, file_path)?;
            all_matches.extend(matches);
        }

        // Sort by position
        all_matches.sort_by_key(|m| m.start);

        Ok(all_matches)
    }

    /// Load rules from configuration
    pub fn load_rules_from_config(&mut self, config: &RuleConfig) -> CryptoResult<()> {
        for rule_config in &config.rules {
            let rule = self.create_rule_from_config(rule_config)?;
            self.add_rule(rule);
        }
        Ok(())
    }

    /// Create a rule from configuration
    fn create_rule_from_config(&self, config: &RuleConfigItem) -> CryptoResult<CustomRule> {
        let rule_type = match config.rule_type.as_str() {
            "regex" => {
                let pattern = config.pattern.as_ref()
                    .ok_or_else(|| CargoCryptError::detection_error("Regex rule requires 'pattern' field"))?;
                
                RuleType::Regex {
                    pattern: pattern.clone(),
                    case_sensitive: config.case_sensitive.unwrap_or(true),
                }
            }
            "entropy" => {
                RuleType::Entropy {
                    min_entropy: config.min_entropy.unwrap_or(4.0),
                    min_length: config.min_length.unwrap_or(8),
                    max_length: config.max_length.unwrap_or(100),
                }
            }
            "keyword" => {
                let keywords = config.keywords.as_ref()
                    .ok_or_else(|| CargoCryptError::detection_error("Keyword rule requires 'keywords' field"))?;
                
                RuleType::Keyword {
                    keywords: keywords.clone(),
                    context_radius: config.context_radius.unwrap_or(20),
                    require_high_entropy: config.require_high_entropy.unwrap_or(false),
                }
            }
            _ => {
                return Err(CargoCryptError::detection_error(&format!(
                    "Unknown rule type: {}", config.rule_type
                )));
            }
        };

        let secret_type = if let Some(custom_type) = &config.secret_type {
            SecretType::Custom(custom_type.clone())
        } else {
            SecretType::Custom("unknown".to_string())
        };

        Ok(CustomRule::new(
            config.id.clone(),
            config.name.clone(),
            config.description.clone().unwrap_or_default(),
            rule_type,
            secret_type,
            config.confidence.unwrap_or(0.7),
        ))
    }

    /// Enable or disable the rule engine
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

/// Configuration for loading rules
#[derive(Debug, Serialize, Deserialize)]
pub struct RuleConfig {
    pub rules: Vec<RuleConfigItem>,
}

/// Configuration for a single rule
#[derive(Debug, Serialize, Deserialize)]
pub struct RuleConfigItem {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub secret_type: Option<String>,
    pub confidence: Option<f64>,
    
    // Regex rule fields
    pub pattern: Option<String>,
    pub case_sensitive: Option<bool>,
    
    // Entropy rule fields
    pub min_entropy: Option<f64>,
    pub min_length: Option<usize>,
    pub max_length: Option<usize>,
    
    // Keyword rule fields
    pub keywords: Option<Vec<String>>,
    pub context_radius: Option<usize>,
    pub require_high_entropy: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_rule() {
        let rule = CustomRule::new(
            "test_regex".to_string(),
            "Test Regex".to_string(),
            "Test regex rule".to_string(),
            RuleType::Regex {
                pattern: r"test_\d+".to_string(),
                case_sensitive: true,
            },
            SecretType::Custom("test".to_string()),
            0.8,
        );

        let matches = rule.matches("This is test_123 and test_456", None).unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].matched_text, "test_123");
        assert_eq!(matches[1].matched_text, "test_456");
    }

    #[test]
    fn test_entropy_rule() {
        let rule = CustomRule::new(
            "test_entropy".to_string(),
            "Test Entropy".to_string(),
            "Test entropy rule".to_string(),
            RuleType::Entropy {
                min_entropy: 3.0,
                min_length: 8,
                max_length: 50,
            },
            SecretType::Custom("high_entropy".to_string()),
            0.7,
        );

        let matches = rule.matches("hello AKIAIOSFODNN7EXAMPLE world", None).unwrap();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_keyword_rule() {
        let rule = CustomRule::new(
            "test_keyword".to_string(),
            "Test Keyword".to_string(),
            "Test keyword rule".to_string(),
            RuleType::Keyword {
                keywords: vec!["password".to_string(), "secret".to_string()],
                context_radius: 10,
                require_high_entropy: false,
            },
            SecretType::Custom("keyword".to_string()),
            0.6,
        );

        let matches = rule.matches("The password is very secure", None).unwrap();
        assert_eq!(matches.len(), 1);
        assert!(matches[0].matched_text.contains("password"));
    }

    #[test]
    fn test_rule_engine() {
        let mut engine = RuleEngine::new();
        
        let rule = CustomRule::new(
            "test_rule".to_string(),
            "Test Rule".to_string(),
            "Test rule".to_string(),
            RuleType::Regex {
                pattern: r"secret_\w+".to_string(),
                case_sensitive: false,
            },
            SecretType::Custom("test".to_string()),
            0.8,
        );

        engine.add_rule(rule);
        
        let matches = engine.execute_rules("This is secret_key and SECRET_TOKEN", None).unwrap();
        assert_eq!(matches.len(), 2);
    }
}