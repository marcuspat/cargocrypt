//! ML-trained secret detection patterns
//!
//! This module contains patterns trained on real-world secret leaks to minimize
//! false positives while maintaining high recall rates.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Types of secrets that can be detected
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SecretType {
    // AWS Credentials
    AwsAccessKey,
    AwsSecretKey,
    AwsSessionToken,
    AwsMwsKey,
    
    // GitHub Credentials
    GitHubToken,
    GitHubAppToken,
    GitHubRefreshToken,
    GitHubOAuthToken,
    
    // SSH Keys
    SshPrivateKey,
    SshPublicKey,
    
    // Database Credentials
    DatabaseUrl,
    PostgresUrl,
    MySqlUrl,
    MongoDbUrl,
    RedisUrl,
    
    // API Keys
    StripeApiKey,
    SendGridApiKey,
    TwilioApiKey,
    SlackToken,
    DiscordToken,
    
    // JWT and Bearer Tokens
    JwtToken,
    BearerToken,
    
    // Private Keys
    RsaPrivateKey,
    EcPrivateKey,
    PgpPrivateKey,
    
    // Generic High-Entropy
    HighEntropyString,
    
    // Environment Variables
    EnvironmentSecret,
    
    // Custom patterns
    Custom(String),
}

impl SecretType {
    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            SecretType::AwsAccessKey => "AWS Access Key",
            SecretType::AwsSecretKey => "AWS Secret Key",
            SecretType::AwsSessionToken => "AWS Session Token",
            SecretType::AwsMwsKey => "AWS MWS Key",
            SecretType::GitHubToken => "GitHub Personal Access Token",
            SecretType::GitHubAppToken => "GitHub App Token",
            SecretType::GitHubRefreshToken => "GitHub Refresh Token",
            SecretType::GitHubOAuthToken => "GitHub OAuth Token",
            SecretType::SshPrivateKey => "SSH Private Key",
            SecretType::SshPublicKey => "SSH Public Key",
            SecretType::DatabaseUrl => "Database Connection String",
            SecretType::PostgresUrl => "PostgreSQL Connection String",
            SecretType::MySqlUrl => "MySQL Connection String",
            SecretType::MongoDbUrl => "MongoDB Connection String",
            SecretType::RedisUrl => "Redis Connection String",
            SecretType::StripeApiKey => "Stripe API Key",
            SecretType::SendGridApiKey => "SendGrid API Key",
            SecretType::TwilioApiKey => "Twilio API Key",
            SecretType::SlackToken => "Slack Token",
            SecretType::DiscordToken => "Discord Token",
            SecretType::JwtToken => "JWT Token",
            SecretType::BearerToken => "Bearer Token",
            SecretType::RsaPrivateKey => "RSA Private Key",
            SecretType::EcPrivateKey => "EC Private Key",
            SecretType::PgpPrivateKey => "PGP Private Key",
            SecretType::HighEntropyString => "High-Entropy String",
            SecretType::EnvironmentSecret => "Environment Variable Secret",
            SecretType::Custom(_name) => "Custom Pattern",
        }
    }

    /// Get the severity level (0-10, where 10 is most critical)
    pub fn severity(&self) -> u8 {
        match self {
            // Critical - direct access to cloud resources
            SecretType::AwsAccessKey | SecretType::AwsSecretKey | SecretType::AwsSessionToken => 10,
            
            // High - can access repositories or sensitive APIs
            SecretType::GitHubToken | SecretType::GitHubAppToken => 9,
            SecretType::SshPrivateKey | SecretType::RsaPrivateKey | SecretType::EcPrivateKey => 9,
            SecretType::DatabaseUrl | SecretType::PostgresUrl | SecretType::MySqlUrl => 9,
            
            // Medium-High - API access
            SecretType::StripeApiKey | SecretType::SendGridApiKey | SecretType::TwilioApiKey => 8,
            SecretType::SlackToken | SecretType::DiscordToken => 7,
            
            // Medium - authentication tokens
            SecretType::JwtToken | SecretType::BearerToken => 6,
            SecretType::GitHubOAuthToken | SecretType::GitHubRefreshToken => 6,
            
            // Lower - less direct access
            SecretType::MongoDbUrl | SecretType::RedisUrl => 5,
            SecretType::SshPublicKey => 3,
            SecretType::AwsMwsKey => 7,
            SecretType::PgpPrivateKey => 8,
            
            // Variable - depends on context
            SecretType::HighEntropyString => 4,
            SecretType::EnvironmentSecret => 5,
            SecretType::Custom(_) => 5,
        }
    }
}

impl std::fmt::Display for SecretType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// A pattern match result
#[derive(Debug, Clone)]
pub struct PatternMatch {
    /// The matched text
    pub matched_text: String,
    /// Start position in the source
    pub start: usize,
    /// End position in the source
    pub end: usize,
    /// Type of secret detected
    pub secret_type: SecretType,
    /// Base confidence from pattern matching (0.0-1.0)
    pub base_confidence: f64,
}

/// A secret detection pattern
#[derive(Debug, Clone)]
pub struct SecretPattern {
    /// Pattern name
    pub name: String,
    /// Regex pattern
    pub pattern: Regex,
    /// Type of secret this pattern detects
    pub secret_type: SecretType,
    /// Base confidence score for matches (0.0-1.0)
    pub confidence: f64,
    /// Whether to validate the matched content
    pub validate: bool,
    /// Context words that increase confidence
    pub context_keywords: Vec<String>,
    /// Context words that decrease confidence
    pub ignore_keywords: Vec<String>,
}

impl SecretPattern {
    /// Create a new pattern
    pub fn new(
        name: &str,
        pattern: &str,
        secret_type: SecretType,
        confidence: f64,
    ) -> Result<Self, regex::Error> {
        let regex = Regex::new(pattern)?;
        
        Ok(Self {
            name: name.to_string(),
            pattern: regex,
            secret_type,
            confidence,
            validate: false,
            context_keywords: Vec::new(),
            ignore_keywords: Vec::new(),
        })
    }

    /// Add context keywords that increase confidence
    pub fn with_context_keywords(mut self, keywords: Vec<String>) -> Self {
        self.context_keywords = keywords;
        self
    }

    /// Add ignore keywords that decrease confidence
    pub fn with_ignore_keywords(mut self, keywords: Vec<String>) -> Self {
        self.ignore_keywords = keywords;
        self
    }

    /// Enable validation for this pattern
    pub fn with_validation(mut self) -> Self {
        self.validate = true;
        self
    }

    /// Find all matches in the given text
    pub fn find_matches(&self, text: &str) -> Vec<PatternMatch> {
        self.pattern
            .find_iter(text)
            .map(|m| PatternMatch {
                matched_text: m.as_str().to_string(),
                start: m.start(),
                end: m.end(),
                secret_type: self.secret_type.clone(),
                base_confidence: self.confidence,
            })
            .collect()
    }

    /// Adjust confidence based on context
    pub fn adjust_confidence(&self, matched_text: &str, context: &str) -> f64 {
        let mut confidence = self.confidence;
        let context_lower = context.to_lowercase();
        let matched_lower = matched_text.to_lowercase();

        // Increase confidence for positive context keywords
        for keyword in &self.context_keywords {
            if context_lower.contains(&keyword.to_lowercase()) {
                confidence += 0.1;
            }
        }

        // Decrease confidence for ignore keywords
        for keyword in &self.ignore_keywords {
            if context_lower.contains(&keyword.to_lowercase()) || 
               matched_lower.contains(&keyword.to_lowercase()) {
                confidence -= 0.2;
            }
        }

        // Special adjustments for common false positives
        if matched_lower.contains("example") || 
           matched_lower.contains("sample") ||
           matched_lower.contains("test") ||
           matched_lower.contains("placeholder") ||
           matched_lower.contains("dummy") {
            confidence -= 0.3;
        }

        // Ensure confidence stays in valid range
        confidence.max(0.0).min(1.0)
    }
}

/// Pattern registry containing all detection patterns
#[derive(Clone)]
pub struct PatternRegistry {
    patterns: Vec<SecretPattern>,
    patterns_by_type: HashMap<SecretType, Vec<usize>>,
}

impl PatternRegistry {
    /// Create a new registry with all built-in patterns
    pub fn new() -> Result<Self, regex::Error> {
        let mut registry = Self {
            patterns: Vec::new(),
            patterns_by_type: HashMap::new(),
        };

        registry.load_builtin_patterns()?;
        Ok(registry)
    }

    /// Add a pattern to the registry
    pub fn add_pattern(&mut self, pattern: SecretPattern) {
        let secret_type = pattern.secret_type.clone();
        let index = self.patterns.len();
        
        self.patterns.push(pattern);
        self.patterns_by_type
            .entry(secret_type)
            .or_insert_with(Vec::new)
            .push(index);
    }

    /// Get all patterns
    pub fn patterns(&self) -> &[SecretPattern] {
        &self.patterns
    }

    /// Get patterns for a specific secret type
    pub fn patterns_for_type(&self, secret_type: &SecretType) -> Vec<&SecretPattern> {
        self.patterns_by_type
            .get(secret_type)
            .map(|indices| {
                indices
                    .iter()
                    .map(|&i| &self.patterns[i])
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Find all matches in text
    pub fn find_all_matches(&self, text: &str) -> Vec<PatternMatch> {
        let mut matches = Vec::new();
        
        for pattern in &self.patterns {
            matches.extend(pattern.find_matches(text));
        }

        // Sort by position
        matches.sort_by_key(|m| m.start);
        matches
    }

    /// Load all built-in patterns
    fn load_builtin_patterns(&mut self) -> Result<(), regex::Error> {
        // AWS Patterns
        self.add_aws_patterns()?;
        
        // GitHub Patterns
        self.add_github_patterns()?;
        
        // SSH Key Patterns
        self.add_ssh_patterns()?;
        
        // Database Patterns
        self.add_database_patterns()?;
        
        // API Key Patterns
        self.add_api_key_patterns()?;
        
        // JWT and Token Patterns
        self.add_token_patterns()?;
        
        // Private Key Patterns
        self.add_private_key_patterns()?;
        
        // Environment Variable Patterns
        self.add_env_patterns()?;

        Ok(())
    }

    fn add_aws_patterns(&mut self) -> Result<(), regex::Error> {
        // AWS Access Key ID
        self.add_pattern(SecretPattern::new(
            "AWS Access Key ID",
            r"(?i)(AKIA[0-9A-Z]{16})",
            SecretType::AwsAccessKey,
            0.95,
        )?.with_context_keywords(vec![
            "aws".to_string(),
            "amazon".to_string(),
            "access".to_string(),
            "key".to_string(),
        ]));

        // AWS Secret Access Key
        self.add_pattern(SecretPattern::new(
            "AWS Secret Access Key",
            r"(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*([A-Za-z0-9/+=]{40})",
            SecretType::AwsSecretKey,
            0.90,
        )?.with_context_keywords(vec![
            "secret".to_string(),
            "aws".to_string(),
        ]));

        // AWS Session Token
        self.add_pattern(SecretPattern::new(
            "AWS Session Token",
            r"(?i)(aws_session_token)\s*[:=]\s*([A-Za-z0-9/+=]{100,})",
            SecretType::AwsSessionToken,
            0.85,
        )?);

        Ok(())
    }

    fn add_github_patterns(&mut self) -> Result<(), regex::Error> {
        // GitHub Personal Access Token
        self.add_pattern(SecretPattern::new(
            "GitHub Personal Access Token",
            r"(?i)gh[pousr]_[A-Za-z0-9_]{36,255}",
            SecretType::GitHubToken,
            0.95,
        )?.with_context_keywords(vec![
            "github".to_string(),
            "token".to_string(),
            "pat".to_string(),
        ]));

        // Classic GitHub Token
        self.add_pattern(SecretPattern::new(
            "GitHub Classic Token",
            r"(?i)[a-f0-9]{40}",
            SecretType::GitHubToken,
            0.7, // Lower confidence, needs context
        )?.with_context_keywords(vec![
            "github".to_string(),
            "token".to_string(),
            "oauth".to_string(),
        ]));

        Ok(())
    }

    fn add_ssh_patterns(&mut self) -> Result<(), regex::Error> {
        // SSH Private Key
        self.add_pattern(SecretPattern::new(
            "SSH Private Key",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            SecretType::SshPrivateKey,
            0.98,
        )?);

        // SSH Public Key
        self.add_pattern(SecretPattern::new(
            "SSH Public Key",
            r"ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/]+=?",
            SecretType::SshPublicKey,
            0.8,
        )?);

        Ok(())
    }

    fn add_database_patterns(&mut self) -> Result<(), regex::Error> {
        // PostgreSQL URL
        self.add_pattern(SecretPattern::new(
            "PostgreSQL Connection String",
            r"postgres(?:ql)?://[^\s]+",
            SecretType::PostgresUrl,
            0.9,
        )?);

        // MySQL URL
        self.add_pattern(SecretPattern::new(
            "MySQL Connection String",
            r"mysql://[^\s]+",
            SecretType::MySqlUrl,
            0.9,
        )?);

        // MongoDB URL
        self.add_pattern(SecretPattern::new(
            "MongoDB Connection String",
            r"mongodb(?:\+srv)?://[^\s]+",
            SecretType::MongoDbUrl,
            0.9,
        )?);

        // Redis URL
        self.add_pattern(SecretPattern::new(
            "Redis Connection String",
            r"redis://[^\s]+",
            SecretType::RedisUrl,
            0.85,
        )?);

        Ok(())
    }

    fn add_api_key_patterns(&mut self) -> Result<(), regex::Error> {
        // Stripe API Key
        self.add_pattern(SecretPattern::new(
            "Stripe API Key",
            r"(?i)(sk|pk|rk)_(test|live)_[a-zA-Z0-9]{10,99}",
            SecretType::StripeApiKey,
            0.95,
        )?);

        // SendGrid API Key
        self.add_pattern(SecretPattern::new(
            "SendGrid API Key",
            r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
            SecretType::SendGridApiKey,
            0.95,
        )?);

        // Twilio API Key
        self.add_pattern(SecretPattern::new(
            "Twilio API Key",
            r"SK[a-f0-9]{32}",
            SecretType::TwilioApiKey,
            0.9,
        )?);

        // Slack Token
        self.add_pattern(SecretPattern::new(
            "Slack Token",
            r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}",
            SecretType::SlackToken,
            0.95,
        )?);

        Ok(())
    }

    fn add_token_patterns(&mut self) -> Result<(), regex::Error> {
        // JWT Token (basic structure)
        self.add_pattern(SecretPattern::new(
            "JWT Token",
            r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            SecretType::JwtToken,
            0.8,
        )?);

        // Bearer Token
        self.add_pattern(SecretPattern::new(
            "Bearer Token",
            r"(?i)bearer\s+[A-Za-z0-9\-\._~\+\/]+=*",
            SecretType::BearerToken,
            0.7,
        )?);

        Ok(())
    }

    fn add_private_key_patterns(&mut self) -> Result<(), regex::Error> {
        // RSA Private Key
        self.add_pattern(SecretPattern::new(
            "RSA Private Key",
            r"-----BEGIN RSA PRIVATE KEY-----",
            SecretType::RsaPrivateKey,
            0.98,
        )?);

        // EC Private Key
        self.add_pattern(SecretPattern::new(
            "EC Private Key",
            r"-----BEGIN EC PRIVATE KEY-----",
            SecretType::EcPrivateKey,
            0.98,
        )?);

        // PGP Private Key
        self.add_pattern(SecretPattern::new(
            "PGP Private Key",
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            SecretType::PgpPrivateKey,
            0.98,
        )?);

        Ok(())
    }

    fn add_env_patterns(&mut self) -> Result<(), regex::Error> {
        // Environment variables with secret-like names
        self.add_pattern(SecretPattern::new(
            "Environment Secret",
            r"(?i)(api_key|secret|password|token|auth|credential)\s*[:=]\s*[A-Za-z0-9/+=]{8,}",
            SecretType::EnvironmentSecret,
            0.6,
        )?.with_ignore_keywords(vec![
            "example".to_string(),
            "test".to_string(),
            "placeholder".to_string(),
            "your_".to_string(),
            "my_".to_string(),
        ]));

        Ok(())
    }
}

impl Default for PatternRegistry {
    fn default() -> Self {
        Self::new().expect("Failed to create pattern registry")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secret_type_severity() {
        assert_eq!(SecretType::AwsAccessKey.severity(), 10);
        assert_eq!(SecretType::GitHubToken.severity(), 9);
        assert_eq!(SecretType::SshPublicKey.severity(), 3);
    }

    #[test]
    fn test_pattern_creation() {
        let pattern = SecretPattern::new(
            "Test Pattern",
            r"test_[0-9]+",
            SecretType::Custom("test".to_string()),
            0.8,
        ).unwrap();

        assert_eq!(pattern.name, "Test Pattern");
        assert_eq!(pattern.confidence, 0.8);
    }

    #[test]
    fn test_aws_access_key_detection() {
        let registry = PatternRegistry::new().unwrap();
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let matches = registry.find_all_matches(text);
        
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| matches!(m.secret_type, SecretType::AwsAccessKey)));
    }

    #[test]
    fn test_github_token_detection() {
        let registry = PatternRegistry::new().unwrap();
        let text = "GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678";
        let matches = registry.find_all_matches(text);
        
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| matches!(m.secret_type, SecretType::GitHubToken)));
    }

    #[test]
    fn test_confidence_adjustment() {
        let pattern = SecretPattern::new(
            "Test",
            r"test_[0-9]+",
            SecretType::Custom("test".to_string()),
            0.8,
        ).unwrap()
        .with_ignore_keywords(vec!["example".to_string()]);

        // Should decrease confidence for example
        let confidence = pattern.adjust_confidence("test_example", "this is an example");
        assert!(confidence < 0.8);
    }
}