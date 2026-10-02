//! Secret detection patterns
//!
//! This module contains regex-based patterns modeled on real-world secret leak
//! formats to minimize false positives while maintaining high recall rates.

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
    GitHubFineGrainedToken,

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
    AnthropicApiKey,
    OpenAiApiKey,
    GoogleApiKey,
    NpmToken,

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
            SecretType::GitHubFineGrainedToken => "GitHub Fine-Grained Token",
            SecretType::AnthropicApiKey => "Anthropic API Key",
            SecretType::OpenAiApiKey => "OpenAI API Key",
            SecretType::GoogleApiKey => "Google API Key",
            SecretType::NpmToken => "npm Access Token",
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
            SecretType::GitHubToken
            | SecretType::GitHubAppToken
            | SecretType::GitHubFineGrainedToken => 9,
            SecretType::AnthropicApiKey
            | SecretType::OpenAiApiKey
            | SecretType::GoogleApiKey
            | SecretType::NpmToken => 8,
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
            if context_lower.contains(&keyword.to_lowercase())
                || matched_lower.contains(&keyword.to_lowercase())
            {
                confidence -= 0.2;
            }
        }

        // Special adjustments for common false positives
        if matched_lower.contains("example")
            || matched_lower.contains("sample")
            || matched_lower.contains("test")
            || matched_lower.contains("placeholder")
            || matched_lower.contains("dummy")
        {
            confidence -= 0.3;
        }

        // Ensure confidence stays in valid range
        confidence.clamp(0.0, 1.0)
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
            .or_default()
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
            .map(|indices| indices.iter().map(|&i| &self.patterns[i]).collect())
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
        self.add_pattern(
            SecretPattern::new(
                "AWS Access Key ID",
                r"(?i)(AKIA[0-9A-Z]{16})",
                SecretType::AwsAccessKey,
                0.95,
            )?
            .with_context_keywords(vec![
                "aws".to_string(),
                "amazon".to_string(),
                "access".to_string(),
                "key".to_string(),
            ]),
        );

        // AWS Secret Access Key
        self.add_pattern(
            SecretPattern::new(
                "AWS Secret Access Key",
                r"(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*([A-Za-z0-9/+=]{40})",
                SecretType::AwsSecretKey,
                0.90,
            )?
            .with_context_keywords(vec!["secret".to_string(), "aws".to_string()]),
        );

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
        // Personal, OAuth, user-to-server, server-to-server and refresh
        // tokens: a fixed prefix and 36 base62 characters.
        self.add_pattern(
            SecretPattern::new(
                "GitHub Personal Access Token",
                r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
                SecretType::GitHubToken,
                0.95,
            )?
            .with_context_keywords(vec![
                "github".to_string(),
                "token".to_string(),
                "pat".to_string(),
            ]),
        );

        // Fine-grained personal access token.
        self.add_pattern(SecretPattern::new(
            "GitHub Fine-Grained Token",
            r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
            SecretType::GitHubFineGrainedToken,
            0.98,
        )?);

        // The pre-2021 token format was 40 bare hex characters, which is also
        // every SHA-1 and git commit id. An unanchored rule for it reported
        // hundreds of checksums per repository, so there is none: such a
        // token is still reported when it is assigned to a secret-named key.

        Ok(())
    }

    fn add_ssh_patterns(&mut self) -> Result<(), regex::Error> {
        // SSH Private Key
        self.add_pattern(SecretPattern::new(
            "SSH Private Key",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s*[A-Za-z0-9+/]{20}",
            SecretType::SshPrivateKey,
            0.98,
        )?);

        // No rule for SSH public keys: they are public.

        Ok(())
    }

    fn add_database_patterns(&mut self) -> Result<(), regex::Error> {
        // PostgreSQL URL
        self.add_pattern(SecretPattern::new(
            "PostgreSQL Connection String",
            r"postgres(?:ql)?://[^\s:/@]+:[^\s@/]+@[^\s]+",
            SecretType::PostgresUrl,
            0.9,
        )?);

        // MySQL URL
        self.add_pattern(SecretPattern::new(
            "MySQL Connection String",
            r"mysql://[^\s:/@]+:[^\s@/]+@[^\s]+",
            SecretType::MySqlUrl,
            0.9,
        )?);

        // MongoDB URL
        self.add_pattern(SecretPattern::new(
            "MongoDB Connection String",
            r"mongodb(?:\+srv)?://[^\s:/@]+:[^\s@/]+@[^\s]+",
            SecretType::MongoDbUrl,
            0.9,
        )?);

        // Redis URL
        self.add_pattern(SecretPattern::new(
            "Redis Connection String",
            r"rediss?://[^\s:/@]*:[^\s@/]+@[^\s]+",
            SecretType::RedisUrl,
            0.85,
        )?);

        Ok(())
    }

    fn add_api_key_patterns(&mut self) -> Result<(), regex::Error> {
        // Stripe API Key
        self.add_pattern(SecretPattern::new(
            "Stripe API Key",
            r"\b(sk|rk)_(test|live)_[a-zA-Z0-9]{16,99}\b",
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

        // Anthropic API key
        self.add_pattern(SecretPattern::new(
            "Anthropic API Key",
            r"\bsk-ant-[A-Za-z0-9]{2,12}-[A-Za-z0-9_\-]{40,}",
            SecretType::AnthropicApiKey,
            0.98,
        )?);

        // OpenAI project, service-account and legacy keys
        self.add_pattern(SecretPattern::new(
            "OpenAI API Key",
            r"\bsk-(proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b",
            SecretType::OpenAiApiKey,
            0.95,
        )?);

        // Google API key
        self.add_pattern(SecretPattern::new(
            "Google API Key",
            r"\bAIza[0-9A-Za-z_\-]{35}\b",
            SecretType::GoogleApiKey,
            0.95,
        )?);

        // npm access token
        self.add_pattern(SecretPattern::new(
            "npm Access Token",
            r"\bnpm_[A-Za-z0-9]{36}\b",
            SecretType::NpmToken,
            0.95,
        )?);

        // Slack Token
        self.add_pattern(SecretPattern::new(
            "Slack Token",
            r"\bxox[abeoprs]-[0-9A-Za-z]{8,}(-[0-9A-Za-z]{8,}){1,4}\b",
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
            r"(?i)\bbearer\s+[A-Za-z0-9\-\._~\+\/]{20,}=*",
            SecretType::BearerToken,
            0.7,
        )?);

        Ok(())
    }

    fn add_private_key_patterns(&mut self) -> Result<(), regex::Error> {
        // RSA Private Key
        self.add_pattern(SecretPattern::new(
            "RSA Private Key",
            r"-----BEGIN RSA PRIVATE KEY-----\s*[A-Za-z0-9+/]{20}",
            SecretType::RsaPrivateKey,
            0.98,
        )?);

        // EC Private Key
        self.add_pattern(SecretPattern::new(
            "EC Private Key",
            r"-----BEGIN EC PRIVATE KEY-----\s*[A-Za-z0-9+/]{20}",
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
        self.add_pattern(
            SecretPattern::new(
                "Environment Secret",
                r"(?i)(api_key|secret|password|token|auth|credential)\s*[:=]\s*[A-Za-z0-9/+=]{8,}",
                SecretType::EnvironmentSecret,
                0.6,
            )?
            .with_ignore_keywords(vec![
                "example".to_string(),
                "test".to_string(),
                "placeholder".to_string(),
                "your_".to_string(),
                "my_".to_string(),
            ]),
        );

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
        )
        .unwrap();

        assert_eq!(pattern.name, "Test Pattern");
        assert_eq!(pattern.confidence, 0.8);
    }

    #[test]
    fn test_aws_access_key_detection() {
        let registry = PatternRegistry::new().unwrap();
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let matches = registry.find_all_matches(text);

        assert!(!matches.is_empty());
        assert!(matches
            .iter()
            .any(|m| matches!(m.secret_type, SecretType::AwsAccessKey)));
    }

    #[test]
    fn test_github_token_detection() {
        let registry = PatternRegistry::new().unwrap();
        // Assembled at run time so no token-shaped literal sits in the repo.
        let body = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
        let text = format!("GITHUB_TOKEN=ghp_{}", body);
        let matches = registry.find_all_matches(&text);

        assert!(matches
            .iter()
            .any(|m| matches!(m.secret_type, SecretType::GitHubToken)));
    }

    fn types_found(text: &str) -> Vec<SecretType> {
        PatternRegistry::new()
            .unwrap()
            .find_all_matches(text)
            .into_iter()
            .map(|m| m.secret_type)
            .collect()
    }

    #[test]
    fn test_current_provider_token_formats() {
        let b62 =
            "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0E1f2G3h4I5j6K7l8M9n0O1p2";
        let cases: Vec<(String, SecretType)> = vec![
            (
                format!("github_pat_{}_{}", &b62[..22], &b62[..59]),
                SecretType::GitHubFineGrainedToken,
            ),
            (format!("gho_{}", &b62[..36]), SecretType::GitHubToken),
            (
                format!("sk-ant-api03-{}", &b62[..80]),
                SecretType::AnthropicApiKey,
            ),
            (format!("sk-proj-{}", &b62[..48]), SecretType::OpenAiApiKey),
            (format!("AIza{}", &b62[..35]), SecretType::GoogleApiKey),
            (format!("npm_{}", &b62[..36]), SecretType::NpmToken),
            (
                format!("xoxb-{}-{}-{}", &b62[..12], &b62[..12], &b62[..24]),
                SecretType::SlackToken,
            ),
            (format!("rk_live_{}", &b62[..24]), SecretType::StripeApiKey),
        ];
        for (token, expected) in cases {
            let found = types_found(&format!("KEY={}", token));
            assert!(found.contains(&expected), "{:?} not found", expected);
        }
    }

    #[test]
    fn test_hashes_and_headers_are_not_tokens() {
        // A SHA-1 / commit id is not a GitHub token.
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        assert!(!types_found(sha1).contains(&SecretType::GitHubToken));
        let checksum = format!("checksum = \"{}{}\"", sha1, &sha1[..24]);
        assert!(types_found(&checksum).is_empty());

        // Mentioning a PEM header or the word "bearer" is not a key.
        assert!(types_found("looks for -----BEGIN RSA PRIVATE KEY----- headers").is_empty());
        assert!(types_found("JWT tokens and bearer tokens").is_empty());
        // Publishable Stripe keys are public by design.
        assert!(types_found("pk_live_A1b2C3d4E5f6G7h8I9j0K1l2").is_empty());
    }

    #[test]
    fn test_confidence_adjustment() {
        let pattern = SecretPattern::new(
            "Test",
            r"test_[0-9]+",
            SecretType::Custom("test".to_string()),
            0.8,
        )
        .unwrap()
        .with_ignore_keywords(vec!["example".to_string()]);

        // Should decrease confidence for example
        let confidence = pattern.adjust_confidence("test_example", "this is an example");
        assert!(confidence < 0.8);
    }
}
