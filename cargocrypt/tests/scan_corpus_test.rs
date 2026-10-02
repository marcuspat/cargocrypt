//! Precision and recall of the detector on a small labelled corpus.
//!
//! The corpus is synthetic and written for this project: it measures
//! regressions, it is not an independent benchmark. Token-shaped values are
//! assembled at run time so that no credential-shaped literal is committed.

use cargocrypt::detection::SecretDetector;

const B62: &str =
    "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6A7b8C9d0E1f2G3h4I5j6K7l8M9n0O1p2";
const RANDOM: &str = "xK9mP2vL8nQ4wR7tY3uI6oA1sD5fG0hJ";

/// Lines that each contain exactly one secret.
fn positives() -> Vec<String> {
    vec![
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE".to_string(),
        format!(
            "aws_secret_access_key = {}{}",
            "wJalrXUtnFEMI/K7MDENG", "/bPxRfiCYEXAMPLEKEY"
        ),
        format!("GITHUB_TOKEN=ghp_{}", &B62[..36]),
        format!("token: github_pat_{}_{}", &B62[..22], &B62[..59]),
        format!("ANTHROPIC_API_KEY=sk-ant-api03-{}", &B62[..80]),
        format!("OPENAI_API_KEY=sk-proj-{}", &B62[..48]),
        format!("const MAPS_KEY: &str = \"AIza{}\";", &B62[..35]),
        format!("//registry.npmjs.org/:_authToken=npm_{}", &B62[..36]),
        format!(
            "SLACK_BOT_TOKEN=xoxb-{}-{}-{}",
            &B62[..12],
            &B62[..12],
            &B62[..24]
        ),
        format!("stripe_key = \"sk_live_{}\"", &B62[..24]),
        "DATABASE_URL=postgres://admin:s3cr3tP4ss@db.internal:5432/app".to_string(),
        "url: mongodb+srv://svc:Zx81kQp02mN@cluster0.example.mongodb.net/prod".to_string(),
        format!("api_key = \"{}\"", RANDOM),
        format!("  password: \"{}\"", "Tr0ub4dor&3xKq9zW"),
        format!("\"client_secret\": \"{}\"", RANDOM),
        format!("export SESSION_SECRET={}", RANDOM),
        format!("Authorization: Bearer {}{}", RANDOM, RANDOM),
        format!(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA{}\n-----END RSA PRIVATE KEY-----",
            &B62[..48]
        ),
        format!(
            "jwt = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.{}\"",
            &B62[..43]
        ),
        format!("auth_token = '{}'", &B62[10..50]),
    ]
}

/// Text with no secret in it, of the kinds a repository is full of.
const NEGATIVES: &[&str] = &[
    "//! This module provides secure cryptographic operations using ChaCha20-Poly1305",
    "use chacha20poly1305::{aead::Aead, XChaCha20Poly1305, XNonce};",
    "const KDF_ARGON2ID_V13: u8 = 1;",
    "fn render_confirm_dialog(message: &str, frame: &mut Frame) {",
    "    let password = prompt_password(\"Enter password for encryption: \")?;",
    "    let password = \"test_password\";",
    "    let secret = PlaintextSecret::from_string(data);",
    "    let encrypted: EncryptedSecret = EncryptedSecret::from_bytes(&serialized)?;",
    "    let token = std::env::var(\"GITHUB_TOKEN\")?;",
    "    result.add_error_with_suggestion(\"icu_properties_data\");",
    "    pub fn decrypt_with_password(&self, password: &str) -> CryptoResult<PlaintextSecret> {",
    "checksum = \"5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419\"",
    "commit da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "    integrity sha512-abc is recorded in the lock file",
    "#### Password Management",
    "- JWT tokens and bearer tokens",
    "The pre-commit hook looks for -----BEGIN RSA PRIVATE KEY----- headers.",
    "[![Crates.io](https://img.shields.io/crates/v/cargocrypt.svg)](https://crates.io/crates/cargocrypt)",
    "DATABASE_URL=${DATABASE_URL}",
    "password: ${{ secrets.DEPLOY_PASSWORD }}",
    "API_KEY=your_api_key_here",
    "SECRET_KEY=changeme",
    "token = \"<your-token>\"",
    "redis_url = \"redis://localhost:6379/0\"",
    "DATABASE_URL=postgres://localhost/app_development",
    "id: 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
    "version = \"0.2.3\"",
    "repository = \"https://github.com/marcuspat/cargocrypt\"",
    "    timeout_secs: 300, max_retries: 3, buffer_size: 65536,",
    "test result: ok. 157 passed; 0 failed; 0 ignored; finished in 5.45s",
    "let authentication_failed_message = \"authentication failed\";",
    "pk_live_A1b2C3d4E5f6G7h8I9j0K1l2",
    "private_key_path = \"/etc/ssl/private/server.key\"",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq8kPbT0m1cE2vR5xW9yZ3aB4dF6hJ7kL0nQ2sU4wX deploy@host",
    "\"token_type\": \"Bearer\", \"expires_in\": 3600",
    "func getSecretFromEnvironment(name string) (string, error) {",
];

const THRESHOLD: f64 = 0.5;

#[test]
fn precision_and_recall_on_the_labelled_corpus() {
    let detector = SecretDetector::new();
    let hit = |text: &str, name: &str| -> usize {
        detector
            .scan_content(text, name)
            .unwrap()
            .into_iter()
            .filter(|f| f.confidence >= THRESHOLD)
            .count()
    };

    let positives = positives();
    let mut missed = Vec::new();
    let mut true_positives = 0;
    for line in &positives {
        if hit(line, "config.env") > 0 {
            true_positives += 1;
        } else {
            missed.push(line.split(['=', ':']).next().unwrap_or("").to_string());
        }
    }

    let mut false_positives = Vec::new();
    for line in NEGATIVES {
        if hit(line, "src/lib.rs") > 0 {
            false_positives.push(*line);
        }
    }

    let recall = true_positives as f64 / positives.len() as f64;
    let precision = true_positives as f64 / (true_positives + false_positives.len()).max(1) as f64;
    println!(
        "corpus: {} positives, {} negatives; recall {:.2} ({} missed: {:?}); precision {:.2} ({} false positives: {:#?})",
        positives.len(),
        NEGATIVES.len(),
        recall,
        missed.len(),
        missed,
        precision,
        false_positives.len(),
        false_positives
    );

    assert!(recall >= 0.90, "recall {:.2}; missed {:?}", recall, missed);
    assert!(
        precision >= 0.90,
        "precision {:.2}; false positives {:#?}",
        precision,
        false_positives
    );
}
