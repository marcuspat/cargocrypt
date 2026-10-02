//! A last check on candidates produced by the generic detectors.
//!
//! Provider rules (`AKIA…`, `ghp_…`) are anchored to a format and need no
//! help. The generic detectors (entropy, keyword context, `KEY=value`) work
//! from statistics, and source code is full of strings that are long and
//! varied without being secret: identifiers, type names, hashes, URLs. This
//! module says whether a value could plausibly be a credential at all.

/// Whether `value` could be a secret. `false` means it reads as an
/// identifier, a word, a hash, a path or a piece of code.
pub fn is_plausible_secret(value: &str) -> bool {
    let value = value.trim_matches(|c| c == '"' || c == '\'' || c == '`');

    if value.chars().count() < 8 {
        return false;
    }
    if looks_like_code(value) || looks_like_location(value) {
        return false;
    }
    if is_hex_digest(value) || is_uuid(value) || is_public_material(value) {
        return false;
    }
    if is_wordy(value) || is_mostly_sequential(value) {
        return false;
    }
    // A credential drawn from a real alphabet almost always mixes classes.
    // Letters only is prose or an identifier; digits only is a number.
    let has_alpha = value.chars().any(|c| c.is_alphabetic());
    let has_digit = value.chars().any(|c| c.is_ascii_digit());
    let has_symbol = value
        .chars()
        .any(|c| !c.is_alphanumeric() && !matches!(c, '_' | '-' | '.'));
    (has_alpha && has_digit) || (has_alpha && has_symbol && has_mixed_case(value))
}

/// Hex strings of 32 or more characters: digests, checksums, commit ids.
/// A bare one is not reportable; a keyword-anchored rule may still claim it.
pub fn is_hex_digest(value: &str) -> bool {
    value.len() >= 32 && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Alphabets and counting runs (`abcdef…`, `1234567890`): placeholders and
/// character-set constants, not key material.
fn is_mostly_sequential(value: &str) -> bool {
    let chars: Vec<u32> = value
        .chars()
        .filter(|c| c.is_alphanumeric())
        .map(|c| c as u32)
        .collect();
    if chars.len() < 8 {
        return false;
    }
    let steps = chars
        .windows(2)
        .filter(|w| w[1] == w[0] + 1 || (w[0] == '9' as u32 && w[1] == '0' as u32))
        .count();
    steps * 10 >= (chars.len() - 1) * 6
}

/// Whether `word` is a URL that carries no credentials.
pub fn is_plain_url(word: &str) -> bool {
    word.contains("://") && looks_like_location(word)
}

/// `8-4-4-4-12` hex: an identifier, not a credential.
fn is_uuid(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, len)| p.len() == len && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// Values that are high-entropy but meant to be published: SSH public key
/// blobs and publishable API keys.
fn is_public_material(value: &str) -> bool {
    ["AAAAB3Nza", "AAAAC3Nza", "AAAAE2Vj", "pk_live_", "pk_test_"]
        .iter()
        .any(|prefix| value.starts_with(prefix))
}

fn has_mixed_case(value: &str) -> bool {
    value.chars().any(|c| c.is_uppercase()) && value.chars().any(|c| c.is_lowercase())
}

/// Expressions, calls, generics, references, interpolations.
fn looks_like_code(value: &str) -> bool {
    value.contains("::")
        || value.contains("->")
        || value.contains("=>")
        || value.chars().any(|c| {
            matches!(
                c,
                '(' | ')' | '{' | '}' | '<' | '>' | '[' | ']' | ';' | ',' | '\\'
            )
        })
        || value.starts_with(['$', '&', '%', '*', '!', '@'])
}

/// URLs without credentials, file paths, dotted module paths.
fn looks_like_location(value: &str) -> bool {
    if let Some(rest) = value.split_once("://").map(|(_, rest)| rest) {
        // A URL is only interesting when it embeds `user:password@`.
        let authority = rest.split('/').next().unwrap_or("");
        return !(authority.contains('@') && authority.contains(':'));
    }
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('~')
}

/// Whether every segment between separators is a word, a short number, or a
/// word with a short numeric suffix (`sha256`, `Poly1305`, `v2`).
fn is_wordy(value: &str) -> bool {
    let mut segments = value
        .split(['_', '-', '.', ' ', ':', '/', '+', '='])
        .filter(|s| !s.is_empty())
        .peekable();
    if segments.peek().is_none() {
        return true;
    }
    segments.all(is_word_like)
}

fn is_word_like(segment: &str) -> bool {
    if segment.chars().all(|c| c.is_ascii_digit()) {
        // Counters and dates, not key material.
        return segment.len() <= 8;
    }

    // Break into alternating runs of letters and digits. A name is one or
    // two words each followed by a short number (`sha256`,
    // `chacha20poly1305`); key material alternates far more often or
    // carries long digit runs.
    let mut letter_runs: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut digits = 0usize;
    for c in segment.chars() {
        if c.is_alphabetic() {
            if digits > 0 {
                digits = 0;
            }
            current.push(c);
        } else if c.is_ascii_digit() {
            if !current.is_empty() {
                letter_runs.push(std::mem::take(&mut current));
            } else if letter_runs.is_empty() {
                return false; // starts with digits, then letters
            }
            digits += 1;
            if digits > 4 {
                return false;
            }
        } else {
            return false;
        }
    }
    if !current.is_empty() {
        letter_runs.push(current);
    }

    // A rhythm test on the letters: random letters change case without
    // pattern and go long stretches without a vowel.
    (1..=3).contains(&letter_runs.len())
        && letter_runs
            .iter()
            .all(|run| (letter_runs.len() == 1 || run.len() >= 2) && reads_as_words(run))
}

fn reads_as_words(letters: &str) -> bool {
    if !letters.is_ascii() {
        return true; // non-English prose; no opinion
    }
    // Split CamelCase into words, keeping acronym runs together.
    let chars: Vec<char> = letters.chars().collect();
    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    for (i, &c) in chars.iter().enumerate() {
        let boundary = i > 0
            && c.is_uppercase()
            && (chars[i - 1].is_lowercase() || chars.get(i + 1).is_some_and(|n| n.is_lowercase()));
        if boundary && !current.is_empty() {
            words.push(std::mem::take(&mut current));
        }
        current.push(c);
    }
    if !current.is_empty() {
        words.push(current);
    }

    let is_vowel = |c: char| matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u' | 'y');
    let mut odd = 0usize;
    for word in &words {
        let len = word.len();
        let vowels = word.chars().filter(|&c| is_vowel(c)).count();
        let mut run = 0usize;
        let mut longest_consonant_run = 0usize;
        for c in word.chars() {
            if is_vowel(c) {
                run = 0;
            } else {
                run += 1;
                longest_consonant_run = longest_consonant_run.max(run);
            }
        }
        let all_caps = word.chars().all(|c| c.is_uppercase());
        // Short words and abbreviations (rfc, src, tmp, http) and acronyms
        // (HTTPS, ASCII) pass as they are; longer runs need a word's rhythm.
        let plausible =
            len <= 4 || (all_caps && len <= 5) || (vowels > 0 && longest_consonant_run <= 4);
        if !plausible {
            odd += 1;
        }
    }
    // Many tiny CamelCase fragments is what random mixed-case text looks like.
    let fragments = words.iter().filter(|w| w.len() <= 2).count();
    odd == 0 && (words.len() < 4 || fragments * 2 < words.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_types_and_prose_are_not_secrets() {
        for value in [
            "icu_properties_data",
            "add_error_with_suggestion",
            "render_confirm_dialog",
            "PlaintextSecret",
            "EncryptedSecret",
            "contextual_analyzer",
            "test_password",
            "benchmark_password_12345",
            "wrong_password",
            "XChaCha20-Poly1305",
            "ChaCha20-Poly1305",
            "chacha20poly1305",
            "Management",
            "sha256_hash_or_token",
            "2026-10-01",
            "HTTPRequestBuilder",
            "KDF_ARGON2ID_V13",
            "test_chacha20poly1305_rfc8439_vector",
            "draft-irtf-cfrg-xchacha-03",
        ] {
            assert!(!is_plausible_secret(value), "{} was accepted", value);
        }
    }

    #[test]
    fn code_paths_urls_and_hashes_are_not_secrets() {
        for value in [
            "PlaintextSecret::from_string(data)",
            "get_password()",
            "${DATABASE_PASSWORD}",
            "&self.password",
            "https://img.shields.io/badge/tests-passing.svg",
            "/etc/ssl/private/server.key",
            "5c839a674fcd7a98952e593242ea400abe93992746761e38641405d28b00f419",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "3f2504e0-4f89-11d3-9a0c-0305e82c3301",
            "AAAAC3NzaC1lZDI1NTE5AAAAIGq8kPbT0m1cE2vR5xW9yZ3aB4dF6hJ7kL0nQ2sU4wX",
            "pk_live_A1b2C3d4E5f6G7h8I9j0K1l2",
            "redis://localhost:6379/0",
            "sk-1234567890abcdef",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        ] {
            assert!(!is_plausible_secret(value), "{} was accepted", value);
        }
    }

    #[test]
    fn credential_shaped_values_are_kept() {
        let aws_secret = ["wJalrXUtnFEMI/K7MDENG", "/bPxRfiCYEXAMPLEKEY"].concat();
        let url_with_credentials =
            format!("postgres://{}:{}@db.internal:5432/app", "admin", "q7Lm2Xv9");
        for value in [
            aws_secret.as_str(),
            "dGVzdF9zZWNyZXRfa2V5XzEyMzQ1Njc4OTA=",
            "xK9mP2vL8nQ4wR7tY3uI6oA1sD5fG0hJ",
            "Tr0ub4dor&3xKq9",
            url_with_credentials.as_str(),
            "7f3a9c2e1b8d4f6a",
            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU",
        ] {
            assert!(is_plausible_secret(value), "{} was rejected", value);
        }
    }

    #[test]
    fn hex_digest_detection() {
        assert!(is_hex_digest("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert!(!is_hex_digest("7f3a9c2e1b8d4f6a"));
        assert!(!is_hex_digest("not-hex-at-all-but-long-enough-to-count"));
    }
}
