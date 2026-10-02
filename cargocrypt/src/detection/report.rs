//! Scan reports: redacted findings rendered as text, JSON or SARIF 2.1.0.
//!
//! A report never contains a secret. Each finding carries a short redacted
//! preview and a fingerprint (a truncated SHA-256 of the rule and the matched
//! value) that identifies the secret stably without revealing it.

use crate::detection::Finding;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Output format of a scan report
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// Human-readable, one finding per line
    Text,
    /// JSON object with a `findings` array
    Json,
    /// SARIF 2.1.0, as consumed by GitHub code scanning
    Sarif,
}

/// A finding with the secret removed, safe to print or upload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReportFinding {
    /// Path of the file, relative to the scan root where possible, with `/`
    /// separators
    pub path: String,
    /// 1-based line
    pub line: usize,
    /// 1-based column
    pub column: usize,
    /// Stable rule identifier, e.g. `aws-access-key`
    pub rule_id: String,
    /// Human-readable secret type
    pub secret_type: String,
    /// Confidence score, 0.0 to 1.0
    pub confidence: f64,
    /// First characters of the match followed by its length
    pub redacted: String,
    /// Truncated SHA-256 over the rule id and matched value
    pub fingerprint: String,
}

/// A complete scan report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Version of cargocrypt that produced the report
    pub tool_version: String,
    /// Findings, ordered by path, line and column
    pub findings: Vec<ReportFinding>,
}

/// Lower-case, dash-separated identifier for a secret type.
pub fn rule_id(secret_type: &str) -> String {
    let mut id = String::with_capacity(secret_type.len());
    for c in secret_type.chars() {
        if c.is_ascii_alphanumeric() {
            id.push(c.to_ascii_lowercase());
        } else if !id.ends_with('-') && !id.is_empty() {
            id.push('-');
        }
    }
    id.trim_end_matches('-').to_string()
}

/// A preview that shows at most the first four characters of a secret.
pub fn redact(value: &str) -> String {
    let shown: String = value.chars().take(4).collect();
    let hidden = value.chars().count().saturating_sub(4);
    if hidden == 0 {
        // Too short to show anything without showing everything.
        return "*".repeat(value.chars().count());
    }
    format!("{}… ({} more characters)", shown, hidden)
}

fn fingerprint(rule: &str, value: &str) -> String {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(rule.as_bytes());
    ctx.update(b"\0");
    ctx.update(value.as_bytes());
    hex::encode(&ctx.finish().as_ref()[..16])
}

fn display_path(path: &Path, root: Option<&Path>) -> String {
    let relative = root.and_then(|r| path.strip_prefix(r).ok()).unwrap_or(path);
    let text = relative.to_string_lossy().replace('\\', "/");
    text.strip_prefix("./").unwrap_or(&text).to_string()
}

impl ScanReport {
    /// Build a report from raw findings. `root` is stripped from paths.
    pub fn new(findings: &[Finding], root: Option<&Path>) -> Self {
        let mut out: Vec<ReportFinding> = findings
            .iter()
            .filter(|f| !f.is_ignored)
            .map(|f| {
                let rule = rule_id(&f.secret.secret_type);
                ReportFinding {
                    path: display_path(&f.file_path, root),
                    line: f.secret.line_number,
                    column: f.secret.column_number,
                    fingerprint: fingerprint(&rule, &f.secret.value),
                    rule_id: rule,
                    secret_type: f.secret.secret_type.clone(),
                    confidence: f.confidence,
                    redacted: redact(&f.secret.value),
                }
            })
            .collect();

        out.sort_by(|a, b| {
            (&a.path, a.line, a.column, &a.rule_id).cmp(&(&b.path, b.line, b.column, &b.rule_id))
        });
        // Several detectors can flag the same value at the same place.
        out.dedup_by(|a, b| a.path == b.path && a.line == b.line && a.fingerprint == b.fingerprint);

        Self {
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            findings: out,
        }
    }

    /// Remove findings already recorded in `baseline`.
    ///
    /// A baseline is an earlier JSON report. A finding is "known" when the
    /// same secret (by fingerprint) sits in the same file; its line may move.
    /// Returns how many findings were suppressed.
    pub fn subtract_baseline(&mut self, baseline: &ScanReport) -> usize {
        let known: std::collections::HashSet<(&str, &str)> = baseline
            .findings
            .iter()
            .map(|f| (f.path.as_str(), f.fingerprint.as_str()))
            .collect();
        let before = self.findings.len();
        self.findings
            .retain(|f| !known.contains(&(f.path.as_str(), f.fingerprint.as_str())));
        before - self.findings.len()
    }

    /// Whether the scan found anything
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Render in the requested format
    pub fn render(&self, format: ReportFormat) -> String {
        match format {
            ReportFormat::Text => self.to_text(),
            ReportFormat::Json => self.to_json(),
            ReportFormat::Sarif => self.to_sarif(),
        }
    }

    /// `path:line:column: type (confidence) preview`, one per line
    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for f in &self.findings {
            out.push_str(&format!(
                "{}:{}:{}: {} [{}] confidence {:.0}%  {}\n",
                f.path,
                f.line,
                f.column,
                f.secret_type,
                f.rule_id,
                f.confidence * 100.0,
                f.redacted
            ));
        }
        match self.findings.len() {
            0 => out.push_str("No secrets found.\n"),
            1 => out.push_str("1 potential secret found.\n"),
            n => out.push_str(&format!("{} potential secrets found.\n", n)),
        }
        out
    }

    /// Pretty-printed JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serialises") + "\n"
    }

    /// SARIF 2.1.0
    pub fn to_sarif(&self) -> String {
        use serde_json::json;

        let mut rules: Vec<(&str, &str)> = self
            .findings
            .iter()
            .map(|f| (f.rule_id.as_str(), f.secret_type.as_str()))
            .collect();
        rules.sort();
        rules.dedup_by(|a, b| a.0 == b.0);

        let rules_json: Vec<_> = rules
            .iter()
            .map(|(id, name)| {
                json!({
                    "id": id,
                    "name": name,
                    "shortDescription": { "text": format!("{} committed in plain text", name) },
                    "help": { "text": "Remove the secret from the file, rotate it, and store it encrypted (`cargocrypt encrypt`)." },
                    "properties": { "tags": ["security", "secret"] }
                })
            })
            .collect();

        let results: Vec<_> = self
            .findings
            .iter()
            .map(|f| {
                json!({
                    "ruleId": f.rule_id,
                    "level": if f.confidence >= 0.7 { "error" } else { "warning" },
                    "message": {
                        "text": format!("{} detected ({}), confidence {:.0}%", f.secret_type, f.redacted, f.confidence * 100.0)
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": { "uri": f.path },
                            "region": { "startLine": f.line.max(1), "startColumn": f.column.max(1) }
                        }
                    }],
                    "partialFingerprints": { "cargocryptSecret/v1": f.fingerprint },
                    "properties": { "confidence": f.confidence }
                })
            })
            .collect();

        let sarif = json!({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "cargocrypt",
                        "version": self.tool_version,
                        "informationUri": "https://github.com/marcuspat/cargocrypt",
                        "rules": rules_json
                    }
                },
                "results": results
            }]
        });
        serde_json::to_string_pretty(&sarif).expect("sarif serialises") + "\n"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detection::FoundSecret;
    use std::path::PathBuf;

    const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

    fn finding(path: &str, line: usize, confidence: f64) -> Finding {
        Finding::new(
            PathBuf::from(path),
            FoundSecret::new(
                SECRET.to_string(),
                "AWS Access Key".to_string(),
                0,
                20,
                line,
                5,
            ),
            confidence,
            "pattern".to_string(),
        )
    }

    #[test]
    fn rule_ids_are_stable_slugs() {
        assert_eq!(rule_id("AWS Access Key"), "aws-access-key");
        assert_eq!(rule_id("GitHub Token (classic)"), "github-token-classic");
    }

    #[test]
    fn no_format_ever_contains_the_secret() {
        let report = ScanReport::new(&[finding("/repo/.env", 3, 0.95)], Some(Path::new("/repo")));
        for format in [ReportFormat::Text, ReportFormat::Json, ReportFormat::Sarif] {
            let rendered = report.render(format);
            assert!(!rendered.contains(SECRET), "{:?} leaked the secret", format);
            assert!(
                !rendered.contains(&SECRET[..8]),
                "{:?} leaked a prefix",
                format
            );
            assert!(rendered.contains(".env"));
        }
    }

    #[test]
    fn redaction_never_shows_a_short_value_whole() {
        assert_eq!(redact("abcd"), "****");
        assert_eq!(redact("abcde"), "abcd… (1 more characters)");
        assert_eq!(redact("ключ-секрет"), "ключ… (7 more characters)");
    }

    #[test]
    fn findings_are_ordered_relative_and_deduplicated() {
        let report = ScanReport::new(
            &[
                finding("/repo/b.rs", 9, 0.9),
                finding("/repo/a.rs", 2, 0.9),
                finding("/repo/a.rs", 2, 0.6), // same value, second detector
            ],
            Some(Path::new("/repo")),
        );
        let places: Vec<_> = report
            .findings
            .iter()
            .map(|f| (f.path.as_str(), f.line))
            .collect();
        assert_eq!(places, vec![("a.rs", 2), ("b.rs", 9)]);
        assert_eq!(
            report.findings[0].fingerprint,
            report.findings[1].fingerprint
        );
        assert_eq!(report.findings[0].fingerprint.len(), 32);
    }

    #[test]
    fn sarif_has_the_shape_code_scanning_expects() {
        let report = ScanReport::new(
            &[
                finding("/repo/.env", 3, 0.95),
                finding("/repo/x.rs", 1, 0.55),
            ],
            Some(Path::new("/repo")),
        );
        let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif()).unwrap();

        assert_eq!(sarif["version"], "2.1.0");
        let run = &sarif["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "cargocrypt");
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "aws-access-key");

        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["ruleId"], "aws-access-key");
        assert_eq!(results[0]["level"], "error");
        assert_eq!(results[1]["level"], "warning");
        let location = &results[0]["locations"][0]["physicalLocation"];
        assert_eq!(location["artifactLocation"]["uri"], ".env");
        assert_eq!(location["region"]["startLine"], 3);
        assert!(results[0]["partialFingerprints"]["cargocryptSecret/v1"].is_string());
    }

    #[test]
    fn baseline_suppresses_known_findings_even_when_they_move() {
        let baseline = ScanReport::new(&[finding("/repo/.env", 3, 0.95)], Some(Path::new("/repo")));
        let mut current = ScanReport::new(
            &[
                finding("/repo/.env", 12, 0.95),
                finding("/repo/new.env", 1, 0.95),
            ],
            Some(Path::new("/repo")),
        );

        assert_eq!(current.subtract_baseline(&baseline), 1);
        assert_eq!(current.findings.len(), 1);
        assert_eq!(current.findings[0].path, "new.env");
    }

    #[test]
    fn empty_report_is_clean_and_still_valid_sarif() {
        let report = ScanReport::new(&[], None);
        assert!(report.is_clean());
        assert!(report.to_text().contains("No secrets found"));
        let sarif: serde_json::Value = serde_json::from_str(&report.to_sarif()).unwrap();
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
