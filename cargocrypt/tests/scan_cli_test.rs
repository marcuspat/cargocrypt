//! `cargocrypt scan`: exit codes, formats, redaction, staged mode.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

fn scan(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cargocrypt").unwrap();
    cmd.current_dir(dir.path()).arg("scan");
    cmd
}

fn tree_with_secret() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("src")).unwrap();
    fs::write(
        dir.path().join(".env"),
        format!("AWS_ACCESS_KEY_ID={}\nDEBUG=true\n", SECRET),
    )
    .unwrap();
    fs::write(dir.path().join("src/main.rs"), "fn main() {}\n").unwrap();
    dir
}

#[test]
fn clean_tree_exits_zero() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    scan(&dir).assert().code(0);
}

#[test]
fn secret_in_a_dotfile_exits_one_and_is_redacted() {
    let dir = tree_with_secret();
    let out = scan(&dir).assert().code(1);
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();

    assert!(stdout.contains(".env:1:"), "{}", stdout);
    assert!(stdout.contains("aws-access-key"), "{}", stdout);
    assert!(!stdout.contains(SECRET), "the secret was printed");
}

#[test]
fn no_fail_reports_but_exits_zero() {
    let dir = tree_with_secret();
    let out = scan(&dir).arg("--no-fail").assert().code(0);
    assert!(String::from_utf8_lossy(&out.get_output().stdout).contains(".env"));
}

#[test]
fn missing_path_exits_two() {
    let dir = TempDir::new().unwrap();
    scan(&dir).arg("does-not-exist").assert().code(2);
}

#[test]
fn json_output_is_machine_readable() {
    let dir = tree_with_secret();
    let out = scan(&dir).args(["--format", "json"]).assert().code(1);
    let json: serde_json::Value = serde_json::from_slice(&out.get_output().stdout).unwrap();

    let findings = json["findings"].as_array().unwrap();
    assert!(findings
        .iter()
        .any(|f| f["path"] == ".env" && f["rule_id"] == "aws-access-key" && f["line"] == 1));
    assert!(!json.to_string().contains(SECRET));
}

#[test]
fn sarif_output_goes_to_a_file() {
    let dir = tree_with_secret();
    let out = scan(&dir)
        .args(["--format", "sarif", "--output", "results.sarif"])
        .assert()
        .code(1);
    assert!(out.get_output().stdout.is_empty());

    let text = fs::read_to_string(dir.path().join("results.sarif")).unwrap();
    assert!(!text.contains(SECRET));
    let sarif: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert!(sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["ruleId"] == "aws-access-key"
            && r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".env"));
}

#[test]
fn min_confidence_filters_findings() {
    let dir = tree_with_secret();
    scan(&dir)
        .args(["--min-confidence", "1.0"])
        .assert()
        .code(0);
    scan(&dir).args(["--min-confidence", "7"]).assert().code(2);
}

#[test]
fn staged_mode_scans_the_index_not_the_working_tree() {
    let dir = tree_with_secret();
    let git = |args: &[&str]| {
        let status = std::process::Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(status.status.success(), "git {:?}", args);
    };
    git(&["init", "-q"]);

    // Nothing staged: clean, even though the working tree holds a secret.
    scan(&dir).arg("--staged").assert().code(0);

    git(&["add", ".env"]);
    // The working copy is cleaned up, but the staged blob still has the key.
    fs::write(dir.path().join(".env"), "DEBUG=true\n").unwrap();
    let out = scan(&dir).arg("--staged").assert().code(1);
    assert!(String::from_utf8_lossy(&out.get_output().stdout).contains(".env"));
}
