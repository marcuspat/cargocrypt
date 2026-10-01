//! The git clean/smudge filters must fail closed.

use assert_cmd::Command;
use std::fs;
use tempfile::TempDir;

fn project() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    dir
}

/// A `cargocrypt` invocation isolated from the developer's own git config.
fn cargocrypt(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cargocrypt").unwrap();
    cmd.current_dir(dir.path())
        .env_remove("CARGOCRYPT_PASSWORD")
        .env("HOME", dir.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dir.path().join("no-such-gitconfig"));
    cmd
}

#[test]
fn clean_filter_refuses_to_run_without_a_password() {
    let dir = project();
    let out = cargocrypt(&dir)
        .args(["git", "filter-clean"])
        .write_stdin("API_KEY=hunter2\n")
        .assert()
        .failure();
    assert!(
        out.get_output().stdout.is_empty(),
        "nothing may be emitted when no password is configured"
    );
}

#[test]
fn smudge_filter_fails_on_wrong_password_instead_of_emitting_ciphertext() {
    let dir = project();
    let plaintext = "API_KEY=hunter2\n";

    let clean = cargocrypt(&dir)
        .env("CARGOCRYPT_PASSWORD", "correct horse battery staple")
        .args(["git", "filter-clean"])
        .write_stdin(plaintext)
        .assert()
        .success();
    let ciphertext = clean.get_output().stdout.clone();
    assert!(!ciphertext.is_empty());

    let roundtrip = cargocrypt(&dir)
        .env("CARGOCRYPT_PASSWORD", "correct horse battery staple")
        .args(["git", "filter-smudge"])
        .write_stdin(ciphertext.clone())
        .assert()
        .success();
    assert_eq!(roundtrip.get_output().stdout, plaintext.as_bytes());

    let wrong = cargocrypt(&dir)
        .env("CARGOCRYPT_PASSWORD", "not the password at all 123")
        .args(["git", "filter-smudge"])
        .write_stdin(ciphertext)
        .assert()
        .failure();
    assert!(wrong.get_output().stdout.is_empty());
}
