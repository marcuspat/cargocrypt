//! Password sources, project configuration and the plaintext backup.

use assert_cmd::Command;
use cargocrypt::{CargoCrypt, CryptoConfig};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn project() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join(".cargocrypt")).unwrap();
    // Cheap KDF so the CLI tests are quick.
    fs::write(
        dir.path().join(".cargocrypt/config.toml"),
        "performance_profile = \"Fast\"\n",
    )
    .unwrap();
    fs::write(dir.path().join("secrets.env"), "API_KEY=hunter2\n").unwrap();
    dir
}

fn cargocrypt(dir: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("cargocrypt").unwrap();
    cmd.current_dir(dir.path())
        .env_remove("CARGOCRYPT_PASSWORD")
        .env_remove("CARGOCRYPT_PASSWORD_FILE");
    cmd
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn project_config_file_is_loaded() {
    let dir = project();
    let crypt = CargoCrypt::builder()
        .project_root(dir.path())
        .build()
        .await
        .unwrap();

    let config = crypt.config().await;
    assert_eq!(
        config.performance_profile,
        cargocrypt::crypto::PerformanceProfile::Fast
    );
    // Keys absent from the file keep their defaults.
    assert_eq!(config.file_ops.encrypted_extension, "enc");
    assert_eq!(
        crypt.crypto().performance_profile(),
        cargocrypt::crypto::PerformanceProfile::Fast
    );
}

#[tokio::test]
async fn invalid_config_file_is_an_error_not_a_silent_default() {
    let dir = project();
    fs::write(
        dir.path().join(".cargocrypt/config.toml"),
        "performance_profile = \"Ludicrous\"\n",
    )
    .unwrap();

    let result = CargoCrypt::builder().project_root(dir.path()).build().await;
    let message = result.err().expect("must fail").to_string();
    assert!(message.contains("config.toml"), "{}", message);
}

#[test]
fn missing_config_file_means_defaults() {
    let dir = TempDir::new().unwrap();
    let config = CryptoConfig::load(dir.path()).unwrap();
    assert!(!config.file_ops.backup_originals);
}

#[test]
fn encryption_leaves_no_plaintext_backup_by_default() {
    let dir = project();
    cargocrypt(&dir)
        .args(["encrypt", "secrets.env", "--password-stdin"])
        .write_stdin("correct horse battery staple\n")
        .assert()
        .success();

    let files = names(dir.path());
    assert!(
        files.contains(&"secrets.env.enc".to_string()),
        "{:?}",
        files
    );
    assert!(!files.iter().any(|f| f.ends_with(".backup")), "{:?}", files);
}

#[cfg(unix)]
#[test]
fn opt_in_backup_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = project();
    fs::write(
        dir.path().join(".cargocrypt/config.toml"),
        "performance_profile = \"Fast\"\n[file_ops]\nbackup_originals = true\n",
    )
    .unwrap();

    cargocrypt(&dir)
        .args(["encrypt", "secrets.env", "--password-stdin"])
        .write_stdin("correct horse battery staple\n")
        .assert()
        .success();

    let backup = dir.path().join("secrets.env.backup");
    let mode = fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn whitespace_is_part_of_the_password() {
    let dir = project();
    // Leading, interior and trailing spaces.
    let password = "  correct  horse  ";

    cargocrypt(&dir)
        .args(["encrypt", "secrets.env", "--password-stdin"])
        .write_stdin(format!("{}\n", password))
        .assert()
        .success();
    fs::remove_file(dir.path().join("secrets.env")).unwrap();

    // The trimmed form is a different password.
    cargocrypt(&dir)
        .args(["decrypt", "secrets.env.enc", "--password-stdin"])
        .write_stdin(format!("{}\n", password.trim()))
        .assert()
        .failure();
    assert!(!dir.path().join("secrets.env").exists());

    cargocrypt(&dir)
        .args(["decrypt", "secrets.env.enc", "--password-stdin"])
        .write_stdin(format!("{}\n", password))
        .assert()
        .success();
    assert_eq!(
        fs::read(dir.path().join("secrets.env")).unwrap(),
        b"API_KEY=hunter2\n"
    );
}

#[test]
fn password_file_flag_and_environment_variable() {
    let dir = project();
    let pw = dir.path().join("pw.txt");
    fs::write(&pw, "correct horse battery staple\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pw, fs::Permissions::from_mode(0o600)).unwrap();
    }

    cargocrypt(&dir)
        .args(["encrypt", "secrets.env", "--password-file", "pw.txt"])
        .assert()
        .success();
    fs::remove_file(dir.path().join("secrets.env")).unwrap();

    cargocrypt(&dir)
        .env("CARGOCRYPT_PASSWORD_FILE", &pw)
        .args(["decrypt", "secrets.env.enc"])
        .assert()
        .success();
    assert!(dir.path().join("secrets.env").exists());

    // Conflicting sources are rejected by the argument parser.
    cargocrypt(&dir)
        .args([
            "decrypt",
            "secrets.env.enc",
            "--password-stdin",
            "--password-file",
            "pw.txt",
        ])
        .assert()
        .failure();
}

#[test]
fn git_filter_no_longer_reads_a_password_from_git_config() {
    let dir = project();
    let git = |args: &[&str]| {
        assert!(std::process::Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap()
            .status
            .success());
    };
    git(&["init", "-q"]);
    git(&["config", "cargocrypt.password", "stored-in-clear-text"]);

    let out = cargocrypt(&dir)
        .args(["git", "filter-clean"])
        .write_stdin("API_KEY=hunter2\n")
        .assert()
        .failure();
    assert!(out.get_output().stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.get_output().stderr).contains("no longer read"));
}
