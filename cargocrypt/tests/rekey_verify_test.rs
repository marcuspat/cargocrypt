//! `verify` and `rekey`: library behaviour and the CLI.

use assert_cmd::Command;
use cargocrypt::crypto::{EncryptedSecret, PerformanceProfile, PlaintextSecret};
use cargocrypt::{CargoCrypt, CryptoConfig};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

const OLD: &str = "correct horse battery staple";
const NEW: &str = "an entirely different passphrase 9";

fn project() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join(".cargocrypt")).unwrap();
    fs::write(
        dir.path().join(".cargocrypt/config.toml"),
        "performance_profile = \"Fast\"\n",
    )
    .unwrap();
    dir
}

async fn crypt(dir: &TempDir) -> CargoCrypt {
    CargoCrypt::builder()
        .config(CryptoConfig {
            performance_profile: PerformanceProfile::Fast,
            ..CryptoConfig::default()
        })
        .project_root(dir.path())
        .build()
        .await
        .unwrap()
}

/// Encrypt `contents` and return the path of the encrypted file, with the
/// plaintext original removed.
async fn encrypted(dir: &TempDir, crypt: &CargoCrypt, contents: &[u8]) -> PathBuf {
    let source = dir.path().join("secrets.env");
    fs::write(&source, contents).unwrap();
    let out = crypt.encrypt_file(&source, OLD).await.unwrap();
    fs::remove_file(&source).unwrap();
    out
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn big() -> Vec<u8> {
    (0..300_000u32).map(|i| (i % 251) as u8).collect()
}

#[tokio::test]
async fn verify_authenticates_without_writing_plaintext() {
    let dir = project();
    let crypt = crypt(&dir).await;
    let file = encrypted(&dir, &crypt, &big()).await;
    let before = names(dir.path());

    let info = crypt.verify_file(&file, OLD).await.unwrap();
    assert_eq!(info.version, 3);
    assert_eq!(info.plaintext_len, 300_000);
    assert_eq!(info.kdf, PerformanceProfile::Fast.kdf_params());
    assert_eq!(names(dir.path()), before, "verify must not create files");

    assert!(crypt.verify_file(&file, NEW).await.is_err());

    let bytes = fs::read(&file).unwrap();
    fs::write(&file, &bytes[..bytes.len() - 1]).unwrap();
    assert!(crypt.verify_file(&file, OLD).await.is_err());
    assert_eq!(names(dir.path()), before);
}

#[tokio::test]
async fn rekey_changes_the_password_and_keeps_the_contents() {
    let dir = project();
    let crypt = crypt(&dir).await;
    let contents = big();
    let file = encrypted(&dir, &crypt, &contents).await;
    let before = names(dir.path());
    let old_bytes = fs::read(&file).unwrap();

    let info = crypt.rekey_file(&file, OLD, NEW, None).await.unwrap();
    assert_eq!(info.plaintext_len, contents.len() as u64);
    assert_eq!(names(dir.path()), before, "no temporary or plaintext files");
    assert_ne!(fs::read(&file).unwrap(), old_bytes);

    assert!(crypt.verify_file(&file, OLD).await.is_err());
    crypt.verify_file(&file, NEW).await.unwrap();
    let plain = crypt.decrypt_file(&file, NEW).await.unwrap();
    assert_eq!(fs::read(plain).unwrap(), contents);
}

#[tokio::test]
async fn failed_rekey_leaves_the_file_untouched() {
    let dir = project();
    let crypt = crypt(&dir).await;
    let file = encrypted(&dir, &crypt, &big()).await;
    let before = names(dir.path());
    let original = fs::read(&file).unwrap();

    // Wrong current password.
    assert!(crypt
        .rekey_file(&file, "not the password 1", NEW, None)
        .await
        .is_err());
    assert_eq!(fs::read(&file).unwrap(), original);
    assert_eq!(names(dir.path()), before);

    // Truncated source: the first chunks authenticate, the last does not.
    // The half-written replacement must not be installed.
    let truncated = &original[..original.len() - 5];
    fs::write(&file, truncated).unwrap();
    assert!(crypt.rekey_file(&file, OLD, NEW, None).await.is_err());
    assert_eq!(fs::read(&file).unwrap(), truncated);
    assert_eq!(names(dir.path()), before);

    // A new password that fails validation is rejected before any work.
    fs::write(&file, &original).unwrap();
    assert!(crypt.rekey_file(&file, OLD, "short", None).await.is_err());
    assert_eq!(fs::read(&file).unwrap(), original);
}

#[tokio::test]
async fn rekey_upgrades_old_formats_and_changes_the_profile() {
    let dir = project();
    let crypt = crypt(&dir).await;

    // Version 1, written by 0.2.3.
    let v1 = dir.path().join("legacy.env.enc");
    fs::copy("tests/fixtures/v1_container.bin", &v1).unwrap();
    assert_eq!(crypt.verify_file(&v1, OLD).await.unwrap().version, 1);
    let info = crypt.rekey_file(&v1, OLD, OLD, None).await.unwrap();
    assert_eq!(info.version, 3);
    assert_eq!(fs::read(&v1).unwrap()[4], 3);
    let plain = crypt.decrypt_file(&v1, OLD).await.unwrap();
    assert_eq!(fs::read(plain).unwrap(), b"API_KEY=hunter2\n");

    // Version 2, single-shot.
    let v2 = dir.path().join("single.env.enc");
    let secret = EncryptedSecret::encrypt_with_password(
        PlaintextSecret::from_string("TOKEN=abc\n".to_string()),
        OLD,
        None,
    )
    .unwrap();
    fs::write(&v2, secret.to_bytes().unwrap()).unwrap();
    assert_eq!(crypt.verify_file(&v2, OLD).await.unwrap().version, 2);
    let info = crypt
        .rekey_file(&v2, OLD, NEW, Some(PerformanceProfile::Balanced))
        .await
        .unwrap();
    assert_eq!(info.kdf, PerformanceProfile::Balanced.kdf_params());
    let verified = crypt.verify_file(&v2, NEW).await.unwrap();
    assert_eq!(verified.version, 3);
    assert_eq!(verified.kdf.m_cost, 65536);
}

#[cfg(unix)]
#[tokio::test]
async fn rekeyed_file_stays_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = project();
    let crypt = crypt(&dir).await;
    let file = encrypted(&dir, &crypt, b"API_KEY=hunter2\n").await;
    crypt.rekey_file(&file, OLD, NEW, None).await.unwrap();
    assert_eq!(
        fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn cli_verify_and_rekey() {
    let dir = project();
    fs::write(dir.path().join("secrets.env"), "API_KEY=hunter2\n").unwrap();
    fs::write(dir.path().join("new.pw"), format!("{}\n", NEW)).unwrap();
    fs::write(dir.path().join("old.pw"), format!("{}\n", OLD)).unwrap();
    #[cfg(unix)]
    for f in ["new.pw", "old.pw"] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path().join(f), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let run = |args: &[&str], stdin: &str| {
        Command::cargo_bin("cargocrypt")
            .unwrap()
            .current_dir(dir.path())
            .env_remove("CARGOCRYPT_PASSWORD_FILE")
            .args(args)
            .write_stdin(stdin.to_string())
            .assert()
    };

    run(&["encrypt", "secrets.env", "--password-file", "old.pw"], "").success();

    let out = run(
        &["verify", "secrets.env.enc", "--password-file", "old.pw"],
        "",
    )
    .success();
    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();
    assert!(stdout.contains("format v3"), "{}", stdout);
    assert!(stdout.contains("16 bytes"), "{}", stdout);

    run(
        &["verify", "secrets.env.enc", "--password-file", "new.pw"],
        "",
    )
    .failure();

    // The current password from stdin needs an explicit source for the new one.
    run(
        &["rekey", "secrets.env.enc", "--password-stdin"],
        &format!("{}\n", OLD),
    )
    .failure();

    run(
        &[
            "rekey",
            "secrets.env.enc",
            "--password-stdin",
            "--new-password-file",
            "new.pw",
        ],
        &format!("{}\n", OLD),
    )
    .success();
    run(
        &["verify", "secrets.env.enc", "--password-file", "old.pw"],
        "",
    )
    .failure();
    run(
        &["verify", "secrets.env.enc", "--password-file", "new.pw"],
        "",
    )
    .success();

    // Same password, stronger profile.
    let out = run(
        &[
            "rekey",
            "secrets.env.enc",
            "--password-file",
            "new.pw",
            "--keep-password",
            "--profile",
            "balanced",
        ],
        "",
    )
    .success();
    assert!(String::from_utf8_lossy(&out.get_output().stdout).contains("64 MiB"));
    run(
        &["verify", "secrets.env.enc", "--password-file", "new.pw"],
        "",
    )
    .success();
}
