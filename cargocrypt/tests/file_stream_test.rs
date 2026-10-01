//! File encryption: streaming container, atomic owner-only output.

use cargocrypt::crypto::{EncryptedSecret, PerformanceProfile, PlaintextSecret};
use cargocrypt::{CargoCrypt, CryptoConfig};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

const PASSWORD: &str = "correct horse battery staple";

async fn crypt(dir: &TempDir) -> CargoCrypt {
    let config = CryptoConfig {
        performance_profile: PerformanceProfile::Fast,
        ..CryptoConfig::default()
    };
    CargoCrypt::builder()
        .config(config)
        .project_root(dir.path())
        .build()
        .await
        .unwrap()
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
async fn large_file_round_trips_through_the_stream_format() {
    let dir = TempDir::new().unwrap();
    let crypt = crypt(&dir).await;

    // Several chunks plus a partial one.
    let plaintext: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    let source = dir.path().join("dump.sql");
    fs::write(&source, &plaintext).unwrap();

    let encrypted = crypt.encrypt_file(&source, PASSWORD).await.unwrap();
    let bytes = fs::read(&encrypted).unwrap();
    assert_eq!(&bytes[..4], b"CCRY");
    assert_eq!(bytes[4], 3, "files are written as streaming containers");
    // The configured profile reaches the header (Fast = 4 MiB).
    assert_eq!(u32::from_le_bytes(bytes[7..11].try_into().unwrap()), 4096);

    fs::remove_file(&source).unwrap();
    let decrypted = crypt.decrypt_file(&encrypted, PASSWORD).await.unwrap();
    assert_eq!(decrypted, source);
    assert_eq!(fs::read(&decrypted).unwrap(), plaintext);
}

#[cfg(unix)]
#[tokio::test]
async fn outputs_are_owner_only_and_no_temporaries_remain() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let crypt = crypt(&dir).await;
    let source = dir.path().join("secrets.env");
    fs::write(&source, b"API_KEY=hunter2\n").unwrap();

    let encrypted = crypt.encrypt_file(&source, PASSWORD).await.unwrap();
    fs::remove_file(&source).unwrap();
    let decrypted = crypt.decrypt_file(&encrypted, PASSWORD).await.unwrap();

    for path in [&encrypted, &decrypted] {
        let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{} is {:o}", path.display(), mode);
    }
    assert!(
        !names(dir.path()).iter().any(|n| n.ends_with(".tmp")),
        "{:?}",
        names(dir.path())
    );
}

#[tokio::test]
async fn failed_decryption_writes_nothing() {
    let dir = TempDir::new().unwrap();
    let crypt = crypt(&dir).await;
    let source = dir.path().join("secrets.env");
    fs::write(&source, vec![7u8; 200_000]).unwrap();
    let encrypted = crypt.encrypt_file(&source, PASSWORD).await.unwrap();
    fs::remove_file(&source).unwrap();
    for name in names(dir.path()) {
        if name.ends_with(".backup") {
            fs::remove_file(dir.path().join(name)).unwrap();
        }
    }
    let before = names(dir.path());

    // Wrong password.
    assert!(crypt
        .decrypt_file(&encrypted, "not the right password 1")
        .await
        .is_err());
    assert_eq!(names(dir.path()), before);

    // Truncated after the first chunks have already authenticated.
    let bytes = fs::read(&encrypted).unwrap();
    fs::write(&encrypted, &bytes[..bytes.len() - 10]).unwrap();
    assert!(crypt.decrypt_file(&encrypted, PASSWORD).await.is_err());
    assert_eq!(names(dir.path()), before);
}

#[tokio::test]
async fn single_shot_v2_files_still_decrypt() {
    let dir = TempDir::new().unwrap();
    let crypt = crypt(&dir).await;

    let v2 = EncryptedSecret::encrypt_with_password(
        PlaintextSecret::from_string("API_KEY=hunter2\n".to_string()),
        PASSWORD,
        None,
    )
    .unwrap();
    let path = dir.path().join("old.env.enc");
    fs::write(&path, v2.to_bytes().unwrap()).unwrap();

    let decrypted = crypt.decrypt_file(&path, PASSWORD).await.unwrap();
    assert_eq!(fs::read(decrypted).unwrap(), b"API_KEY=hunter2\n");
}

#[tokio::test]
async fn v1_files_still_decrypt() {
    let dir = TempDir::new().unwrap();
    let crypt = crypt(&dir).await;
    let path = dir.path().join("legacy.env.enc");
    fs::copy("tests/fixtures/v1_container.bin", &path).unwrap();

    let decrypted = crypt.decrypt_file(&path, PASSWORD).await.unwrap();
    assert_eq!(fs::read(decrypted).unwrap(), b"API_KEY=hunter2\n");
}
