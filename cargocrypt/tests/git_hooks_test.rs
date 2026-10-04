//! The installed git hooks and filter configuration must call commands that
//! exist and behave.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn bin_dir() -> std::path::PathBuf {
    assert_cmd::cargo::cargo_bin("cargocrypt")
        .parent()
        .unwrap()
        .to_path_buf()
}

fn run(dir: &Path, program: &str, args: &[&str]) -> Output {
    let path = format!(
        "{}:{}",
        bin_dir().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    Command::new(program)
        .args(args)
        .current_dir(dir)
        .env("PATH", path)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", dir.join("no-such-gitconfig"))
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .env_remove("CARGOCRYPT_PASSWORD")
        .env_remove("CARGOCRYPT_PASSWORD_FILE")
        .output()
        .unwrap()
}

fn repo() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("Cargo.toml"),
        "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    assert!(run(dir.path(), "git", &["init", "-q"]).status.success());
    dir
}

#[test]
fn pre_commit_hook_blocks_secrets_and_allows_clean_commits() {
    let dir = repo();
    let installed = run(dir.path(), "cargocrypt", &["git", "install-hooks"]);
    assert!(
        installed.status.success(),
        "{}",
        String::from_utf8_lossy(&installed.stderr)
    );
    let hook = fs::read_to_string(dir.path().join(".git/hooks/pre-commit")).unwrap();
    assert!(hook.contains("cargocrypt scan --staged"), "{}", hook);

    // A clean file commits. (The hook used to call a flag that does not
    // exist, so it rejected every commit.)
    fs::write(dir.path().join("main.rs"), "fn main() {}\n").unwrap();
    assert!(run(dir.path(), "git", &["add", "main.rs", "Cargo.toml"])
        .status
        .success());
    let clean = run(dir.path(), "git", &["commit", "-q", "-m", "clean"]);
    assert!(
        clean.status.success(),
        "clean commit was blocked: {}{}",
        String::from_utf8_lossy(&clean.stdout),
        String::from_utf8_lossy(&clean.stderr)
    );

    // A staged credential does not.
    fs::write(
        dir.path().join(".env"),
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
    )
    .unwrap();
    assert!(run(dir.path(), "git", &["add", ".env"]).status.success());
    let blocked = run(dir.path(), "git", &["commit", "-q", "-m", "secret"]);
    assert!(!blocked.status.success(), "a staged secret was committed");
}

#[test]
fn configured_filter_commands_exist() {
    let dir = repo();
    let configured = run(dir.path(), "cargocrypt", &["git", "configure-attributes"]);
    assert!(
        configured.status.success(),
        "{}",
        String::from_utf8_lossy(&configured.stderr)
    );

    for which in ["clean", "smudge"] {
        let out = run(
            dir.path(),
            "git",
            &[
                "config",
                "--get",
                &format!("filter.cargocrypt-encrypt.{}", which),
            ],
        );
        let command = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(
            command.starts_with(&format!("cargocrypt git filter-{}", which)),
            "filter.{} = {:?}",
            which,
            command
        );

        // The configured subcommand must be one the binary accepts.
        let words: Vec<&str> = command.split_whitespace().skip(1).take(2).collect();
        let help = run(dir.path(), "cargocrypt", &[words[0], words[1], "--help"]);
        assert!(help.status.success(), "`{}` is not a command", command);
    }
}

/// The whole path: a file matching a configured pattern is stored encrypted
/// in git and comes back as plaintext on checkout.
#[test]
fn transparent_encryption_round_trips_through_git() {
    let dir = repo();
    fs::create_dir(dir.path().join(".cargocrypt")).unwrap();
    fs::write(
        dir.path().join(".cargocrypt/config.toml"),
        "performance_profile = \"Fast\"\n",
    )
    .unwrap();
    assert!(
        run(dir.path(), "cargocrypt", &["git", "configure-attributes"])
            .status
            .success()
    );

    let with_password = |args: &[&str]| {
        let path = format!(
            "{}:{}",
            bin_dir().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new("git")
            .args(args)
            .current_dir(dir.path())
            .env("PATH", path)
            .env("CARGOCRYPT_PASSWORD", "correct horse battery staple")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", dir.path().join("no-such-gitconfig"))
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.com")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.com")
            .output()
            .unwrap()
    };

    let plaintext = "DB_PASSWORD=not-a-real-one\n";
    fs::write(dir.path().join("app.secret"), plaintext).unwrap();
    let added = with_password(&["add", "app.secret", ".gitattributes"]);
    assert!(
        added.status.success(),
        "{}",
        String::from_utf8_lossy(&added.stderr)
    );

    // What git stored is a container, not the plaintext.
    let blob = with_password(&["cat-file", "-p", ":app.secret"]);
    assert!(
        blob.stdout.starts_with(b"CCRY"),
        "the staged blob is not encrypted"
    );
    assert!(!String::from_utf8_lossy(&blob.stdout).contains("not-a-real-one"));

    assert!(with_password(&["commit", "-q", "-m", "add secret"])
        .status
        .success());

    // Remove the working copy and let git restore it through the smudge filter.
    fs::remove_file(dir.path().join("app.secret")).unwrap();
    let restored = with_password(&["checkout", "--", "app.secret"]);
    assert!(
        restored.status.success(),
        "{}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("app.secret")).unwrap(),
        plaintext
    );

    // Without a password the filter refuses rather than storing plaintext.
    fs::write(dir.path().join("other.secret"), plaintext).unwrap();
    assert!(!run(dir.path(), "git", &["add", "other.secret"])
        .status
        .success());
}
