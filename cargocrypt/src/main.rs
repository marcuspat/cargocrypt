//! CargoCrypt CLI application
//!
//! Zero-config cryptographic operations for Rust projects

use cargocrypt::{CargoCrypt, CargoCryptError, CryptoResult, SecretDetector};
use clap::{Parser, Subcommand};
use rpassword::prompt_password;
use std::{path::PathBuf, sync::Arc};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize CargoCrypt in current project
    Init {
        /// Enable Git integration
        #[arg(long)]
        git: bool,
    },
    /// Encrypt a file
    Encrypt {
        file: PathBuf,
        /// Read the password from the first line of stdin instead of prompting
        #[arg(long, conflicts_with = "password_file")]
        password_stdin: bool,
        /// Read the password from a file (also: CARGOCRYPT_PASSWORD_FILE)
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
    /// Decrypt a file
    Decrypt {
        file: PathBuf,
        /// Read the password from the first line of stdin instead of prompting
        #[arg(long, conflicts_with = "password_file")]
        password_stdin: bool,
        /// Read the password from a file (also: CARGOCRYPT_PASSWORD_FILE)
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
    /// Check that an encrypted file is intact and the password opens it
    ///
    /// Decrypts and authenticates the whole file without writing anything.
    Verify {
        file: PathBuf,
        /// Read the password from the first line of stdin instead of prompting
        #[arg(long, conflicts_with = "password_file")]
        password_stdin: bool,
        /// Read the password from a file (also: CARGOCRYPT_PASSWORD_FILE)
        #[arg(long)]
        password_file: Option<PathBuf>,
    },
    /// Re-encrypt a file in place with a new password and/or profile
    ///
    /// The plaintext never touches the disk, and the file is replaced only
    /// once the old contents have authenticated. Older container formats are
    /// upgraded to the current one.
    Rekey {
        file: PathBuf,
        /// Read the current password from the first line of stdin
        #[arg(long, conflicts_with = "password_file")]
        password_stdin: bool,
        /// Read the current password from a file (also: CARGOCRYPT_PASSWORD_FILE)
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Read the new password from a file instead of prompting
        #[arg(long, conflicts_with = "keep_password")]
        new_password_file: Option<PathBuf>,
        /// Keep the current password (change only the profile or format)
        #[arg(long)]
        keep_password: bool,
        /// Key derivation profile for the result (default: the configured one)
        #[arg(long, value_enum)]
        profile: Option<ProfileArg>,
    },
    /// Scan files for secrets committed in plain text
    ///
    /// Exits 0 when nothing is found, 1 when secrets are found, 2 on error.
    Scan {
        /// Files or directories to scan (default: current directory)
        paths: Vec<PathBuf>,
        /// Scan the staged contents of files in the git index
        #[arg(long, conflicts_with = "paths")]
        staged: bool,
        /// Output format
        #[arg(long, value_enum, default_value_t = ScanFormat::Text)]
        format: ScanFormat,
        /// Minimum confidence (0.0 to 1.0) for a finding to be reported
        #[arg(long, default_value_t = 0.5)]
        min_confidence: f64,
        /// Write the report to a file instead of stdout
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Exit 0 even when secrets are found
        #[arg(long)]
        no_fail: bool,
        /// Ignore findings recorded in this earlier JSON report
        /// (create one with `scan --format json --output <file>`)
        #[arg(long)]
        baseline: Option<PathBuf>,
    },
    /// Show configuration
    Config,
    /// Print a shell completion script to stdout
    ///
    /// For example: `cargocrypt completions bash > ~/.local/share/bash-completion/completions/cargocrypt`
    Completions {
        /// Shell to generate for
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
    /// Launch interactive TUI for all CargoCrypt operations
    Tui,
    /// Git-specific commands
    #[command(subcommand)]
    Git(GitCommands),
    /// Monitoring and performance commands
    #[command(subcommand)]
    Monitor(MonitorCommands),
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ProfileArg {
    Fast,
    Balanced,
    Secure,
    Paranoid,
}

impl From<ProfileArg> for cargocrypt::crypto::PerformanceProfile {
    fn from(profile: ProfileArg) -> Self {
        use cargocrypt::crypto::PerformanceProfile as P;
        match profile {
            ProfileArg::Fast => P::Fast,
            ProfileArg::Balanced => P::Balanced,
            ProfileArg::Secure => P::Secure,
            ProfileArg::Paranoid => P::Paranoid,
        }
    }
}

fn describe(info: &cargocrypt::ContainerInfo) -> String {
    format!(
        "format v{}, Argon2id {} MiB / {} passes / {} lanes, {} bytes of content",
        info.version,
        info.kdf.m_cost / 1024,
        info.kdf.t_cost,
        info.kdf.p_cost,
        info.plaintext_len
    )
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ScanFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Subcommand)]
enum GitCommands {
    /// Install git hooks for automatic secret detection
    InstallHooks,
    /// Uninstall git hooks
    UninstallHooks,
    /// Configure git attributes for automatic encryption
    ConfigureAttributes,
    /// Clean filter for git (used internally)
    FilterClean {
        /// File being processed (placeholder - content comes from stdin)
        #[arg(default_value = "-")]
        file: String,
    },
    /// Smudge filter for git (used internally)
    FilterSmudge {
        /// File being processed (placeholder - content comes from stdin)
        #[arg(default_value = "-")]
        file: String,
    },
    /// Update .gitignore with CargoCrypt patterns
    UpdateIgnore,
}

#[derive(Subcommand)]
enum MonitorCommands {
    /// Show current system metrics
    Metrics,
    /// Display real-time monitoring dashboard
    Dashboard,
    /// Start monitoring HTTP server
    Server {
        /// Port to listen on
        #[arg(long, default_value = "3030")]
        port: u16,
        /// Host to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },
    /// Show performance alerts
    Alerts,
    /// Export metrics to JSON
    Export {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Health check
    Health,
}

#[tokio::main]
async fn main() -> CryptoResult<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { git } => {
            CargoCrypt::init_project().await?;
            println!("✅ CargoCrypt initialized successfully!");

            if git {
                // Initialize git integration
                use cargocrypt::git::GitIntegration;

                println!("🔧 Setting up Git integration...");
                let mut git_integration = GitIntegration::new().await?;
                git_integration.setup_repository().await?;
                println!("✅ Git integration configured successfully!");
            }
        }
        Commands::Encrypt {
            file,
            password_stdin,
            password_file,
        } => {
            let crypt = CargoCrypt::new().await?;
            let password = obtain_password(password_stdin, password_file, true)?;
            let encrypted_file = crypt.encrypt_file(&file, &password).await?;
            println!("✅ File encrypted: {}", encrypted_file.display());
        }
        Commands::Decrypt {
            file,
            password_stdin,
            password_file,
        } => {
            let crypt = CargoCrypt::new().await?;
            let password = obtain_password(password_stdin, password_file, false)?;
            let decrypted_file = crypt.decrypt_file(&file, &password).await?;
            println!("✅ File decrypted: {}", decrypted_file.display());
        }
        Commands::Verify {
            file,
            password_stdin,
            password_file,
        } => {
            let crypt = CargoCrypt::new().await?;
            let password = obtain_password(password_stdin, password_file, false)?;
            let info = crypt.verify_file(&file, &password).await?;
            println!("✅ {} is intact: {}", file.display(), describe(&info));
        }
        Commands::Rekey {
            file,
            password_stdin,
            password_file,
            new_password_file,
            keep_password,
            profile,
        } => {
            let crypt = CargoCrypt::new().await?;
            let old = obtain_password(password_stdin, password_file, false)?;
            let new = if keep_password {
                old.clone()
            } else if let Some(path) = new_password_file {
                cargocrypt::password::read_password_file(path)?
            } else if password_stdin {
                // stdin is already consumed by the current password.
                return Err(CargoCryptError::Config {
                    message: "With --password-stdin the new password must come from --new-password-file, or use --keep-password".to_string(),
                    suggestion: None,
                });
            } else {
                let first = zeroize::Zeroizing::new(prompt_password("Enter new password: ")?);
                let again = zeroize::Zeroizing::new(prompt_password("Confirm new password: ")?);
                if *first != *again {
                    return Err(CargoCryptError::Config {
                        message: "Passwords do not match".to_string(),
                        suggestion: None,
                    });
                }
                first
            };
            let info = crypt
                .rekey_file(&file, &old, &new, profile.map(Into::into))
                .await?;
            println!("✅ {} re-encrypted: {}", file.display(), describe(&info));
        }
        Commands::Scan {
            paths,
            staged,
            format,
            min_confidence,
            output,
            no_fail,
            baseline,
        } => {
            let code = match run_scan(paths, staged, format, min_confidence, output, baseline).await
            {
                Ok(true) => 0,
                Ok(false) if no_fail => 0,
                Ok(false) => 1,
                Err(e) => {
                    eprintln!("error: {}", e);
                    2
                }
            };
            std::process::exit(code);
        }
        Commands::Config => {
            let crypt = CargoCrypt::new().await?;
            let config = crypt.config().await;
            println!("📋 Current configuration:");
            println!("  Performance Profile: {:?}", config.performance_profile);
            // The profile decides the cost; `[key_params]` in the config
            // file is not used.
            let kdf = config.performance_profile.kdf_params();
            println!("  Key derivation: Argon2id");
            println!("  Memory cost: {} KiB", kdf.m_cost);
            println!("  Time cost: {} passes", kdf.t_cost);
            println!("  Parallelism: {}", kdf.p_cost);
            println!("  Auto-backup: {}", config.file_ops.backup_originals);
            println!("  Fail-secure: {}", config.security.fail_secure);
        }
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "cargocrypt",
                &mut std::io::stdout(),
            );
        }
        Commands::Tui => {
            println!("Starting TUI...");
            let crypt = Arc::new(CargoCrypt::new().await?);
            cargocrypt::tui_simple::run_simple_tui(crypt).await?;
        }
        Commands::Git(git_cmd) => {
            handle_git_command(git_cmd).await?;
        }
        Commands::Monitor(monitor_cmd) => {
            handle_monitor_command(monitor_cmd).await?;
        }
    }

    Ok(())
}

/// Run a secret scan and write the report. Returns whether the scan was clean.
async fn run_scan(
    paths: Vec<PathBuf>,
    staged: bool,
    format: ScanFormat,
    min_confidence: f64,
    output: Option<PathBuf>,
    baseline: Option<PathBuf>,
) -> CryptoResult<bool> {
    use cargocrypt::detection::{ReportFormat, ScanOptions, ScanReport, SecretDetector};

    if !(0.0..=1.0).contains(&min_confidence) {
        return Err(CargoCryptError::Config {
            message: format!(
                "--min-confidence must be between 0 and 1, got {}",
                min_confidence
            ),
            suggestion: None,
        });
    }

    let detector = SecretDetector::new();
    let mut options = ScanOptions::default().with_min_confidence(min_confidence);
    options.include_low_confidence = true; // --min-confidence is the only threshold
    options.sort_by_confidence = false;
    // Dotfiles are where secrets live (`.env`, `.npmrc`); never skip them.
    options.scan_config.scan_hidden = true;

    let mut findings = Vec::new();
    if staged {
        for path in staged_files()? {
            // Lock files are skipped on the staged path too: a routine
            // `cargo update` stages Cargo.lock, and its checksum garden must
            // not block the commit. This loop reads index blobs and so never
            // reaches should_skip_file — the same predicate applies here
            // (gate r1).
            if SecretDetector::is_lock_file(std::path::Path::new(&path)) {
                continue;
            }
            // Scan what is about to be committed, not the working tree copy.
            let blob = std::process::Command::new("git")
                .arg("show")
                .arg(format!(":{}", path))
                .output()?;
            if !blob.status.success() {
                continue;
            }
            if let Ok(content) = String::from_utf8(blob.stdout) {
                findings.extend(
                    detector
                        .scan_content(&content, &path)?
                        .into_iter()
                        .filter(|f| f.confidence >= min_confidence),
                );
            }
        }
    } else {
        let paths = if paths.is_empty() {
            vec![PathBuf::from(".")]
        } else {
            paths
        };
        for path in &paths {
            if path.is_dir() {
                findings.extend(detector.scan_directory(path, &options).await?);
            } else if path.is_file() {
                findings.extend(detector.scan_file(path, &options).await?);
            } else {
                return Err(CargoCryptError::from(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("{}: no such file or directory", path.display()),
                )));
            }
        }
    }

    // `.cargocryptignore` lives at the SCAN ROOT — the repo being scanned —
    // not the process CWD: `cargocrypt scan <path>` run from another
    // directory must resolve the same suppressions an in-root run would,
    // or known-benign fixtures fail the scan (gate r2). Staged mode anchors
    // at the git toplevel; path mode at the first root argument.
    let scan_root: PathBuf = if staged {
        std::process::Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        paths
            .first()
            .map(|p| {
                if p.is_dir() {
                    p.clone()
                } else {
                    p.parent().map(|d| d.to_path_buf()).unwrap_or_default()
                }
            })
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from("."))
    };
    let ignore_file = scan_root.join(".cargocryptignore");
    if ignore_file.is_file() {
        let mut builder = ignore::gitignore::GitignoreBuilder::new(&scan_root);
        if let Some(e) = builder.add(&ignore_file) {
            return Err(CargoCryptError::Config {
                message: format!(".cargocryptignore: {}", e),
                suggestion: None,
            });
        }
        let matcher = builder.build().map_err(|e| CargoCryptError::Config {
            message: format!(".cargocryptignore: {}", e),
            suggestion: None,
        })?;
        findings.retain(|f| {
            // findings may carry root-prefixed or absolute paths: match
            // relative to the ignore file's root either way
            let rel = f
                .file_path
                .strip_prefix(&scan_root)
                .unwrap_or(&f.file_path);
            let path = rel.strip_prefix("./").unwrap_or(rel);
            !matcher.matched_path_or_any_parents(path, false).is_ignore()
        });
    }

    let mut report = ScanReport::new(&findings, None);
    if let Some(path) = baseline {
        let text = std::fs::read_to_string(&path)?;
        let known: ScanReport =
            serde_json::from_str(&text).map_err(|e| CargoCryptError::Config {
                message: format!("{} is not a scan report: {}", path.display(), e),
                suggestion: Some(
                    "Create a baseline with `cargocrypt scan --format json --output <file>`"
                        .to_string(),
                ),
            })?;
        let suppressed = report.subtract_baseline(&known);
        if suppressed > 0 {
            eprintln!("{} finding(s) suppressed by the baseline", suppressed);
        }
    }
    let rendered = report.render(match format {
        ScanFormat::Text => ReportFormat::Text,
        ScanFormat::Json => ReportFormat::Json,
        ScanFormat::Sarif => ReportFormat::Sarif,
    });
    match output {
        Some(path) => std::fs::write(path, rendered)?,
        None => print!("{}", rendered),
    }
    Ok(report.is_clean())
}

/// Paths added, copied or modified in the git index.
fn staged_files() -> CryptoResult<Vec<String>> {
    let out = std::process::Command::new("git")
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"])
        .output()?;
    if !out.status.success() {
        return Err(CargoCryptError::Config {
            message: format!(
                "git diff --cached failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            suggestion: Some("Run `cargocrypt scan --staged` inside a git repository".to_string()),
        });
    }
    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|p| !p.is_empty())
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect())
}

/// Get the password for encrypt/decrypt.
///
/// Order: `--password-stdin`, `--password-file`, `CARGOCRYPT_PASSWORD_FILE`,
/// then an interactive prompt (with confirmation when encrypting).
fn obtain_password(
    from_stdin: bool,
    file: Option<PathBuf>,
    confirm: bool,
) -> CryptoResult<zeroize::Zeroizing<String>> {
    use cargocrypt::password;
    use zeroize::Zeroizing;

    if from_stdin {
        return password::read_password_line(std::io::stdin().lock());
    }
    if let Some(path) = file {
        return password::read_password_file(path);
    }
    if let Some(path) = std::env::var_os(password::PASSWORD_FILE_ENV).filter(|p| !p.is_empty()) {
        return password::read_password_file(path);
    }

    let entered = Zeroizing::new(prompt_password(if confirm {
        "Enter password for encryption: "
    } else {
        "Enter password for decryption: "
    })?);
    if confirm {
        let again = Zeroizing::new(prompt_password("Confirm password: ")?);
        if *entered != *again {
            return Err(CargoCryptError::Config {
                message: "Passwords do not match".to_string(),
                suggestion: None,
            });
        }
    }
    Ok(entered)
}

/// Resolve the password used by the git clean/smudge filters.
///
/// Order: `CARGOCRYPT_PASSWORD_FILE`, then `CARGOCRYPT_PASSWORD`. There is
/// deliberately no fallback: a filter that cannot find a password must fail,
/// otherwise files are "encrypted" under a publicly known constant.
///
/// `git config cargocrypt.password` is no longer read. It kept the password
/// in clear text in `.git/config`; if it is still set, say so rather than
/// failing with a bare "no password".
fn git_filter_password() -> CryptoResult<zeroize::Zeroizing<String>> {
    if let Some(password) = cargocrypt::password::from_environment()? {
        return Ok(password);
    }

    let legacy = std::process::Command::new("git")
        .args(["config", "--get", "cargocrypt.password"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false);

    Err(CargoCryptError::Config {
        message: if legacy {
            "`git config cargocrypt.password` is set but no longer read: it stores the password in clear text in .git/config".to_string()
        } else {
            "No password available for the CargoCrypt git filter".to_string()
        },
        suggestion: Some(
            "Set CARGOCRYPT_PASSWORD_FILE to a file containing the password (mode 600), or CARGOCRYPT_PASSWORD".to_string(),
        ),
    })
}

async fn handle_git_command(cmd: GitCommands) -> CryptoResult<()> {
    use cargocrypt::git::{GitAttributes, GitHooks, GitIgnoreManager, GitIntegration};

    match cmd {
        GitCommands::InstallHooks => {
            let git_integration = GitIntegration::new().await?;
            let hooks = GitHooks::new(git_integration.repo())?;

            println!("🔧 Installing Git hooks...");

            // Install secret detection hook
            hooks.install_secret_detection_hook().await?;

            // Install encryption validation hook
            hooks.install_encryption_validation_hook().await?;

            println!("✅ Git hooks installed successfully!");
            println!("   - Pre-commit: Secret detection");
            println!("   - Pre-push: Encryption validation");
        }
        GitCommands::UninstallHooks => {
            let git_integration = GitIntegration::new().await?;
            let hooks = GitHooks::new(git_integration.repo())?;

            println!("🔧 Uninstalling Git hooks...");
            hooks.uninstall_hooks().await?;
            println!("✅ Git hooks removed successfully!");
        }
        GitCommands::ConfigureAttributes => {
            let git_integration = GitIntegration::new().await?;
            let mut attributes = GitAttributes::new(git_integration.repo())?;

            println!("🔧 Configuring Git attributes...");

            // Add default CargoCrypt patterns
            attributes.add_cargocrypt_patterns().await?;

            // Configure filters
            attributes
                .configure_filters(git_integration.config())
                .await?;

            // Save attributes
            attributes.save().await?;

            println!("✅ Git attributes configured successfully!");
            println!("   Patterns added for automatic encryption:");
            for pattern in attributes.get_patterns() {
                println!("   - {}", pattern.pattern);
            }
        }
        GitCommands::FilterClean { .. } => {
            // This is called by git during staging
            // Read from stdin, encrypt, write to stdout
            use cargocrypt::CargoCrypt;
            use std::io::{self, Read, Write};

            let mut input = Vec::new();
            io::stdin()
                .read_to_end(&mut input)
                .map_err(cargocrypt::error::CargoCryptError::from)?;

            let password = git_filter_password()?;

            let crypt = CargoCrypt::new().await?;
            let encrypted = crypt.crypto().encrypt_data(&input, &password).await?;

            // Output encrypted data
            let encrypted_bytes = encrypted.to_bytes()?;
            io::stdout()
                .write_all(&encrypted_bytes)
                .map_err(cargocrypt::error::CargoCryptError::from)?;
        }
        GitCommands::FilterSmudge { .. } => {
            // This is called by git during checkout
            // Read from stdin, decrypt, write to stdout
            use cargocrypt::{crypto::EncryptedSecret, CargoCrypt};
            use std::io::{self, Read, Write};

            let mut input = Vec::new();
            io::stdin()
                .read_to_end(&mut input)
                .map_err(cargocrypt::error::CargoCryptError::from)?;

            let password = git_filter_password()?;

            let crypt = CargoCrypt::new().await?;

            // A blob that is not a CargoCrypt container was committed before
            // the filter was configured: pass it through untouched. A blob that
            // is a container must decrypt, or the smudge fails.
            match EncryptedSecret::from_bytes(&input) {
                Ok(encrypted) => {
                    let decrypted = crypt.crypto().decrypt_data(&encrypted, &password)?;
                    io::stdout()
                        .write_all(&decrypted)
                        .map_err(cargocrypt::error::CargoCryptError::from)?;
                }
                Err(e) if EncryptedSecret::has_magic(&input) => return Err(e.into()),
                Err(_) => {
                    io::stdout()
                        .write_all(&input)
                        .map_err(cargocrypt::error::CargoCryptError::from)?;
                }
            }
        }
        GitCommands::UpdateIgnore => {
            let git_integration = GitIntegration::new().await?;
            let mut ignore_manager = GitIgnoreManager::new(git_integration.repo())?;

            println!("🔧 Updating .gitignore...");

            // Add CargoCrypt patterns
            ignore_manager.add_cargocrypt_patterns().await?;

            // Save the updated .gitignore
            ignore_manager.save().await?;

            println!("✅ .gitignore updated successfully!");
            println!("   Added patterns:");
            for pattern in ignore_manager.get_ignore_patterns() {
                println!("   - {}", pattern);
            }
        }
    }

    Ok(())
}

async fn handle_monitor_command(cmd: MonitorCommands) -> CryptoResult<()> {
    use cargocrypt::monitoring::{server::MonitoringServer, MonitoringConfig, MonitoringManager};
    use std::net::SocketAddr;

    // Initialize monitoring manager
    let monitoring = Arc::new(MonitoringManager::new(MonitoringConfig::default()));

    match cmd {
        MonitorCommands::Metrics => {
            println!("📊 System Metrics");
            println!("================");

            let metrics = monitoring.get_metrics().await;

            // Display crypto operations
            println!("\n🔐 Crypto Operations:");
            for (op_type, summary) in &metrics.crypto_operations {
                println!(
                    "  {}: {} ops, avg {}ms, {:.1}% errors",
                    op_type,
                    summary.count,
                    summary.avg_duration_ms,
                    summary.error_rate * 100.0
                );
            }

            // Display file operations
            println!("\n📁 File Operations:");
            for (op_type, summary) in &metrics.file_operations {
                println!(
                    "  {}: {} ops, avg {}ms, {:.1}% errors",
                    op_type,
                    summary.count,
                    summary.avg_duration_ms,
                    summary.error_rate * 100.0
                );
            }

            // Display system metrics
            println!("\n🖥️  System:");
            println!("  Uptime: {}s", metrics.system_metrics.uptime_seconds);
            println!(
                "  Memory Peak: {:.1} MB",
                metrics.system_metrics.memory_peak_mb
            );
            println!(
                "  Data Encrypted: {:.1} MB",
                metrics.system_metrics.total_encrypted_mb
            );
            println!(
                "  Data Decrypted: {:.1} MB",
                metrics.system_metrics.total_decrypted_mb
            );
            println!(
                "  Files Processed: {}",
                metrics.system_metrics.files_processed
            );
        }

        MonitorCommands::Dashboard => {
            println!("🖥️  Starting monitoring dashboard...");
            println!("Note: the dashboard shows sample data; it is not wired to live metrics yet.");
            println!("Press 'q' to quit, arrow keys or 1-5 to navigate");

            // Create and run monitoring dashboard
            use cargocrypt::tui::monitoring::MonitoringDashboard;
            let mut dashboard = MonitoringDashboard::new(monitoring);
            dashboard
                .run()
                .await
                .map_err(|e| CargoCryptError::from(std::io::Error::other(e.to_string())))?
        }

        MonitorCommands::Server { port, host } => {
            let addr: SocketAddr = format!("{}:{}", host, port).parse().map_err(|e| {
                cargocrypt::error::CargoCryptError::Config {
                    message: format!("Invalid address {}:{}: {}", host, port, e),
                    suggestion: Some("Please provide a valid host and port".to_string()),
                }
            })?;

            println!("🌐 Starting monitoring server on http://{}", addr);
            println!("Available endpoints:");
            println!("  GET /health     - Health check");
            println!("  GET /metrics    - Prometheus metrics");
            println!("  GET /alerts     - Performance alerts");
            println!("  GET /throughput - Real-time throughput");
            println!("Press Ctrl+C to stop");

            let server = MonitoringServer::new(monitoring, addr);
            server
                .start()
                .await
                .map_err(|e| CargoCryptError::from(std::io::Error::other(e.to_string())))?;
        }

        MonitorCommands::Alerts => {
            println!("⚠️  Performance Alerts");
            println!("=====================");

            let alerts = monitoring.check_performance_alerts().await;

            if alerts.is_empty() {
                println!("✅ No active alerts");
            } else {
                for alert in alerts {
                    let severity_emoji = match alert.severity {
                        cargocrypt::monitoring::AlertSeverity::Critical => "🔴",
                        cargocrypt::monitoring::AlertSeverity::Warning => "🟡",
                        cargocrypt::monitoring::AlertSeverity::Info => "🔵",
                    };

                    println!(
                        "{} {:?}: {}",
                        severity_emoji, alert.alert_type, alert.message
                    );

                    for (key, value) in &alert.metrics {
                        println!("   {}: {:.2}", key, value);
                    }
                }
            }
        }

        MonitorCommands::Export { output } => {
            let json = monitoring.export_metrics_json().await;

            match output {
                Some(file_path) => {
                    tokio::fs::write(&file_path, &json).await?;
                    println!("✅ Metrics exported to: {}", file_path.display());
                }
                None => {
                    println!("{}", json);
                }
            }
        }

        MonitorCommands::Health => {
            println!("🏥 System Health Check");
            println!("=====================");

            let health = monitoring.health_check().await;

            let status_emoji = match health.status {
                cargocrypt::monitoring::HealthStatus::Healthy => "✅",
                cargocrypt::monitoring::HealthStatus::Degraded => "⚠️",
                cargocrypt::monitoring::HealthStatus::Critical => "🔴",
                cargocrypt::monitoring::HealthStatus::Unknown => "❓",
            };

            println!("{} Status: {:?}", status_emoji, health.status);
            println!("📊 Uptime: {}s", health.uptime_seconds);
            println!(
                "💾 Memory: {:.1} MB current, {:.1} MB peak",
                health.memory_stats.current_mb, health.memory_stats.peak_mb
            );

            if !health.alerts.is_empty() {
                println!("\n⚠️  Active Alerts:");
                for alert in &health.alerts {
                    println!("  - {:?}: {}", alert.alert_type, alert.message);
                }
            }
        }
    }

    Ok(())
}
