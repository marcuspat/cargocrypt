//! CargoCrypt CLI application
//!
//! Zero-config cryptographic operations for Rust projects

use cargocrypt::{CargoCrypt, CryptoResult, CargoCryptError};
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
        /// Read password from stdin instead of prompting
        #[arg(long)]
        password_stdin: bool,
    },
    /// Decrypt a file
    Decrypt { 
        file: PathBuf,
        /// Read password from stdin instead of prompting
        #[arg(long)]
        password_stdin: bool,
    },
    /// Show configuration
    Config,
    /// Launch interactive TUI for all CargoCrypt operations
    Tui,
    /// Git-specific commands
    #[command(subcommand)]
    Git(GitCommands),
    /// Monitoring and performance commands
    #[command(subcommand)]
    Monitor(MonitorCommands),
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
        Commands::Encrypt { file, password_stdin } => {
            let crypt = CargoCrypt::new().await?;
            
            let password = if password_stdin {
                // Read password from stdin
                use std::io::{self, BufRead};
                let stdin = io::stdin();
                let mut handle = stdin.lock();
                let mut password = String::new();
                handle.read_line(&mut password).map_err(|e| CargoCryptError::from(e))?;
                password.trim().to_string()
            } else {
                // Prompt for password with confirmation
                let password = prompt_password("Enter password for encryption: ")?;
                let password_confirm = prompt_password("Confirm password: ")?;
                
                if password != password_confirm {
                    eprintln!("❌ Error: Passwords do not match");
                    std::process::exit(1);
                }
                password
            };
            
            let encrypted_file = crypt.encrypt_file(&file, &password).await?;
            println!("✅ File encrypted: {}", encrypted_file.display());
        }
        Commands::Decrypt { file, password_stdin } => {
            let crypt = CargoCrypt::new().await?;
            
            let password = if password_stdin {
                // Read password from stdin
                use std::io::{self, BufRead};
                let stdin = io::stdin();
                let mut handle = stdin.lock();
                let mut password = String::new();
                handle.read_line(&mut password).map_err(|e| CargoCryptError::from(e))?;
                password.trim().to_string()
            } else {
                // Prompt for password
                prompt_password("Enter password for decryption: ")?
            };
            
            let decrypted_file = crypt.decrypt_file(&file, &password).await?;
            println!("✅ File decrypted: {}", decrypted_file.display());
        }
        Commands::Config => {
            let crypt = CargoCrypt::new().await?;
            let config = crypt.config().await;
            println!("📋 Current configuration:");
            println!("  Performance Profile: {:?}", config.performance_profile);
            println!("  Key derivation: Argon2id");
            println!("  Memory cost: {} KiB", config.key_params.memory_cost);
            println!("  Time cost: {} iterations", config.key_params.time_cost);
            println!("  Parallelism: {}", config.key_params.parallelism);
            println!("  Auto-backup: {}", config.file_ops.backup_originals);
            println!("  Fail-secure: {}", config.security.fail_secure);
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

async fn handle_git_command(cmd: GitCommands) -> CryptoResult<()> {
    use cargocrypt::git::{GitIntegration, GitHooks, GitAttributes, GitIgnoreManager};
    
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
            attributes.configure_filters(git_integration.config()).await?;
            
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
            use std::io::{self, Read, Write};
            use cargocrypt::CargoCrypt;
            
            let mut input = Vec::new();
            io::stdin().read_to_end(&mut input)
                .map_err(|e| cargocrypt::error::CargoCryptError::from(e))?;
            
            // Get password from git config or environment
            let password = std::env::var("CARGOCRYPT_PASSWORD")
                .unwrap_or_else(|_| {
                    // Try to read from git config
                    std::process::Command::new("git")
                        .args(&["config", "--get", "cargocrypt.password"])
                        .output()
                        .ok()
                        .and_then(|output| {
                            if output.status.success() {
                                String::from_utf8(output.stdout).ok()
                                    .map(|s| s.trim().to_string())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| "default-password".to_string())
                });
            
            let crypt = CargoCrypt::new().await?;
            let encrypted = crypt.crypto().encrypt_data(&input, &password).await?;
            
            // Output encrypted data
            let encrypted_bytes = bincode::serialize(&encrypted)
                .map_err(|e| cargocrypt::error::CargoCryptError::Serialization { 
                    message: format!("Failed to serialize: {}", e), 
                    source: Box::new(e) 
                })?;
            io::stdout().write_all(&encrypted_bytes)
                .map_err(|e| cargocrypt::error::CargoCryptError::from(e))?;
        }
        GitCommands::FilterSmudge { .. } => {
            // This is called by git during checkout
            // Read from stdin, decrypt, write to stdout
            use std::io::{self, Read, Write};
            use cargocrypt::{CargoCrypt, crypto::EncryptedSecret};
            
            let mut input = Vec::new();
            io::stdin().read_to_end(&mut input)
                .map_err(|e| cargocrypt::error::CargoCryptError::from(e))?;
            
            // Get password from git config or environment
            let password = std::env::var("CARGOCRYPT_PASSWORD")
                .unwrap_or_else(|_| {
                    // Try to read from git config
                    std::process::Command::new("git")
                        .args(&["config", "--get", "cargocrypt.password"])
                        .output()
                        .ok()
                        .and_then(|output| {
                            if output.status.success() {
                                String::from_utf8(output.stdout).ok()
                                    .map(|s| s.trim().to_string())
                            } else {
                                None
                            }
                        })
                        .unwrap_or_else(|| "default-password".to_string())
                });
            
            let crypt = CargoCrypt::new().await?;
            
            // Try to deserialize and decrypt
            match bincode::deserialize::<EncryptedSecret>(&input) {
                Ok(encrypted) => {
                    match crypt.crypto().decrypt_data(&encrypted, &password) {
                        Ok(decrypted) => {
                            io::stdout().write_all(&decrypted)
                                .map_err(|e| cargocrypt::error::CargoCryptError::from(e))?;
                        }
                        Err(_) => {
                            // If decryption fails, output original (might not be encrypted)
                            io::stdout().write_all(&input)
                                .map_err(|e| cargocrypt::error::CargoCryptError::from(e))?;
                        }
                    }
                }
                Err(_) => {
                    // If deserialization fails, output original (not encrypted)
                    io::stdout().write_all(&input)
                        .map_err(|e| cargocrypt::error::CargoCryptError::from(e))?;
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
    use cargocrypt::monitoring::{MonitoringManager, MonitoringConfig, server::MonitoringServer};
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
                println!("  {}: {} ops, avg {}ms, {:.1}% errors", 
                    op_type, summary.count, summary.avg_duration_ms, summary.error_rate * 100.0);
            }
            
            // Display file operations
            println!("\n📁 File Operations:");
            for (op_type, summary) in &metrics.file_operations {
                println!("  {}: {} ops, avg {}ms, {:.1}% errors", 
                    op_type, summary.count, summary.avg_duration_ms, summary.error_rate * 100.0);
            }
            
            // Display system metrics
            println!("\n🖥️  System:");
            println!("  Uptime: {}s", metrics.system_metrics.uptime_seconds);
            println!("  Memory Peak: {:.1} MB", metrics.system_metrics.memory_peak_mb);
            println!("  Data Encrypted: {:.1} MB", metrics.system_metrics.total_encrypted_mb);
            println!("  Data Decrypted: {:.1} MB", metrics.system_metrics.total_decrypted_mb);
            println!("  Files Processed: {}", metrics.system_metrics.files_processed);
        }
        
        MonitorCommands::Dashboard => {
            println!("🖥️  Starting monitoring dashboard...");
            println!("Press 'q' to quit, arrow keys or 1-5 to navigate");
            
            // Create and run monitoring dashboard
            use cargocrypt::tui::monitoring::MonitoringDashboard;
            let mut dashboard = MonitoringDashboard::new(monitoring);
            dashboard.run().await.map_err(|e| CargoCryptError::from(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?
        }
        
        MonitorCommands::Server { port, host } => {
            let addr: SocketAddr = format!("{}:{}", host, port).parse()
                .map_err(|e| cargocrypt::error::CargoCryptError::Config {
                    message: format!("Invalid address {}:{}: {}", host, port, e),
                    suggestion: Some("Please provide a valid host and port".to_string()),
                })?;
            
            println!("🌐 Starting monitoring server on http://{}", addr);
            println!("Available endpoints:");
            println!("  GET /health     - Health check");
            println!("  GET /metrics    - Prometheus metrics");
            println!("  GET /alerts     - Performance alerts");
            println!("  GET /throughput - Real-time throughput");
            println!("Press Ctrl+C to stop");
            
            let server = MonitoringServer::new(monitoring, addr);
            server.start().await.map_err(|e| CargoCryptError::from(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;
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
                    
                    println!("{} {:?}: {}", severity_emoji, alert.alert_type, alert.message);
                    
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
            println!("💾 Memory: {:.1} MB current, {:.1} MB peak", 
                health.memory_stats.current_mb, health.memory_stats.peak_mb);
            
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