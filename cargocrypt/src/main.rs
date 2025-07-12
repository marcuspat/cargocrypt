//! CargoCrypt CLI application
//!
//! Zero-config cryptographic operations for Rust projects

use cargocrypt::{CargoCrypt, CryptoResult, tui::run_tui};
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
    Init,
    /// Encrypt a file
    Encrypt { file: PathBuf },
    /// Decrypt a file
    Decrypt { file: PathBuf },
    /// Show configuration
    Config,
    /// Launch interactive TUI for all CargoCrypt operations
    Tui,
}

#[tokio::main]
async fn main() -> CryptoResult<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            CargoCrypt::init_project().await?;
            println!("✅ CargoCrypt initialized successfully!");
        }
        Commands::Encrypt { file } => {
            let crypt = CargoCrypt::new().await?;
            
            // Prompt for password with confirmation
            let password = prompt_password("Enter password for encryption: ")?;
            let password_confirm = prompt_password("Confirm password: ")?;
            
            if password != password_confirm {
                eprintln!("❌ Error: Passwords do not match");
                std::process::exit(1);
            }
            
            let encrypted_file = crypt.encrypt_file(&file, &password).await?;
            println!("✅ File encrypted: {}", encrypted_file.display());
        }
        Commands::Decrypt { file } => {
            let crypt = CargoCrypt::new().await?;
            
            // Prompt for password
            let password = prompt_password("Enter password for decryption: ")?;
            
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
            let crypt = Arc::new(CargoCrypt::new().await?);
            run_tui(crypt).await?;
        }
    }

    Ok(())
}