//! CargoCrypt CLI application
//!
//! Zero-config cryptographic operations for Rust projects

use cargocrypt::{CargoCrypt, CryptoResult};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

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
            // TODO: Prompt for password in real implementation
            let password = "temporary_password"; 
            let encrypted_file = crypt.encrypt_file(&file, password).await?;
            println!("✅ File encrypted: {}", encrypted_file.display());
        }
        Commands::Decrypt { file } => {
            let crypt = CargoCrypt::new().await?;
            // TODO: Prompt for password in real implementation
            let password = "temporary_password";
            let decrypted_file = crypt.decrypt_file(&file, password).await?;
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
    }

    Ok(())
}