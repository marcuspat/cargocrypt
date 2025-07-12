use cargocrypt::{CargoCrypt, CargoCryptConfig};
use std::path::PathBuf;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a CargoCrypt instance
    let config = CargoCryptConfig::default();
    let cargocrypt = CargoCrypt::new(config)?;
    
    // Test files
    let test_files = vec![
        ".env",
        "secrets.txt",
        "config.json",
        ".gitignore",
        "file.tar.gz",
        "noextension",
    ];
    
    // Create test files
    for filename in &test_files {
        tokio::fs::write(filename, format!("Test content for {}", filename)).await?;
    }
    
    println!("Testing encryption:");
    let password = "test-password";
    
    // Encrypt each file
    for filename in &test_files {
        match cargocrypt.encrypt_file(filename, password).await {
            Ok(encrypted_path) => {
                println!("{} -> {}", filename, encrypted_path.display());
            }
            Err(e) => {
                println!("{} -> ERROR: {}", filename, e);
            }
        }
    }
    
    println!("\nTesting decryption:");
    
    // Test decrypting the encrypted files
    let encrypted_files = vec![
        ".env.enc",
        "secrets.txt.enc",
        "config.json.enc",
        ".gitignore.enc",
        "file.tar.gz.enc",
        "noextension.enc",
    ];
    
    for filename in &encrypted_files {
        if tokio::fs::metadata(filename).await.is_ok() {
            match cargocrypt.decrypt_file(filename, password).await {
                Ok(decrypted_path) => {
                    println!("{} -> {}", filename, decrypted_path.display());
                }
                Err(e) => {
                    println!("{} -> ERROR: {}", filename, e);
                }
            }
        }
    }
    
    // Cleanup
    for filename in &test_files {
        let _ = tokio::fs::remove_file(filename).await;
        let _ = tokio::fs::remove_file(format!("{}.enc", filename)).await;
        let _ = tokio::fs::remove_file(format!("{}.backup", filename)).await;
    }
    
    Ok(())
}