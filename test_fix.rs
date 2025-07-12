use std::path::{Path, PathBuf};

fn encrypt_path(path: &Path, enc_ext: &str) -> PathBuf {
    if let Some(ext) = path.extension() {
        path.with_extension(format!("{}.{}", ext.to_string_lossy(), enc_ext))
    } else {
        // No extension, just append .enc
        let mut path_str = path.to_string_lossy().into_owned();
        path_str.push('.');
        path_str.push_str(enc_ext);
        PathBuf::from(path_str)
    }
}

fn decrypt_path(path: &Path, enc_ext: &str) -> Option<PathBuf> {
    let path_str = path.to_string_lossy();
    let enc_suffix = format!(".{}", enc_ext);
    
    if path_str.ends_with(&enc_suffix) {
        let new_path = path_str[..path_str.len() - enc_suffix.len()].to_string();
        Some(PathBuf::from(new_path))
    } else {
        None
    }
}

fn main() {
    let test_cases = vec![
        ".env",
        "secrets.txt",
        "config.json",
        ".gitignore",
        "file.tar.gz",
        "noextension",
    ];
    
    println!("Testing encryption paths:");
    for path_str in &test_cases {
        let path = Path::new(path_str);
        let encrypted = encrypt_path(path, "enc");
        println!("{} -> {}", path_str, encrypted.display());
    }
    
    println!("\nTesting decryption paths:");
    let encrypted_cases = vec![
        ".env.enc",
        "secrets.txt.enc",
        "config.json.enc",
        ".gitignore.enc",
        "file.tar.gz.enc",
        "noextension.enc",
    ];
    
    for path_str in &encrypted_cases {
        let path = Path::new(path_str);
        match decrypt_path(path, "enc") {
            Some(decrypted) => println!("{} -> {}", path_str, decrypted.display()),
            None => println!("{} -> ERROR: doesn't end with .enc", path_str),
        }
    }
}