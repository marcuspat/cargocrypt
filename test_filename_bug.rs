use std::path::Path;

fn main() {
    // Test various file paths
    let test_paths = vec![
        ".env",
        "secrets.txt",
        "config.json",
        ".gitignore",
        "file.tar.gz",
        "noextension",
    ];
    
    for path_str in test_paths {
        let path = Path::new(path_str);
        
        // Current behavior
        let ext = path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("");
        
        let current_output = path.with_extension(
            format!("{}.enc", ext)
        );
        
        println!("{} -> {} (extension: '{}')", 
            path_str, 
            current_output.display(),
            ext
        );
    }
}