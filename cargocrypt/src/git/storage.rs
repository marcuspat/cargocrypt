//! Encrypted storage in Git repositories
//! 
//! This module provides encrypted blob storage within Git repositories,
//! enabling secure storage of encrypted files alongside regular git operations.
//! It supports git-native patterns for storing and retrieving encrypted data.

use super::{GitRepo, GitError, GitResult};
use crate::crypto::{CryptoEngine, EncryptedSecret, PlaintextSecret, SecretMetadata, CryptoResult};
use git2::{Repository, Oid, ObjectType, Blob, Tree, TreeBuilder, Signature};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use serde::{Deserialize, Serialize};
use base64ct::{Base64, Encoding};

/// Configuration for encrypted storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Git ref for storing encrypted objects
    pub storage_ref: String,
    /// Whether to compress encrypted data
    pub compress: bool,
    /// Maximum blob size before splitting
    pub max_blob_size: usize,
    /// Storage version for compatibility
    pub version: u32,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_ref: "refs/cargocrypt/storage".to_string(),
            compress: true,
            max_blob_size: 1024 * 1024, // 1MB
            version: 1,
        }
    }
}

/// Reference to a stored encrypted object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageRef {
    /// Git object ID
    pub oid: String,
    /// Path within the storage tree
    pub path: String,
    /// Metadata about the stored object
    pub metadata: StorageMetadata,
}

/// Metadata for stored objects
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetadata {
    /// Original file path
    pub original_path: String,
    /// File size (encrypted)
    pub size: u64,
    /// Storage timestamp
    pub timestamp: u64,
    /// Checksum of encrypted data
    pub checksum: String,
    /// Encryption algorithm used
    pub algorithm: String,
    /// Whether data is compressed
    pub compressed: bool,
}

/// Encrypted storage manager for Git repositories
pub struct EncryptedStorage {
    repo: GitRepo,
    crypto: CryptoEngine,
    config: StorageConfig,
}

impl EncryptedStorage {
    /// Create a new encrypted storage manager
    pub fn new(repo: &GitRepo, crypto: &CryptoEngine) -> GitResult<Self> {
        let config = StorageConfig::default();
        
        Ok(Self {
            repo: repo.clone(),
            crypto: crypto.clone(),
            config,
        })
    }
    
    /// Create with custom configuration
    pub fn with_config(repo: &GitRepo, crypto: &CryptoEngine, config: StorageConfig) -> GitResult<Self> {
        Ok(Self {
            repo: repo.clone(),
            crypto: crypto.clone(),
            config,
        })
    }
    
    /// Initialize encrypted storage in the repository
    pub async fn initialize(&self) -> GitResult<()> {
        // Create initial storage tree
        let git_repo = self.repo.inner();
        let signature = self.get_signature()?;
        
        // Create empty tree for storage
        let mut tree_builder = git_repo.treebuilder(None)?;
        let tree_oid = tree_builder.write()?;
        let tree = git_repo.find_tree(tree_oid)?;
        
        // Create initial commit for storage
        let commit_oid = git_repo.commit(
            Some(&self.config.storage_ref),
            &signature,
            &signature,
            "Initialize CargoCrypt encrypted storage",
            &tree,
            &[],
        )?;
        
        // Create storage configuration
        let storage_config_path = self.repo.workdir().join(".cargocrypt").join("storage.toml");
        let config_content = toml::to_string(&self.config)
            .map_err(|e| GitError::StorageFailed(format!("Failed to serialize config: {}", e)))?;
        
        fs::write(&storage_config_path, config_content).await
            .map_err(|e| GitError::StorageFailed(format!("Failed to write storage config: {}", e)))?;
        
        Ok(())
    }
    
    /// Store encrypted data in git storage
    pub async fn store(&self, file_path: &Path, encrypted_secret: &EncryptedSecret) -> GitResult<StorageRef> {
        let git_repo = self.repo.inner();
        
        // Serialize encrypted data
        let encrypted_data = self.serialize_encrypted_secret(encrypted_secret)?;
        
        // Compress if enabled
        let final_data = if self.config.compress {
            self.compress_data(&encrypted_data)?
        } else {
            encrypted_data
        };
        
        // Create blob in git
        let blob_oid = git_repo.blob(&final_data)?;
        
        // Create storage metadata
        let metadata = StorageMetadata {
            original_path: file_path.to_string_lossy().to_string(),
            size: final_data.len() as u64,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            checksum: self.calculate_checksum(&final_data),
            algorithm: encrypted_secret.metadata().algorithm.clone(),
            compressed: self.config.compress,
        };
        
        // Store in storage tree
        let storage_path = self.get_storage_path(file_path);
        self.update_storage_tree(&storage_path, blob_oid, &metadata).await?;
        
        Ok(StorageRef {
            oid: blob_oid.to_string(),
            path: storage_path,
            metadata,
        })
    }
    
    /// Retrieve encrypted data from git storage
    pub async fn retrieve(&self, storage_ref: &StorageRef) -> GitResult<EncryptedSecret> {
        let git_repo = self.repo.inner();
        
        // Get blob from git
        let oid = Oid::from_str(&storage_ref.oid)
            .map_err(|e| GitError::StorageFailed(format!("Invalid OID: {}", e)))?;
        let blob = git_repo.find_blob(oid)?;
        
        // Decompress if needed
        let data = if storage_ref.metadata.compressed {
            self.decompress_data(blob.content())?
        } else {
            blob.content().to_vec()
        };
        
        // Deserialize encrypted secret
        self.deserialize_encrypted_secret(&data)
    }
    
    /// List all stored encrypted files
    pub async fn list_stored_files(&self) -> GitResult<Vec<StorageRef>> {
        let git_repo = self.repo.inner();
        let mut stored_files = Vec::new();
        
        // Get current storage tree
        if let Ok(storage_ref) = git_repo.find_reference(&self.config.storage_ref) {
            let commit = git_repo.find_commit(storage_ref.target().unwrap())?;
            let tree = commit.tree()?;
            
            // Walk the tree to find all stored files
            tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
                if entry.kind() == Some(ObjectType::Blob) {
                    let entry_name = entry.name().unwrap_or("");
                    let full_path = if root.is_empty() {
                        entry_name.to_string()
                    } else {
                        format!("{}{}", root, entry_name)
                    };
                    
                    // Try to load metadata
                    if let Ok(metadata) = self.load_metadata_for_path(&full_path) {
                        stored_files.push(StorageRef {
                            oid: entry.id().to_string(),
                            path: full_path,
                            metadata,
                        });
                    }
                }
                git2::TreeWalkResult::Ok
            })?;
        }
        
        Ok(stored_files)
    }
    
    /// Delete a stored file
    pub async fn delete(&self, storage_ref: &StorageRef) -> GitResult<()> {
        // Remove from storage tree
        self.remove_from_storage_tree(&storage_ref.path).await?;
        
        Ok(())
    }
    
    /// Update storage tree with new entry
    async fn update_storage_tree(&self, path: &str, blob_oid: Oid, metadata: &StorageMetadata) -> GitResult<()> {
        let git_repo = self.repo.inner();
        let signature = self.get_signature()?;
        
        // Get current storage tree or create new one
        let current_tree = if let Ok(storage_ref) = git_repo.find_reference(&self.config.storage_ref) {
            let commit = git_repo.find_commit(storage_ref.target().unwrap())?;
            Some(commit.tree()?)
        } else {
            None
        };
        
        // Create new tree with updated entry
        let mut tree_builder = git_repo.treebuilder(current_tree.as_ref())?;
        
        // Add the blob entry
        tree_builder.insert(path, blob_oid, git2::FileMode::Blob.into())?;
        
        // Store metadata as a separate blob
        let metadata_path = format!("{}.metadata", path);
        let metadata_json = serde_json::to_string(metadata)
            .map_err(|e| GitError::StorageFailed(format!("Failed to serialize metadata: {}", e)))?;
        let metadata_oid = git_repo.blob(metadata_json.as_bytes())?;
        tree_builder.insert(&metadata_path, metadata_oid, git2::FileMode::Blob.into())?;
        
        let tree_oid = tree_builder.write()?;
        let tree = git_repo.find_tree(tree_oid)?;
        
        // Create commit
        let parent_commits = if let Ok(storage_ref) = git_repo.find_reference(&self.config.storage_ref) {
            vec![git_repo.find_commit(storage_ref.target().unwrap())?]
        } else {
            vec![]
        };
        
        let parent_refs: Vec<&git2::Commit> = parent_commits.iter().collect();
        
        git_repo.commit(
            Some(&self.config.storage_ref),
            &signature,
            &signature,
            &format!("Store encrypted file: {}", path),
            &tree,
            &parent_refs,
        )?;
        
        Ok(())
    }
    
    /// Remove entry from storage tree
    async fn remove_from_storage_tree(&self, path: &str) -> GitResult<()> {
        let git_repo = self.repo.inner();
        let signature = self.get_signature()?;
        
        // Get current storage tree
        let storage_ref = git_repo.find_reference(&self.config.storage_ref)?;
        let commit = git_repo.find_commit(storage_ref.target().unwrap())?;
        let current_tree = commit.tree()?;
        
        // Create new tree without the entry
        let mut tree_builder = git_repo.treebuilder(Some(&current_tree))?;
        tree_builder.remove(path)?;
        tree_builder.remove(&format!("{}.metadata", path))?; // Remove metadata too
        
        let tree_oid = tree_builder.write()?;
        let tree = git_repo.find_tree(tree_oid)?;
        
        // Create commit
        git_repo.commit(
            Some(&self.config.storage_ref),
            &signature,
            &signature,
            &format!("Remove encrypted file: {}", path),
            &tree,
            &[&commit],
        )?;
        
        Ok(())
    }
    
    /// Get storage path for a file
    fn get_storage_path(&self, file_path: &Path) -> String {
        // Convert file path to storage path (flatten directory structure)
        let path_str = file_path.to_string_lossy();
        path_str.replace('/', "_").replace('\\', "_")
    }
    
    /// Load metadata for a storage path
    fn load_metadata_for_path(&self, path: &str) -> GitResult<StorageMetadata> {
        let git_repo = self.repo.inner();
        let metadata_path = format!("{}.metadata", path);
        
        let storage_ref = git_repo.find_reference(&self.config.storage_ref)?;
        let commit = git_repo.find_commit(storage_ref.target().unwrap())?;
        let tree = commit.tree()?;
        
        let metadata_entry = tree.get_path(Path::new(&metadata_path))?;
        let metadata_blob = git_repo.find_blob(metadata_entry.id())?;
        
        let metadata: StorageMetadata = serde_json::from_slice(metadata_blob.content())
            .map_err(|e| GitError::StorageFailed(format!("Failed to deserialize metadata: {}", e)))?;
        
        Ok(metadata)
    }
    
    /// Serialize encrypted secret to bytes
    fn serialize_encrypted_secret(&self, encrypted_secret: &EncryptedSecret) -> GitResult<Vec<u8>> {
        bincode::serialize(encrypted_secret)
            .map_err(|e| GitError::StorageFailed(format!("Failed to serialize encrypted secret: {}", e)))
    }
    
    /// Deserialize encrypted secret from bytes
    fn deserialize_encrypted_secret(&self, data: &[u8]) -> GitResult<EncryptedSecret> {
        bincode::deserialize(data)
            .map_err(|e| GitError::StorageFailed(format!("Failed to deserialize encrypted secret: {}", e)))
    }
    
    /// Compress data using built-in compression
    fn compress_data(&self, data: &[u8]) -> GitResult<Vec<u8>> {
        use std::io::Write;
        use std::io::prelude::*;
        
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data)
            .map_err(|e| GitError::StorageFailed(format!("Compression failed: {}", e)))?;
        encoder.finish()
            .map_err(|e| GitError::StorageFailed(format!("Compression finish failed: {}", e)))
    }
    
    /// Decompress data
    fn decompress_data(&self, data: &[u8]) -> GitResult<Vec<u8>> {
        use std::io::prelude::*;
        
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| GitError::StorageFailed(format!("Decompression failed: {}", e)))?;
        Ok(decompressed)
    }
    
    /// Calculate checksum of data
    fn calculate_checksum(&self, data: &[u8]) -> String {
        use ring::digest;
        let digest = digest::digest(&digest::SHA256, data);
        hex::encode(digest.as_ref())
    }
    
    /// Get git signature
    fn get_signature(&self) -> GitResult<Signature> {
        self.repo.inner().signature()
            .or_else(|_| Signature::now("CargoCrypt Storage", "storage@cargocrypt.local"))
            .map_err(|e| GitError::StorageFailed(format!("Failed to create signature: {}", e)))
    }
    
    /// Get storage statistics
    pub async fn get_storage_stats(&self) -> GitResult<StorageStats> {
        let stored_files = self.list_stored_files().await?;
        
        let total_files = stored_files.len();
        let total_size: u64 = stored_files.iter().map(|f| f.metadata.size).sum();
        let compressed_files = stored_files.iter().filter(|f| f.metadata.compressed).count();
        
        let algorithms: HashMap<String, usize> = stored_files.iter().fold(HashMap::new(), |mut acc, f| {
            *acc.entry(f.metadata.algorithm.clone()).or_insert(0) += 1;
            acc
        });
        
        Ok(StorageStats {
            total_files,
            total_size,
            compressed_files,
            algorithms,
            storage_ref: self.config.storage_ref.clone(),
        })
    }
    
    /// Optimize storage (garbage collection, compression)
    pub async fn optimize(&self) -> GitResult<OptimizationResult> {
        let mut result = OptimizationResult::default();
        
        // Get current stats
        let stored_files = self.list_stored_files().await?;
        result.files_before = stored_files.len();
        result.size_before = stored_files.iter().map(|f| f.metadata.size).sum();
        
        // TODO: Implement optimization strategies:
        // 1. Remove duplicate blobs
        // 2. Recompress with better algorithms
        // 3. Merge small files
        // 4. Remove orphaned metadata
        
        // For now, just return current stats
        result.files_after = result.files_before;
        result.size_after = result.size_before;
        
        Ok(result)
    }
    
    /// Export storage to external format
    pub async fn export(&self, export_path: &Path) -> GitResult<()> {
        let stored_files = self.list_stored_files().await?;
        
        // Create export directory
        fs::create_dir_all(export_path).await
            .map_err(|e| GitError::StorageFailed(format!("Failed to create export directory: {}", e)))?;
        
        // Export each file
        for storage_ref in stored_files {
            let encrypted_secret = self.retrieve(&storage_ref).await?;
            let export_file_path = export_path.join(&storage_ref.path);
            
            // Serialize to file
            let serialized = self.serialize_encrypted_secret(&encrypted_secret)?;
            fs::write(&export_file_path, serialized).await
                .map_err(|e| GitError::StorageFailed(format!("Failed to export file: {}", e)))?;
            
            // Export metadata
            let metadata_path = export_file_path.with_extension("metadata.json");
            let metadata_json = serde_json::to_string_pretty(&storage_ref.metadata)
                .map_err(|e| GitError::StorageFailed(format!("Failed to serialize metadata: {}", e)))?;
            fs::write(&metadata_path, metadata_json).await
                .map_err(|e| GitError::StorageFailed(format!("Failed to export metadata: {}", e)))?;
        }
        
        Ok(())
    }
}

/// Storage statistics
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub total_files: usize,
    pub total_size: u64,
    pub compressed_files: usize,
    pub algorithms: HashMap<String, usize>,
    pub storage_ref: String,
}

/// Optimization result
#[derive(Debug, Clone, Default)]
pub struct OptimizationResult {
    pub files_before: usize,
    pub files_after: usize,
    pub size_before: u64,
    pub size_after: u64,
    pub operations_performed: Vec<String>,
}

/// Git object storage for large files
pub struct GitObjectStorage {
    repo: GitRepo,
    config: StorageConfig,
}

impl GitObjectStorage {
    /// Create a new git object storage
    pub fn new(repo: &GitRepo) -> GitResult<Self> {
        let config = StorageConfig::default();
        
        Ok(Self {
            repo: repo.clone(),
            config,
        })
    }
    
    /// Store a large file as git objects
    pub async fn store_large_file(&self, file_path: &Path) -> GitResult<Vec<Oid>> {
        let git_repo = self.repo.inner();
        let mut oids = Vec::new();
        
        let file_content = fs::read(file_path).await
            .map_err(|e| GitError::StorageFailed(format!("Failed to read file: {}", e)))?;
        
        // Split into chunks if larger than max blob size
        let chunks = if file_content.len() > self.config.max_blob_size {
            file_content.chunks(self.config.max_blob_size).collect::<Vec<_>>()
        } else {
            vec![&file_content[..]]
        };
        
        // Store each chunk as a blob
        for chunk in chunks {
            let oid = git_repo.blob(chunk)?;
            oids.push(oid);
        }
        
        Ok(oids)
    }
    
    /// Retrieve a large file from git objects
    pub async fn retrieve_large_file(&self, oids: &[Oid]) -> GitResult<Vec<u8>> {
        let git_repo = self.repo.inner();
        let mut content = Vec::new();
        
        for oid in oids {
            let blob = git_repo.find_blob(*oid)?;
            content.extend_from_slice(blob.content());
        }
        
        Ok(content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::crypto::{PlaintextSecret, SecretType};
    
    #[tokio::test]
    async fn test_encrypted_storage_creation() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let crypto = CryptoEngine::new();
        let storage = EncryptedStorage::new(&repo, &crypto).unwrap();
        
        storage.initialize().await.unwrap();
        
        // Check that storage config was created
        let config_path = temp_dir.path().join(".cargocrypt/storage.toml");
        assert!(config_path.exists());
    }
    
    #[tokio::test]
    async fn test_store_and_retrieve() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let crypto = CryptoEngine::new();
        let storage = EncryptedStorage::new(&repo, &crypto).unwrap();
        
        storage.initialize().await.unwrap();
        
        // Create test secret
        let plaintext = PlaintextSecret::new("test-secret".to_string(), SecretType::ApiKey);
        let encrypted = crypto.encrypt(&plaintext).await.unwrap();
        
        // Store in git
        let file_path = Path::new("test.secret");
        let storage_ref = storage.store(file_path, &encrypted).await.unwrap();
        
        // Retrieve from git
        let retrieved = storage.retrieve(&storage_ref).await.unwrap();
        
        // Decrypt and verify
        let decrypted = crypto.decrypt(&retrieved).await.unwrap();
        assert_eq!(decrypted.value(), plaintext.value());
    }
    
    #[tokio::test]
    async fn test_list_stored_files() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let crypto = CryptoEngine::new();
        let storage = EncryptedStorage::new(&repo, &crypto).unwrap();
        
        storage.initialize().await.unwrap();
        
        // Store multiple files
        for i in 0..3 {
            let plaintext = PlaintextSecret::new(format!("secret-{}", i), SecretType::ApiKey);
            let encrypted = crypto.encrypt(&plaintext).await.unwrap();
            let file_path = Path::new(&format!("test{}.secret", i));
            storage.store(file_path, &encrypted).await.unwrap();
        }
        
        // List stored files
        let stored_files = storage.list_stored_files().await.unwrap();
        assert_eq!(stored_files.len(), 3);
    }
    
    #[tokio::test]
    async fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let crypto = CryptoEngine::new();
        let storage = EncryptedStorage::new(&repo, &crypto).unwrap();
        
        storage.initialize().await.unwrap();
        
        // Store a test file
        let plaintext = PlaintextSecret::new("test-secret".to_string(), SecretType::ApiKey);
        let encrypted = crypto.encrypt(&plaintext).await.unwrap();
        let file_path = Path::new("test.secret");
        storage.store(file_path, &encrypted).await.unwrap();
        
        // Get stats
        let stats = storage.get_storage_stats().await.unwrap();
        assert_eq!(stats.total_files, 1);
        assert!(stats.total_size > 0);
    }
}