//! Secret storage traits and implementations

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::crypto::{EncryptedSecret, PlaintextSecret};
use crate::error::CryptoResult;

/// Trait for secret storage backends
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Store a secret
    async fn store(&self, key: &str, secret: EncryptedSecret) -> CryptoResult<()>;
    
    /// Retrieve a secret
    async fn retrieve(&self, key: &str) -> CryptoResult<Option<EncryptedSecret>>;
    
    /// Delete a secret
    async fn delete(&self, key: &str) -> CryptoResult<()>;
    
    /// List all secret keys
    async fn list(&self) -> CryptoResult<Vec<String>>;
}

/// In-memory secret store implementation
#[derive(Debug, Clone)]
pub struct MemorySecretStore {
    secrets: Arc<RwLock<HashMap<String, EncryptedSecret>>>,
}

impl MemorySecretStore {
    /// Create a new memory secret store
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for MemorySecretStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretStore for MemorySecretStore {
    async fn store(&self, key: &str, secret: EncryptedSecret) -> CryptoResult<()> {
        let mut secrets = self.secrets.write().await;
        secrets.insert(key.to_string(), secret);
        Ok(())
    }
    
    async fn retrieve(&self, key: &str) -> CryptoResult<Option<EncryptedSecret>> {
        let secrets = self.secrets.read().await;
        Ok(secrets.get(key).cloned())
    }
    
    async fn delete(&self, key: &str) -> CryptoResult<()> {
        let mut secrets = self.secrets.write().await;
        secrets.remove(key);
        Ok(())
    }
    
    async fn list(&self) -> CryptoResult<Vec<String>> {
        let secrets = self.secrets.read().await;
        Ok(secrets.keys().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_memory_store() {
        let store = MemorySecretStore::new();
        
        // Test store and retrieve
        let secret = EncryptedSecret::default();
        store.store("test", secret.clone()).await.unwrap();
        
        let retrieved = store.retrieve("test").await.unwrap();
        assert!(retrieved.is_some());
        
        // Test list
        let keys = store.list().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], "test");
        
        // Test delete
        store.delete("test").await.unwrap();
        let retrieved = store.retrieve("test").await.unwrap();
        assert!(retrieved.is_none());
    }
}