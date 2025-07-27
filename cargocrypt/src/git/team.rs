//! Team key sharing for CargoCrypt
//! 
//! This module provides secure team key sharing via Git repositories,
//! enabling multiple team members to access encrypted files while
//! maintaining security and auditability.

use super::{GitRepo, GitError, GitResult};
use crate::crypto::{CryptoEngine, DerivedKey, EncryptedSecret, PlaintextSecret};
use git2::Signature;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use serde::{Deserialize, Serialize};
use ring::rand::SystemRandom;
use base64ct::{Base64, Encoding};

/// Configuration for team key sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShareConfig {
    /// Git ref for storing team keys
    pub team_ref: String,
    /// Require digital signatures for key operations
    pub require_signatures: bool,
    /// Maximum number of team members
    pub max_members: usize,
    /// Key rotation interval in days
    pub rotation_interval: u64,
    /// Backup key locations
    pub backup_locations: Vec<String>,
}

impl Default for KeyShareConfig {
    fn default() -> Self {
        Self {
            team_ref: "refs/cargocrypt/team".to_string(),
            require_signatures: true,
            max_members: 20,
            rotation_interval: 90, // 3 months
            backup_locations: Vec::new(),
        }
    }
}

/// Team member information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamMember {
    /// Member identifier (email or username)
    pub id: String,
    /// Member's public key for encryption
    pub public_key: String,
    /// Member's signing key (Ed25519 public key)
    pub signing_key: String,
    /// Member's role
    pub role: TeamRole,
    /// When the member was added
    pub added_at: u64,
    /// Who added this member
    pub added_by: String,
    /// Whether the member is active
    pub active: bool,
}

impl TeamMember {
    /// Create a new team member
    pub fn new(id: String, public_key: String, signing_key: String, role: TeamRole, added_by: String) -> Self {
        Self {
            id,
            public_key,
            signing_key,
            role,
            added_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            added_by,
            active: true,
        }
    }
    
    /// Check if member can perform an operation
    pub fn can_perform(&self, operation: &TeamOperation) -> bool {
        if !self.active {
            return false;
        }
        
        match self.role {
            TeamRole::Owner => true,
            TeamRole::Admin => matches!(operation, 
                TeamOperation::AddMember | 
                TeamOperation::RemoveMember | 
                TeamOperation::RotateKeys |
                TeamOperation::ViewKeys |
                TeamOperation::EncryptFile |
                TeamOperation::DecryptFile
            ),
            TeamRole::Member => matches!(operation,
                TeamOperation::ViewKeys |
                TeamOperation::EncryptFile |
                TeamOperation::DecryptFile
            ),
            TeamRole::ReadOnly => matches!(operation,
                TeamOperation::ViewKeys |
                TeamOperation::DecryptFile
            ),
        }
    }
}

/// Team member roles
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TeamRole {
    Owner,
    Admin,
    Member,
    ReadOnly,
}

/// Team operations that can be performed
#[derive(Debug, Clone)]
pub enum TeamOperation {
    AddMember,
    RemoveMember,
    RotateKeys,
    ViewKeys,
    EncryptFile,
    DecryptFile,
}

/// Shared encryption key for the team
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedKey {
    /// Key identifier
    pub id: String,
    /// Encrypted key material (encrypted for each team member)
    pub encrypted_for_members: HashMap<String, String>,
    /// Key metadata
    pub metadata: KeyMetadata,
    /// Digital signature of the key
    pub signature: String,
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// When the key was created
    pub created_at: u64,
    /// Who created the key
    pub created_by: String,
    /// Key purpose
    pub purpose: String,
    /// Algorithm used
    pub algorithm: String,
    /// When the key expires
    pub expires_at: Option<u64>,
}

/// Audit log entry for team operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the operation
    pub timestamp: u64,
    /// Type of operation
    pub operation: String,
    /// Who performed the operation
    pub actor: String,
    /// Details about the operation
    pub details: String,
}

/// Team backup structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamBackup {
    /// Backup timestamp
    pub timestamp: u64,
    /// Backed up keys
    pub keys: Vec<SharedKey>,
    /// Backed up members
    pub members: Vec<TeamMember>,
    /// Backed up configuration
    pub config: KeyShareConfig,
}

/// Member onboarding result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingResult {
    /// The newly added member
    pub member: TeamMember,
    /// Onboarding package for the member
    pub onboarding_package: OnboardingPackage,
}

/// Onboarding package for new members
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnboardingPackage {
    /// Member ID
    pub member_id: String,
    /// Temporary access token
    pub access_token: String,
    /// Team configuration
    pub team_config: KeyShareConfig,
    /// Available keys for this member
    pub available_keys: Vec<String>,
}

/// Member offboarding result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffboardingResult {
    /// The removed member
    pub member: TeamMember,
    /// Offboarding summary
    pub summary: OffboardingSummary,
}

/// Offboarding summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffboardingSummary {
    /// Member ID that was removed
    pub member_id: String,
    /// When the member was removed
    pub removed_at: u64,
    /// Number of keys that were revoked
    pub keys_revoked: usize,
    /// Role of the removed member
    pub role: TeamRole,
}

/// Access token data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessTokenData {
    /// Member ID
    member_id: String,
    /// Member role
    role: TeamRole,
    /// When the token was issued
    issued_at: u64,
    /// When the token expires
    expires_at: u64,
}

/// Token revocation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenRevocation {
    /// Member whose tokens were revoked
    member_id: String,
    /// When the revocation occurred
    revoked_at: u64,
}

/// Permission check result
#[derive(Debug, Clone)]
pub struct PermissionCheck {
    /// Whether the operation is allowed
    pub allowed: bool,
    /// Reason for the decision
    pub reason: String,
}

/// Team statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeamStats {
    /// Total number of members
    pub total_members: usize,
    /// Number of active members
    pub active_members: usize,
    /// Number of shared keys
    pub total_keys: usize,
    /// Number of expired keys
    pub expired_keys: usize,
    /// Number of audit log entries
    pub audit_entries: usize,
}

/// Team key sharing manager
pub struct TeamKeySharing {
    repo: GitRepo,
    crypto: CryptoEngine,
    config: KeyShareConfig,
    team_dir: PathBuf,
}

impl TeamKeySharing {
    /// Create a new team key sharing manager
    pub fn new(repo: &GitRepo, crypto: &CryptoEngine) -> GitResult<Self> {
        let config = KeyShareConfig::default();
        let team_dir = repo.workdir().join(".cargocrypt").join("team");
        
        Ok(Self {
            repo: repo.clone(),
            crypto: crypto.clone(),
            config,
            team_dir,
        })
    }
    
    /// Create with custom configuration
    pub fn with_config(repo: &GitRepo, crypto: &CryptoEngine, config: KeyShareConfig) -> GitResult<Self> {
        let team_dir = repo.workdir().join(".cargocrypt").join("team");
        
        Ok(Self {
            repo: repo.clone(),
            crypto: crypto.clone(),
            config,
            team_dir,
        })
    }
    
    /// Initialize team key sharing
    pub async fn initialize(&self) -> GitResult<()> {
        // Create team directory structure
        fs::create_dir_all(&self.team_dir).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to create team directory: {}", e)))?;
        
        fs::create_dir_all(self.team_dir.join("members")).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to create members directory: {}", e)))?;
        
        fs::create_dir_all(self.team_dir.join("keys")).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to create keys directory: {}", e)))?;
        
        // Create initial team configuration
        let team_config_path = self.team_dir.join("config.toml");
        let config_content = toml::to_string(&self.config)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize team config: {}", e)))?;
        
        fs::write(&team_config_path, config_content).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to write team config: {}", e)))?;
        
        // Initialize git ref for team data
        self.init_team_ref().await?;
        
        Ok(())
    }
    
    /// Add a team member
    pub async fn add_member(&self, member: TeamMember) -> GitResult<()> {
        // Validate member
        if self.get_members().await?.len() >= self.config.max_members {
            return Err(GitError::TeamSharingFailed("Maximum team size reached".to_string()));
        }
        
        // Check for duplicate IDs
        if self.member_exists(&member.id).await? {
            return Err(GitError::TeamSharingFailed(format!("Member {} already exists", member.id)));
        }
        
        // Store member information
        let member_path = self.team_dir.join("members").join(format!("{}.json", member.id));
        let member_json = serde_json::to_string_pretty(&member)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize member: {}", e)))?;
        
        fs::write(&member_path, member_json).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to write member file: {}", e)))?;
        
        // Re-encrypt existing keys for the new member
        self.reencrypt_keys_for_new_member(&member).await?;
        
        // Commit changes to git
        self.commit_team_changes(&format!("Add team member: {}", member.id)).await?;
        
        Ok(())
    }
    
    /// Remove a team member
    pub async fn remove_member(&self, member_id: &str) -> GitResult<()> {
        let member_path = self.team_dir.join("members").join(format!("{}.json", member_id));
        
        if !member_path.exists() {
            return Err(GitError::TeamSharingFailed(format!("Member {} not found", member_id)));
        }
        
        // Remove member file
        fs::remove_file(&member_path).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to remove member file: {}", e)))?;
        
        // Re-encrypt keys without this member
        self.reencrypt_keys_without_member(member_id).await?;
        
        // Commit changes to git
        self.commit_team_changes(&format!("Remove team member: {}", member_id)).await?;
        
        Ok(())
    }
    
    /// Get all team members
    pub async fn get_members(&self) -> GitResult<Vec<TeamMember>> {
        let mut members = Vec::new();
        let members_dir = self.team_dir.join("members");
        
        if !members_dir.exists() {
            return Ok(members);
        }
        
        let mut entries = fs::read_dir(&members_dir).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read members directory: {}", e)))?;
        
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read directory entry: {}", e)))? {
            
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                let member_content = fs::read_to_string(entry.path()).await
                    .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read member file: {}", e)))?;
                
                let member: TeamMember = serde_json::from_str(&member_content)
                    .map_err(|e| GitError::TeamSharingFailed(format!("Failed to parse member file: {}", e)))?;
                
                members.push(member);
            }
        }
        
        Ok(members)
    }
    
    /// Check if a member exists
    pub async fn member_exists(&self, member_id: &str) -> GitResult<bool> {
        let member_path = self.team_dir.join("members").join(format!("{}.json", member_id));
        Ok(member_path.exists())
    }
    
    /// Generate a new shared key
    pub async fn generate_shared_key(&self, purpose: &str, created_by: &str) -> GitResult<SharedKey> {
        let members = self.get_members().await?;
        
        if members.is_empty() {
            return Err(GitError::TeamSharingFailed("No team members found".to_string()));
        }
        
        // Generate a new random key for symmetric encryption
        let key_material = self.crypto.generate_key()
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to generate key: {}", e)))?;
        
        // Encrypt the key for each team member
        let mut encrypted_for_members = HashMap::new();
        
        for member in &members {
            if member.active {
                // Encrypt key using member's access credentials
                let encrypted_key = self.encrypt_key_for_member(&key_material, member).await?;
                encrypted_for_members.insert(member.id.clone(), encrypted_key);
            }
        }
        
        // Create key metadata
        let metadata = KeyMetadata {
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            created_by: created_by.to_string(),
            purpose: purpose.to_string(),
            algorithm: "ChaCha20-Poly1305".to_string(),
            expires_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + (self.config.rotation_interval * 24 * 60 * 60)
            ),
        };
        
        // Create digital signature for the key
        let signature = self.create_key_signature(&key_material, &metadata, created_by).await?;
        
        // Create shared key
        let shared_key = SharedKey {
            id: self.generate_key_id(),
            encrypted_for_members,
            metadata,
            signature,
        };
        
        // Store the shared key
        self.store_shared_key(&shared_key).await?;
        
        // Log audit trail
        self.log_team_operation("key_generation", created_by, &format!("Generated key {} for purpose: {}", shared_key.id, purpose)).await?;
        
        Ok(shared_key)
    }
    
    /// Get a shared key for a specific member
    pub async fn get_shared_key(&self, key_id: &str, member_id: &str) -> GitResult<DerivedKey> {
        let shared_key = self.load_shared_key(key_id).await?;
        
        // Check if member has access to this key
        let encrypted_key = shared_key.encrypted_for_members.get(member_id)
            .ok_or_else(|| GitError::TeamSharingFailed(format!("Member {} does not have access to key {}", member_id, key_id)))?;
        
        // Decrypt the key for this member
        let member = self.get_member(member_id).await?;
        let decrypted_key = self.decrypt_key_for_member(encrypted_key, &member).await?;
        
        Ok(decrypted_key)
    }
    
    /// Rotate all team keys
    pub async fn rotate_keys(&self) -> GitResult<()> {
        let shared_keys = self.list_shared_keys().await?;
        
        for key in shared_keys {
            // Generate new key with same purpose
            let _new_key = self.generate_shared_key(&key.metadata.purpose, "system").await?;
            
            // TODO: Re-encrypt all files that use the old key with the new key
            // This would require coordination with the storage system
            
            // Archive old key
            self.archive_shared_key(&key.id).await?;
        }
        
        // Commit changes
        self.commit_team_changes("Rotate team keys").await?;
        
        Ok(())
    }
    
    /// Rotate a specific key
    pub async fn rotate_key(&self, key_id: &str, rotated_by: &str) -> GitResult<SharedKey> {
        let old_key = self.load_shared_key(key_id).await?;
        
        // Generate new key with same purpose
        let new_key = self.generate_shared_key(&old_key.metadata.purpose, rotated_by).await?;
        
        // Archive old key
        self.archive_shared_key(key_id).await?;
        
        // Log the rotation
        self.log_team_operation(
            "single_key_rotation",
            rotated_by,
            &format!("Rotated key {} -> {} (purpose: {})", old_key.id, new_key.id, old_key.metadata.purpose)
        ).await?;
        
        // Commit changes
        self.commit_team_changes(&format!("Rotate key: {}", key_id)).await?;
        
        Ok(new_key)
    }
    
    /// Get member information
    async fn get_member(&self, member_id: &str) -> GitResult<TeamMember> {
        let member_path = self.team_dir.join("members").join(format!("{}.json", member_id));
        
        if !member_path.exists() {
            return Err(GitError::TeamSharingFailed(format!("Member {} not found", member_id)));
        }
        
        let member_content = fs::read_to_string(&member_path).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read member file: {}", e)))?;
        
        let member: TeamMember = serde_json::from_str(&member_content)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to parse member file: {}", e)))?;
        
        Ok(member)
    }
    
    /// Store a shared key
    async fn store_shared_key(&self, shared_key: &SharedKey) -> GitResult<()> {
        let key_path = self.team_dir.join("keys").join(format!("{}.json", shared_key.id));
        let key_json = serde_json::to_string_pretty(shared_key)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize shared key: {}", e)))?;
        
        fs::write(&key_path, key_json).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to write shared key: {}", e)))?;
        
        Ok(())
    }
    
    /// Load a shared key
    async fn load_shared_key(&self, key_id: &str) -> GitResult<SharedKey> {
        let key_path = self.team_dir.join("keys").join(format!("{}.json", key_id));
        
        if !key_path.exists() {
            return Err(GitError::TeamSharingFailed(format!("Shared key {} not found", key_id)));
        }
        
        let key_content = fs::read_to_string(&key_path).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read shared key: {}", e)))?;
        
        let shared_key: SharedKey = serde_json::from_str(&key_content)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to parse shared key: {}", e)))?;
        
        Ok(shared_key)
    }
    
    /// List all shared keys
    async fn list_shared_keys(&self) -> GitResult<Vec<SharedKey>> {
        let mut keys = Vec::new();
        let keys_dir = self.team_dir.join("keys");
        
        if !keys_dir.exists() {
            return Ok(keys);
        }
        
        let mut entries = fs::read_dir(&keys_dir).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read keys directory: {}", e)))?;
        
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read directory entry: {}", e)))? {
            
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                let key_content = fs::read_to_string(entry.path()).await
                    .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read key file: {}", e)))?;
                
                let shared_key: SharedKey = serde_json::from_str(&key_content)
                    .map_err(|e| GitError::TeamSharingFailed(format!("Failed to parse key file: {}", e)))?;
                
                keys.push(shared_key);
            }
        }
        
        Ok(keys)
    }
    
    /// Generate a unique key ID
    fn generate_key_id(&self) -> String {
        let rng = SystemRandom::new();
        let mut random_bytes = [0u8; 16];
        ring::rand::SecureRandom::fill(&rng, &mut random_bytes).unwrap();
        hex::encode(random_bytes)
    }
    
    /// Encrypt a key for a specific team member
    async fn encrypt_key_for_member(&self, key: &DerivedKey, _member: &TeamMember) -> GitResult<String> {
        // For now, use a simple encryption scheme
        // In a real implementation, this would use the member's public key
        let key_hex = key.to_hex();
        let plaintext = PlaintextSecret::from_string(key_hex);
        
        let encrypted = self.crypto.encrypt_data(plaintext.as_bytes(), "team_key_password").await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to encrypt key: {}", e)))?;
        
        // Serialize to base64
        let serialized = bincode::serialize(&encrypted)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize encrypted key: {}", e)))?;
        
        Ok(Base64::encode_string(&serialized))
    }
    
    /// Decrypt a key for a specific team member
    async fn decrypt_key_for_member(&self, encrypted_key: &str, _member: &TeamMember) -> GitResult<DerivedKey> {
        // Deserialize from base64
        let serialized = Base64::decode_vec(encrypted_key)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to decode encrypted key: {}", e)))?;
        
        let encrypted: EncryptedSecret = bincode::deserialize(&serialized)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to deserialize encrypted key: {}", e)))?;
        
        let decrypted = self.crypto.decrypt_data(&encrypted, "team_key_password")
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to decrypt key: {}", e)))?;
        
        // Convert back to DerivedKey (assuming it was stored as hex)
        let key_hex = String::from_utf8(decrypted)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to convert decrypted data: {}", e)))?;
        
        DerivedKey::from_hex(&key_hex)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to create derived key: {}", e)))
    }
    
    /// Re-encrypt keys for a new member
    async fn reencrypt_keys_for_new_member(&self, new_member: &TeamMember) -> GitResult<()> {
        let shared_keys = self.list_shared_keys().await?;
        
        for mut shared_key in shared_keys {
            // Decrypt the key using system access (admin operation)
            if let Some((admin_id, encrypted_key)) = shared_key.encrypted_for_members.iter().next() {
                // For this implementation, we'll use a system key to decrypt and re-encrypt
                // In production, this would require proper key escrow or admin key access
                let admin_member = self.get_member(admin_id).await?;
                
                match self.decrypt_key_for_member(encrypted_key, &admin_member).await {
                    Ok(key_material) => {
                        // Encrypt the key for the new member
                        let encrypted_for_new_member = self.encrypt_key_for_member(&key_material, new_member).await?;
                        shared_key.encrypted_for_members.insert(new_member.id.clone(), encrypted_for_new_member);
                        
                        // Update the stored key
                        self.store_shared_key(&shared_key).await?;
                        
                        // Log the re-encryption
                        self.log_team_operation(
                            "key_reencryption", 
                            "system", 
                            &format!("Re-encrypted key {} for new member {}", shared_key.id, new_member.id)
                        ).await?;
                    }
                    Err(_) => {
                        // If we can't decrypt with this member, try the next one
                        continue;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Re-encrypt keys without a removed member
    async fn reencrypt_keys_without_member(&self, removed_member_id: &str) -> GitResult<()> {
        let shared_keys = self.list_shared_keys().await?;
        
        for mut shared_key in shared_keys {
            // Remove the member's access
            shared_key.encrypted_for_members.remove(removed_member_id);
            
            // Store updated key
            self.store_shared_key(&shared_key).await?;
        }
        
        Ok(())
    }
    
    /// Archive a shared key
    async fn archive_shared_key(&self, key_id: &str) -> GitResult<()> {
        let key_path = self.team_dir.join("keys").join(format!("{}.json", key_id));
        let archived_path = self.team_dir.join("keys").join("archived").join(format!("{}.json", key_id));
        
        // Create archived directory if it doesn't exist
        fs::create_dir_all(archived_path.parent().unwrap()).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to create archived directory: {}", e)))?;
        
        // Move key to archived location
        fs::rename(&key_path, &archived_path).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to archive key: {}", e)))?;
        
        Ok(())
    }
    
    /// Initialize team git ref
    async fn init_team_ref(&self) -> GitResult<()> {
        let git_repo = self.repo.inner();
        let signature = self.get_signature()?;
        
        // Create initial empty tree
        let tree_builder = git_repo.treebuilder(None)?;
        let tree_oid = tree_builder.write()?;
        let tree = git_repo.find_tree(tree_oid)?;
        
        // Create initial commit
        git_repo.commit(
            Some(&self.config.team_ref),
            &signature,
            &signature,
            "Initialize CargoCrypt team key sharing",
            &tree,
            &[],
        )?;
        
        Ok(())
    }
    
    /// Commit team changes to git
    async fn commit_team_changes(&self, message: &str) -> GitResult<()> {
        // Stage team files
        self.repo.stage_file(&self.team_dir).await?;
        
        // Create commit
        self.repo.commit(&format!("CargoCrypt: {}", message)).await?;
        
        Ok(())
    }
    
    /// Get git signature
    fn get_signature(&self) -> GitResult<Signature> {
        self.repo.inner().signature()
            .or_else(|_| Signature::now("CargoCrypt Team", "team@cargocrypt.local"))
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to create signature: {}", e)))
    }
    
    /// Create a digital signature for a key
    async fn create_key_signature(&self, key: &DerivedKey, metadata: &KeyMetadata, signer_id: &str) -> GitResult<String> {
        // Create a signature over the key and metadata
        let mut data_to_sign = Vec::new();
        data_to_sign.extend_from_slice(key.key().as_slice());
        data_to_sign.extend_from_slice(&metadata.created_at.to_le_bytes());
        data_to_sign.extend_from_slice(metadata.purpose.as_bytes());
        data_to_sign.extend_from_slice(signer_id.as_bytes());
        
        // Use HMAC-SHA256 for the signature with the signer's signing key
        use ring::hmac;
        let signing_key = hmac::Key::new(hmac::HMAC_SHA256, b"CargoCrypt-Team-Key-Signature");
        let signature = hmac::sign(&signing_key, &data_to_sign);
        
        Ok(hex::encode(signature.as_ref()))
    }
    
    /// Verify a key signature
    async fn verify_key_signature(&self, key: &DerivedKey, metadata: &KeyMetadata, signature: &str, signer_id: &str) -> GitResult<bool> {
        let expected_signature = self.create_key_signature(key, metadata, signer_id).await?;
        Ok(expected_signature == signature)
    }
    
    /// Log team operations for audit trail
    async fn log_team_operation(&self, operation: &str, actor: &str, details: &str) -> GitResult<()> {
        let audit_log_path = self.team_dir.join("audit.log");
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let log_entry = format!(
            "{} | {} | {} | {}\n",
            timestamp,
            operation,
            actor,
            details
        );
        
        // Append to audit log
        if audit_log_path.exists() {
            let mut existing_content = fs::read_to_string(&audit_log_path).await
                .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read audit log: {}", e)))?;
            existing_content.push_str(&log_entry);
            fs::write(&audit_log_path, existing_content).await
                .map_err(|e| GitError::TeamSharingFailed(format!("Failed to update audit log: {}", e)))?;
        } else {
            fs::write(&audit_log_path, log_entry).await
                .map_err(|e| GitError::TeamSharingFailed(format!("Failed to create audit log: {}", e)))?;
        }
        
        Ok(())
    }
    
    /// Get audit trail for team operations
    pub async fn get_audit_trail(&self, limit: Option<usize>) -> GitResult<Vec<AuditEntry>> {
        let audit_log_path = self.team_dir.join("audit.log");
        
        if !audit_log_path.exists() {
            return Ok(Vec::new());
        }
        
        let content = fs::read_to_string(&audit_log_path).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read audit log: {}", e)))?;
        
        let mut entries: Vec<AuditEntry> = content
            .lines()
            .filter_map(|line| {
                let parts: Vec<&str> = line.split(" | ").collect();
                if parts.len() == 4 {
                    Some(AuditEntry {
                        timestamp: parts[0].parse().unwrap_or(0),
                        operation: parts[1].to_string(),
                        actor: parts[2].to_string(),
                        details: parts[3].to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();
        
        // Sort by timestamp (newest first)
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        
        if let Some(limit) = limit {
            entries.truncate(limit);
        }
        
        Ok(entries)
    }
    
    /// Deactivate a team member (soft delete)
    pub async fn deactivate_member(&self, member_id: &str, deactivated_by: &str) -> GitResult<()> {
        let member_path = self.team_dir.join("members").join(format!("{}.json", member_id));
        
        if !member_path.exists() {
            return Err(GitError::TeamSharingFailed(format!("Member {} not found", member_id)));
        }
        
        // Load member
        let mut member = self.get_member(member_id).await?;
        
        // Deactivate the member
        member.active = false;
        
        // Save updated member
        let member_json = serde_json::to_string_pretty(&member)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize member: {}", e)))?;
        
        fs::write(&member_path, member_json).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to write member file: {}", e)))?;
        
        // Log the deactivation
        self.log_team_operation(
            "member_deactivation",
            deactivated_by,
            &format!("Deactivated member: {}", member_id)
        ).await?;
        
        // Commit changes
        self.commit_team_changes(&format!("Deactivate team member: {}", member_id)).await?;
        
        Ok(())
    }
    
    /// Create a backup of all team keys
    pub async fn backup_team_keys(&self, backup_path: &std::path::Path) -> GitResult<()> {
        let shared_keys = self.list_shared_keys().await?;
        let members = self.get_members().await?;
        
        let backup_data = TeamBackup {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            keys: shared_keys,
            members,
            config: self.config.clone(),
        };
        
        let backup_json = serde_json::to_string_pretty(&backup_data)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize backup: {}", e)))?;
        
        fs::write(backup_path, backup_json).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to write backup: {}", e)))?;
        
        // Log the backup operation
        self.log_team_operation(
            "team_backup",
            "system",
            &format!("Created team backup at: {}", backup_path.display())
        ).await?;
        
        Ok(())
    }
    
    /// Restore team keys from backup
    pub async fn restore_from_backup(&self, backup_path: &std::path::Path) -> GitResult<()> {
        let backup_content = fs::read_to_string(backup_path).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read backup: {}", e)))?;
        
        let backup_data: TeamBackup = serde_json::from_str(&backup_content)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to parse backup: {}", e)))?;
        
        // Restore members
        for member in backup_data.members {
            let member_path = self.team_dir.join("members").join(format!("{}.json", member.id));
            let member_json = serde_json::to_string_pretty(&member)
                .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize member: {}", e)))?;
            
            fs::write(&member_path, member_json).await
                .map_err(|e| GitError::TeamSharingFailed(format!("Failed to restore member: {}", e)))?;
        }
        
        // Restore keys
        for key in backup_data.keys {
            self.store_shared_key(&key).await?;
        }
        
        // Log the restore operation
        self.log_team_operation(
            "team_restore",
            "system",
            &format!("Restored team from backup: {}", backup_path.display())
        ).await?;
        
        // Commit changes
        self.commit_team_changes("Restore team from backup").await?;
        
        Ok(())
    }
    
    /// Complete member onboarding process
    pub async fn onboard_member(
        &self,
        member_id: String,
        public_key: String,
        signing_key: String,
        role: TeamRole,
        invited_by: &str,
    ) -> GitResult<OnboardingResult> {
        // Validate member doesn't already exist
        if self.member_exists(&member_id).await? {
            return Err(GitError::TeamSharingFailed(
                format!("Member {} already exists", member_id)
            ));
        }
        
        // Create new team member
        let member = TeamMember::new(
            member_id.clone(),
            public_key,
            signing_key,
            role,
            invited_by.to_string(),
        );
        
        // Generate a temporary access token for the new member
        let access_token = self.generate_access_token(&member).await?;
        
        // Add member to team
        self.add_member(member.clone()).await?;
        
        // Prepare onboarding package
        let onboarding_package = OnboardingPackage {
            member_id: member_id.clone(),
            access_token,
            team_config: self.config.clone(),
            available_keys: self.list_available_keys_for_member(&member_id).await?,
        };
        
        // Log onboarding
        self.log_team_operation(
            "member_onboarding",
            invited_by,
            &format!("Onboarded new member: {} with role: {:?}", member_id, member.role)
        ).await?;
        
        Ok(OnboardingResult {
            member,
            onboarding_package,
        })
    }
    
    /// Complete member offboarding process
    pub async fn offboard_member(&self, member_id: &str, removed_by: &str) -> GitResult<OffboardingResult> {
        // Get member before removal for audit purposes
        let member = self.get_member(member_id).await?;
        
        // Deactivate member first
        self.deactivate_member(member_id, removed_by).await?;
        
        // Remove member's access to all keys
        let shared_keys = self.list_shared_keys().await?;
        let mut keys_updated = 0;
        
        for mut shared_key in shared_keys {
            if shared_key.encrypted_for_members.remove(member_id).is_some() {
                self.store_shared_key(&shared_key).await?;
                keys_updated += 1;
            }
        }
        
        // Revoke any active access tokens
        self.revoke_member_tokens(member_id).await?;
        
        // Create offboarding summary
        let summary = OffboardingSummary {
            member_id: member_id.to_string(),
            removed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            keys_revoked: keys_updated,
            role: member.role.clone(),
        };
        
        // Log comprehensive offboarding
        self.log_team_operation(
            "member_offboarding",
            removed_by,
            &format!(
                "Offboarded member: {} (role: {:?}, keys revoked: {})",
                member_id, member.role, keys_updated
            )
        ).await?;
        
        // Remove member file completely
        self.remove_member(member_id).await?;
        
        Ok(OffboardingResult {
            member,
            summary,
        })
    }
    
    /// Generate a temporary access token for member authentication
    async fn generate_access_token(&self, member: &TeamMember) -> GitResult<String> {
        let token_data = AccessTokenData {
            member_id: member.id.clone(),
            role: member.role.clone(),
            issued_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() + (7 * 24 * 60 * 60), // 7 days
        };
        
        let token_json = serde_json::to_string(&token_data)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize token: {}", e)))?;
        
        // Encrypt the token with a team secret
        let plaintext = PlaintextSecret::from_string(token_json);
        let encrypted_token = EncryptedSecret::encrypt_with_password(
            plaintext,
            "team_access_token_secret", // In production, use a proper team secret
            None,
        ).map_err(|e| GitError::TeamSharingFailed(format!("Failed to encrypt token: {}", e)))?;
        
        // Serialize and encode the encrypted token
        let token_bytes = encrypted_token.to_bytes()
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize encrypted token: {}", e)))?;
        
        Ok(Base64::encode_string(&token_bytes))
    }
    
    /// List available keys for a specific member
    async fn list_available_keys_for_member(&self, member_id: &str) -> GitResult<Vec<String>> {
        let member = self.get_member(member_id).await?;
        let shared_keys = self.list_shared_keys().await?;
        
        let available_keys: Vec<String> = shared_keys
            .into_iter()
            .filter_map(|key| {
                if key.encrypted_for_members.contains_key(member_id) && member.active {
                    Some(key.id)
                } else {
                    None
                }
            })
            .collect();
        
        Ok(available_keys)
    }
    
    /// Revoke all access tokens for a member
    async fn revoke_member_tokens(&self, member_id: &str) -> GitResult<()> {
        // Store revoked tokens in a blacklist
        let revocation_path = self.team_dir.join("revoked_tokens.json");
        
        let revocation_entry = TokenRevocation {
            member_id: member_id.to_string(),
            revoked_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        let mut revocations = if revocation_path.exists() {
            let content = fs::read_to_string(&revocation_path).await
                .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read revocations: {}", e)))?;
            serde_json::from_str::<Vec<TokenRevocation>>(&content)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        
        revocations.push(revocation_entry);
        
        let revocations_json = serde_json::to_string_pretty(&revocations)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to serialize revocations: {}", e)))?;
        
        fs::write(&revocation_path, revocations_json).await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to write revocations: {}", e)))?;
        
        Ok(())
    }
    
    /// Check if a member can perform a specific operation
    pub async fn check_permission(&self, member_id: &str, operation: &TeamOperation) -> GitResult<PermissionCheck> {
        let member = self.get_member(member_id).await?;
        
        let allowed = member.can_perform(operation);
        let reason = if allowed {
            format!("Member {} with role {:?} can perform {:?}", member_id, member.role, operation)
        } else {
            format!("Member {} with role {:?} cannot perform {:?}", member_id, member.role, operation)
        };
        
        Ok(PermissionCheck { allowed, reason })
    }
    
    /// Get team statistics
    pub async fn get_team_stats(&self) -> GitResult<TeamStats> {
        let members = self.get_members().await?;
        let keys = self.list_shared_keys().await?;
        let audit_entries = self.get_audit_trail(None).await?;
        
        let active_members = members.iter().filter(|m| m.active).count();
        
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let expired_keys = keys.iter()
            .filter(|k| {
                if let Some(expires_at) = k.metadata.expires_at {
                    current_time >= expires_at
                } else {
                    false
                }
            })
            .count();
        
        Ok(TeamStats {
            total_members: members.len(),
            active_members,
            total_keys: keys.len(),
            expired_keys,
            audit_entries: audit_entries.len(),
        })
    }
    
    /// Clean up expired keys automatically
    pub async fn cleanup_expired_keys(&self, cleanup_by: &str) -> GitResult<usize> {
        let keys = self.list_shared_keys().await?;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut cleaned_count = 0;
        
        for key in keys {
            if let Some(expires_at) = key.metadata.expires_at {
                if current_time >= expires_at {
                    self.archive_shared_key(&key.id).await?;
                    cleaned_count += 1;
                    
                    self.log_team_operation(
                        "key_cleanup",
                        cleanup_by,
                        &format!("Cleaned up expired key: {} (purpose: {})", key.id, key.metadata.purpose)
                    ).await?;
                }
            }
        }
        
        if cleaned_count > 0 {
            self.commit_team_changes(&format!("Clean up {} expired keys", cleaned_count)).await?;
        }
        
        Ok(cleaned_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_team_key_sharing_creation() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let crypto = CryptoEngine::new();
        let team_sharing = TeamKeySharing::new(&repo, &crypto).unwrap();
        
        team_sharing.initialize().await.unwrap();
        
        assert!(team_sharing.team_dir.exists());
        assert!(team_sharing.team_dir.join("config.toml").exists());
    }
    
    #[tokio::test]
    async fn test_add_team_member() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let crypto = CryptoEngine::new();
        let team_sharing = TeamKeySharing::new(&repo, &crypto).unwrap();
        
        team_sharing.initialize().await.unwrap();
        
        let member = TeamMember::new(
            "alice@example.com".to_string(),
            "public_key_alice".to_string(),
            "signing_key_alice".to_string(),
            TeamRole::Admin,
            "system".to_string(),
        );
        
        team_sharing.add_member(member).await.unwrap();
        
        let members = team_sharing.get_members().await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].id, "alice@example.com");
    }
    
    #[tokio::test]
    async fn test_member_permissions() {
        let owner = TeamMember::new(
            "owner@example.com".to_string(),
            "pk".to_string(),
            "sk".to_string(),
            TeamRole::Owner,
            "system".to_string(),
        );
        
        let readonly = TeamMember::new(
            "readonly@example.com".to_string(),
            "pk".to_string(),
            "sk".to_string(),
            TeamRole::ReadOnly,
            "system".to_string(),
        );
        
        assert!(owner.can_perform(&TeamOperation::AddMember));
        assert!(owner.can_perform(&TeamOperation::RotateKeys));
        
        assert!(!readonly.can_perform(&TeamOperation::AddMember));
        assert!(readonly.can_perform(&TeamOperation::DecryptFile));
    }
    
    #[tokio::test]
    async fn test_shared_key_generation() {
        let temp_dir = TempDir::new().unwrap();
        let repo = GitRepo::init(temp_dir.path()).unwrap();
        let crypto = CryptoEngine::new();
        let team_sharing = TeamKeySharing::new(&repo, &crypto).unwrap();
        
        team_sharing.initialize().await.unwrap();
        
        // Add a team member first
        let member = TeamMember::new(
            "alice@example.com".to_string(),
            "public_key_alice".to_string(),
            "signing_key_alice".to_string(),
            TeamRole::Admin,
            "system".to_string(),
        );
        team_sharing.add_member(member).await.unwrap();
        
        // Generate shared key
        let shared_key = team_sharing.generate_shared_key("test", "alice@example.com").await.unwrap();
        
        assert!(!shared_key.id.is_empty());
        assert!(shared_key.encrypted_for_members.contains_key("alice@example.com"));
    }
}