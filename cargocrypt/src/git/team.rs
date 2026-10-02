//! Team key sharing for CargoCrypt
//!
//! Shared keys are stored in the repository, wrapped separately for each
//! member with that member's X25519 public key
//! ([`crate::crypto::envelope`]). Reading a key requires the member's secret
//! key, which never enters the repository.
//!
//! # What this does and does not give you
//!
//! - **Confidentiality against repository readers.** Someone with a clone but
//!   no member secret key cannot recover a shared key.
//! - **Granting is explicit.** Adding a member records their public key; it
//!   does not hand them existing keys. An existing holder grants each key
//!   with [`TeamKeySharing::grant_key`], which needs that holder's secret.
//! - **Removal is not revocation.** Deleting a member's wrapped copy does not
//!   make them forget a key they already read. Rotate the key and re-encrypt
//!   what it protected.
//! - **No authentication of the member list yet.** Member files, roles and
//!   the audit log are plain JSON in the working tree: anyone who can push
//!   can add a member or edit a role. Entries are not signed, so treat
//!   repository write access as equivalent to team administration.

use super::{GitError, GitRepo, GitResult};
use crate::crypto::envelope::{self, RecipientPublicKey, RecipientSecretKey};
use crate::crypto::{CryptoEngine, DerivedKey};
use base64ct::{Base64, Encoding};
use git2::Signature;
use ring::rand::SystemRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;

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
    /// Member's X25519 public key, hex encoded: what shared keys are sealed
    /// to. Generate a pair with [`RecipientSecretKey::generate`].
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
    pub fn new(
        id: String,
        public_key: String,
        signing_key: String,
        role: TeamRole,
        added_by: String,
    ) -> Self {
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
            TeamRole::Admin => matches!(
                operation,
                TeamOperation::AddMember
                    | TeamOperation::RemoveMember
                    | TeamOperation::RotateKeys
                    | TeamOperation::ViewKeys
                    | TeamOperation::EncryptFile
                    | TeamOperation::DecryptFile
            ),
            TeamRole::Member => matches!(
                operation,
                TeamOperation::ViewKeys | TeamOperation::EncryptFile | TeamOperation::DecryptFile
            ),
            TeamRole::ReadOnly => matches!(
                operation,
                TeamOperation::ViewKeys | TeamOperation::DecryptFile
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
    /// Reserved. Always empty: keys are not signed yet. (An earlier version
    /// filled this with an HMAC under a constant, which anyone could forge.)
    #[serde(default)]
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
    /// Reserved. Always empty. (An earlier version issued a "token"
    /// encrypted under a constant; possession of a member secret key is the
    /// only credential.)
    #[serde(default)]
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
    pub fn with_config(
        repo: &GitRepo,
        crypto: &CryptoEngine,
        config: KeyShareConfig,
    ) -> GitResult<Self> {
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
        fs::create_dir_all(&self.team_dir).await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to create team directory: {}", e))
        })?;

        fs::create_dir_all(self.team_dir.join("members"))
            .await
            .map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to create members directory: {}", e))
            })?;

        fs::create_dir_all(self.team_dir.join("keys"))
            .await
            .map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to create keys directory: {}", e))
            })?;

        // Create initial team configuration
        let team_config_path = self.team_dir.join("config.toml");
        let config_content = toml::to_string(&self.config).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to serialize team config: {}", e))
        })?;

        fs::write(&team_config_path, config_content)
            .await
            .map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to write team config: {}", e))
            })?;

        // Initialize git ref for team data
        self.init_team_ref().await?;

        Ok(())
    }

    /// Add a team member
    pub async fn add_member(&self, member: TeamMember) -> GitResult<()> {
        // Validate member
        if self.get_members().await?.len() >= self.config.max_members {
            return Err(GitError::TeamSharingFailed(
                "Maximum team size reached".to_string(),
            ));
        }

        // Check for duplicate IDs
        if self.member_exists(&member.id).await? {
            return Err(GitError::TeamSharingFailed(format!(
                "Member {} already exists",
                member.id
            )));
        }

        // A member who cannot receive keys is a misconfiguration, not a
        // member: reject a malformed public key now rather than at first use.
        RecipientPublicKey::from_hex(&member.public_key).map_err(|e| {
            GitError::TeamSharingFailed(format!(
                "Member {} has no usable public key: {}",
                member.id, e
            ))
        })?;

        // Store member information
        let member_path = self
            .team_dir
            .join("members")
            .join(format!("{}.json", member.id));
        let member_json = serde_json::to_string_pretty(&member).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to serialize member: {}", e))
        })?;

        fs::write(&member_path, member_json).await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to write member file: {}", e))
        })?;

        // Existing keys are not handed over here: wrapping one for a new
        // member means unwrapping it first, which takes a current holder's
        // secret key. See `grant_key`.

        // Commit changes to git
        self.commit_team_changes(&format!("Add team member: {}", member.id))
            .await?;

        Ok(())
    }

    /// Remove a team member
    pub async fn remove_member(&self, member_id: &str) -> GitResult<()> {
        let member_path = self
            .team_dir
            .join("members")
            .join(format!("{}.json", member_id));

        if !member_path.exists() {
            return Err(GitError::TeamSharingFailed(format!(
                "Member {} not found",
                member_id
            )));
        }

        // Remove member file
        fs::remove_file(&member_path).await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to remove member file: {}", e))
        })?;

        // Re-encrypt keys without this member
        self.reencrypt_keys_without_member(member_id).await?;

        // Commit changes to git
        self.commit_team_changes(&format!("Remove team member: {}", member_id))
            .await?;

        Ok(())
    }

    /// Get all team members
    pub async fn get_members(&self) -> GitResult<Vec<TeamMember>> {
        let mut members = Vec::new();
        let members_dir = self.team_dir.join("members");

        if !members_dir.exists() {
            return Ok(members);
        }

        let mut entries = fs::read_dir(&members_dir).await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to read members directory: {}", e))
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to read directory entry: {}", e))
        })? {
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                let member_content = fs::read_to_string(entry.path()).await.map_err(|e| {
                    GitError::TeamSharingFailed(format!("Failed to read member file: {}", e))
                })?;

                let member: TeamMember = serde_json::from_str(&member_content).map_err(|e| {
                    GitError::TeamSharingFailed(format!("Failed to parse member file: {}", e))
                })?;

                members.push(member);
            }
        }

        Ok(members)
    }

    /// Check if a member exists
    pub async fn member_exists(&self, member_id: &str) -> GitResult<bool> {
        let member_path = self
            .team_dir
            .join("members")
            .join(format!("{}.json", member_id));
        Ok(member_path.exists())
    }

    /// Generate a new shared key
    pub async fn generate_shared_key(
        &self,
        purpose: &str,
        created_by: &str,
    ) -> GitResult<SharedKey> {
        let members = self.get_members().await?;

        if members.is_empty() {
            return Err(GitError::TeamSharingFailed(
                "No team members found".to_string(),
            ));
        }

        // Generate a new random key for symmetric encryption
        let key_material = self
            .crypto
            .generate_key()
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to generate key: {}", e)))?;

        // Seal the key to each active member's public key
        let key_id = self.generate_key_id();
        let mut encrypted_for_members = HashMap::new();

        for member in &members {
            if member.active {
                let encrypted_key = self.encrypt_key_for_member(&key_material, member, &key_id)?;
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
                    .as_secs()
                    + (self.config.rotation_interval * 24 * 60 * 60),
            ),
        };

        // Create shared key
        let shared_key = SharedKey {
            id: key_id,
            encrypted_for_members,
            metadata,
            signature: String::new(),
        };

        // Store the shared key
        self.store_shared_key(&shared_key).await?;

        // Log audit trail
        self.log_team_operation(
            "key_generation",
            created_by,
            &format!("Generated key {} for purpose: {}", shared_key.id, purpose),
        )
        .await?;

        Ok(shared_key)
    }

    /// Get a shared key for a specific member
    ///
    /// `secret` is the member's own secret key; the wrapped copy in the
    /// repository cannot be opened without it.
    pub async fn get_shared_key(
        &self,
        key_id: &str,
        member_id: &str,
        secret: &RecipientSecretKey,
    ) -> GitResult<DerivedKey> {
        let shared_key = self.load_shared_key(key_id).await?;

        // Check if member has access to this key
        let encrypted_key = shared_key
            .encrypted_for_members
            .get(member_id)
            .ok_or_else(|| {
                GitError::TeamSharingFailed(format!(
                    "Member {} does not have access to key {}",
                    member_id, key_id
                ))
            })?;

        self.decrypt_key_for_member(encrypted_key, member_id, key_id, secret)
    }

    /// Give `recipient_id` access to an existing key.
    ///
    /// `granter_id` must already hold the key and proves it by supplying
    /// their secret key, which unwraps the key so it can be sealed again to
    /// the recipient's public key.
    pub async fn grant_key(
        &self,
        key_id: &str,
        granter_id: &str,
        granter_secret: &RecipientSecretKey,
        recipient_id: &str,
    ) -> GitResult<()> {
        let granter = self.get_member(granter_id).await?;
        if !granter.active || !granter.can_perform(&TeamOperation::AddMember) {
            return Err(GitError::TeamSharingFailed(format!(
                "Member {} may not grant keys",
                granter_id
            )));
        }
        let recipient = self.get_member(recipient_id).await?;
        if !recipient.active {
            return Err(GitError::TeamSharingFailed(format!(
                "Member {} is not active",
                recipient_id
            )));
        }

        let key_material = self
            .get_shared_key(key_id, granter_id, granter_secret)
            .await?;
        let sealed = self.encrypt_key_for_member(&key_material, &recipient, key_id)?;

        let mut shared_key = self.load_shared_key(key_id).await?;
        shared_key
            .encrypted_for_members
            .insert(recipient.id.clone(), sealed);
        self.store_shared_key(&shared_key).await?;

        self.log_team_operation(
            "key_grant",
            granter_id,
            &format!("Granted key {} to {}", key_id, recipient_id),
        )
        .await?;
        self.commit_team_changes(&format!("Grant key {} to {}", key_id, recipient_id))
            .await
    }

    /// Rotate all team keys
    pub async fn rotate_keys(&self) -> GitResult<()> {
        let shared_keys = self.list_shared_keys().await?;

        for key in shared_keys {
            // Generate new key with same purpose
            let _new_key = self
                .generate_shared_key(&key.metadata.purpose, "system")
                .await?;

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
        let new_key = self
            .generate_shared_key(&old_key.metadata.purpose, rotated_by)
            .await?;

        // Archive old key
        self.archive_shared_key(key_id).await?;

        // Log the rotation
        self.log_team_operation(
            "single_key_rotation",
            rotated_by,
            &format!(
                "Rotated key {} -> {} (purpose: {})",
                old_key.id, new_key.id, old_key.metadata.purpose
            ),
        )
        .await?;

        // Commit changes
        self.commit_team_changes(&format!("Rotate key: {}", key_id))
            .await?;

        Ok(new_key)
    }

    /// Get member information
    async fn get_member(&self, member_id: &str) -> GitResult<TeamMember> {
        let member_path = self
            .team_dir
            .join("members")
            .join(format!("{}.json", member_id));

        if !member_path.exists() {
            return Err(GitError::TeamSharingFailed(format!(
                "Member {} not found",
                member_id
            )));
        }

        let member_content = fs::read_to_string(&member_path).await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to read member file: {}", e))
        })?;

        let member: TeamMember = serde_json::from_str(&member_content).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to parse member file: {}", e))
        })?;

        Ok(member)
    }

    /// Store a shared key
    async fn store_shared_key(&self, shared_key: &SharedKey) -> GitResult<()> {
        let key_path = self
            .team_dir
            .join("keys")
            .join(format!("{}.json", shared_key.id));
        let key_json = serde_json::to_string_pretty(shared_key).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to serialize shared key: {}", e))
        })?;

        fs::write(&key_path, key_json).await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to write shared key: {}", e))
        })?;

        Ok(())
    }

    /// Load a shared key
    async fn load_shared_key(&self, key_id: &str) -> GitResult<SharedKey> {
        let key_path = self.team_dir.join("keys").join(format!("{}.json", key_id));

        if !key_path.exists() {
            return Err(GitError::TeamSharingFailed(format!(
                "Shared key {} not found",
                key_id
            )));
        }

        let key_content = fs::read_to_string(&key_path).await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to read shared key: {}", e))
        })?;

        let shared_key: SharedKey = serde_json::from_str(&key_content).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to parse shared key: {}", e))
        })?;

        Ok(shared_key)
    }

    /// List all shared keys
    async fn list_shared_keys(&self) -> GitResult<Vec<SharedKey>> {
        let mut keys = Vec::new();
        let keys_dir = self.team_dir.join("keys");

        if !keys_dir.exists() {
            return Ok(keys);
        }

        let mut entries = fs::read_dir(&keys_dir).await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to read keys directory: {}", e))
        })?;

        while let Some(entry) = entries.next_entry().await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to read directory entry: {}", e))
        })? {
            if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
                let key_content = fs::read_to_string(entry.path()).await.map_err(|e| {
                    GitError::TeamSharingFailed(format!("Failed to read key file: {}", e))
                })?;

                let shared_key: SharedKey = serde_json::from_str(&key_content).map_err(|e| {
                    GitError::TeamSharingFailed(format!("Failed to parse key file: {}", e))
                })?;

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

    /// Associated data binding a wrapped key to its key id and its member.
    fn envelope_context(key_id: &str, member_id: &str) -> Vec<u8> {
        let mut context = Vec::with_capacity(key_id.len() + member_id.len() + 1);
        context.extend_from_slice(key_id.as_bytes());
        context.push(0);
        context.extend_from_slice(member_id.as_bytes());
        context
    }

    /// Seal a key to one member's public key.
    fn encrypt_key_for_member(
        &self,
        key: &DerivedKey,
        member: &TeamMember,
        key_id: &str,
    ) -> GitResult<String> {
        let recipient = RecipientPublicKey::from_hex(&member.public_key).map_err(|e| {
            GitError::TeamSharingFailed(format!(
                "Member {} has no usable public key: {}",
                member.id, e
            ))
        })?;
        let material = zeroize::Zeroizing::new(key.to_hex());
        let sealed = envelope::seal(
            material.as_bytes(),
            &recipient,
            &Self::envelope_context(key_id, &member.id),
        )
        .map_err(|e| GitError::TeamSharingFailed(format!("Failed to seal key: {}", e)))?;

        Ok(Base64::encode_string(&sealed))
    }

    /// Open a member's wrapped copy of a key with that member's secret key.
    fn decrypt_key_for_member(
        &self,
        encrypted_key: &str,
        member_id: &str,
        key_id: &str,
        secret: &RecipientSecretKey,
    ) -> GitResult<DerivedKey> {
        let sealed = Base64::decode_vec(encrypted_key).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to decode wrapped key: {}", e))
        })?;
        let material = envelope::open(&sealed, secret, &Self::envelope_context(key_id, member_id))
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to open key: {}", e)))?;
        let key_hex = std::str::from_utf8(&material)
            .map_err(|e| GitError::TeamSharingFailed(format!("Wrapped key is not valid: {}", e)))?;

        DerivedKey::from_hex(key_hex).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to create derived key: {}", e))
        })
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
        let archived_path = self
            .team_dir
            .join("keys")
            .join("archived")
            .join(format!("{}.json", key_id));

        // Create archived directory if it doesn't exist
        fs::create_dir_all(archived_path.parent().unwrap())
            .await
            .map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to create archived directory: {}", e))
            })?;

        // Move key to archived location
        fs::rename(&key_path, &archived_path)
            .await
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
        // Stage all team files. `self.team_dir` is a directory
        // (`.cargocrypt/team`), so this must walk it rather than treat it as
        // a single file to blob directly (see `stage_all_under`).
        self.repo.stage_all_under(&self.team_dir).await?;

        // Create commit
        self.repo
            .commit(&format!("CargoCrypt: {}", message))
            .await?;

        Ok(())
    }

    /// Get git signature
    fn get_signature(&self) -> GitResult<Signature<'_>> {
        self.repo
            .inner()
            .signature()
            .or_else(|_| Signature::now("CargoCrypt Team", "team@cargocrypt.local"))
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to create signature: {}", e)))
    }

    /// Log team operations for audit trail
    async fn log_team_operation(
        &self,
        operation: &str,
        actor: &str,
        details: &str,
    ) -> GitResult<()> {
        let audit_log_path = self.team_dir.join("audit.log");

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let log_entry = format!("{} | {} | {} | {}\n", timestamp, operation, actor, details);

        // Append to audit log
        if audit_log_path.exists() {
            let mut existing_content = fs::read_to_string(&audit_log_path).await.map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to read audit log: {}", e))
            })?;
            existing_content.push_str(&log_entry);
            fs::write(&audit_log_path, existing_content)
                .await
                .map_err(|e| {
                    GitError::TeamSharingFailed(format!("Failed to update audit log: {}", e))
                })?;
        } else {
            fs::write(&audit_log_path, log_entry).await.map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to create audit log: {}", e))
            })?;
        }

        Ok(())
    }

    /// Get audit trail for team operations
    pub async fn get_audit_trail(&self, limit: Option<usize>) -> GitResult<Vec<AuditEntry>> {
        let audit_log_path = self.team_dir.join("audit.log");

        if !audit_log_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&audit_log_path)
            .await
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
        entries.sort_by_key(|e| std::cmp::Reverse(e.timestamp));

        if let Some(limit) = limit {
            entries.truncate(limit);
        }

        Ok(entries)
    }

    /// Deactivate a team member (soft delete)
    pub async fn deactivate_member(&self, member_id: &str, deactivated_by: &str) -> GitResult<()> {
        let member_path = self
            .team_dir
            .join("members")
            .join(format!("{}.json", member_id));

        if !member_path.exists() {
            return Err(GitError::TeamSharingFailed(format!(
                "Member {} not found",
                member_id
            )));
        }

        // Load member
        let mut member = self.get_member(member_id).await?;

        // Deactivate the member
        member.active = false;

        // Save updated member
        let member_json = serde_json::to_string_pretty(&member).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to serialize member: {}", e))
        })?;

        fs::write(&member_path, member_json).await.map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to write member file: {}", e))
        })?;

        // Log the deactivation
        self.log_team_operation(
            "member_deactivation",
            deactivated_by,
            &format!("Deactivated member: {}", member_id),
        )
        .await?;

        // Commit changes
        self.commit_team_changes(&format!("Deactivate team member: {}", member_id))
            .await?;

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

        let backup_json = serde_json::to_string_pretty(&backup_data).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to serialize backup: {}", e))
        })?;

        fs::write(backup_path, backup_json)
            .await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to write backup: {}", e)))?;

        // Log the backup operation
        self.log_team_operation(
            "team_backup",
            "system",
            &format!("Created team backup at: {}", backup_path.display()),
        )
        .await?;

        Ok(())
    }

    /// Restore team keys from backup
    pub async fn restore_from_backup(&self, backup_path: &std::path::Path) -> GitResult<()> {
        let backup_content = fs::read_to_string(backup_path)
            .await
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to read backup: {}", e)))?;

        let backup_data: TeamBackup = serde_json::from_str(&backup_content)
            .map_err(|e| GitError::TeamSharingFailed(format!("Failed to parse backup: {}", e)))?;

        // Restore members
        for member in backup_data.members {
            let member_path = self
                .team_dir
                .join("members")
                .join(format!("{}.json", member.id));
            let member_json = serde_json::to_string_pretty(&member).map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to serialize member: {}", e))
            })?;

            fs::write(&member_path, member_json).await.map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to restore member: {}", e))
            })?;
        }

        // Restore keys
        for key in backup_data.keys {
            self.store_shared_key(&key).await?;
        }

        // Log the restore operation
        self.log_team_operation(
            "team_restore",
            "system",
            &format!("Restored team from backup: {}", backup_path.display()),
        )
        .await?;

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
            return Err(GitError::TeamSharingFailed(format!(
                "Member {} already exists",
                member_id
            )));
        }

        // Create new team member
        let member = TeamMember::new(
            member_id.clone(),
            public_key,
            signing_key,
            role,
            invited_by.to_string(),
        );

        // Add member to team
        self.add_member(member.clone()).await?;

        // Prepare onboarding package
        let onboarding_package = OnboardingPackage {
            member_id: member_id.clone(),
            access_token: String::new(),
            team_config: self.config.clone(),
            available_keys: self.list_available_keys_for_member(&member_id).await?,
        };

        // Log onboarding
        self.log_team_operation(
            "member_onboarding",
            invited_by,
            &format!(
                "Onboarded new member: {} with role: {:?}",
                member_id, member.role
            ),
        )
        .await?;

        Ok(OnboardingResult {
            member,
            onboarding_package,
        })
    }

    /// Complete member offboarding process
    pub async fn offboard_member(
        &self,
        member_id: &str,
        removed_by: &str,
    ) -> GitResult<OffboardingResult> {
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
            ),
        )
        .await?;

        // Remove member file completely
        self.remove_member(member_id).await?;

        Ok(OffboardingResult { member, summary })
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
            let content = fs::read_to_string(&revocation_path).await.map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to read revocations: {}", e))
            })?;
            serde_json::from_str::<Vec<TokenRevocation>>(&content).unwrap_or_default()
        } else {
            Vec::new()
        };

        revocations.push(revocation_entry);

        let revocations_json = serde_json::to_string_pretty(&revocations).map_err(|e| {
            GitError::TeamSharingFailed(format!("Failed to serialize revocations: {}", e))
        })?;

        fs::write(&revocation_path, revocations_json)
            .await
            .map_err(|e| {
                GitError::TeamSharingFailed(format!("Failed to write revocations: {}", e))
            })?;

        Ok(())
    }

    /// Check if a member can perform a specific operation
    pub async fn check_permission(
        &self,
        member_id: &str,
        operation: &TeamOperation,
    ) -> GitResult<PermissionCheck> {
        let member = self.get_member(member_id).await?;

        let allowed = member.can_perform(operation);
        let reason = if allowed {
            format!(
                "Member {} with role {:?} can perform {:?}",
                member_id, member.role, operation
            )
        } else {
            format!(
                "Member {} with role {:?} cannot perform {:?}",
                member_id, member.role, operation
            )
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

        let expired_keys = keys
            .iter()
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
                        &format!(
                            "Cleaned up expired key: {} (purpose: {})",
                            key.id, key.metadata.purpose
                        ),
                    )
                    .await?;
                }
            }
        }

        if cleaned_count > 0 {
            self.commit_team_changes(&format!("Clean up {} expired keys", cleaned_count))
                .await?;
        }

        Ok(cleaned_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        team: TeamKeySharing,
    }

    async fn fixture() -> Fixture {
        let dir = TempDir::new().unwrap();
        let repo = GitRepo::init(dir.path()).unwrap();
        let crypto = CryptoEngine::new();
        let team = TeamKeySharing::new(&repo, &crypto).unwrap();
        team.initialize().await.unwrap();
        Fixture { _dir: dir, team }
    }

    fn member(id: &str, role: TeamRole) -> (TeamMember, RecipientSecretKey) {
        let secret = RecipientSecretKey::generate().unwrap();
        let member = TeamMember::new(
            id.to_string(),
            secret.public_key().to_hex(),
            String::new(),
            role,
            "system".to_string(),
        );
        (member, secret)
    }

    #[tokio::test]
    async fn test_team_key_sharing_creation() {
        let f = fixture().await;
        assert!(f.team.team_dir.exists());
        assert!(f.team.team_dir.join("config.toml").exists());
    }

    #[tokio::test]
    async fn test_add_team_member() {
        let f = fixture().await;
        let (alice, _) = member("alice@example.com", TeamRole::Admin);
        f.team.add_member(alice).await.unwrap();

        let members = f.team.get_members().await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].id, "alice@example.com");
    }

    #[tokio::test]
    async fn test_member_without_a_real_public_key_is_rejected() {
        let f = fixture().await;
        let bogus = TeamMember::new(
            "mallory@example.com".to_string(),
            "public_key_mallory".to_string(),
            String::new(),
            TeamRole::Member,
            "system".to_string(),
        );
        assert!(f.team.add_member(bogus).await.is_err());
        assert!(f.team.get_members().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_member_permissions() {
        let (owner, _) = member("owner@example.com", TeamRole::Owner);
        let (readonly, _) = member("readonly@example.com", TeamRole::ReadOnly);

        assert!(owner.can_perform(&TeamOperation::AddMember));
        assert!(owner.can_perform(&TeamOperation::RotateKeys));

        assert!(!readonly.can_perform(&TeamOperation::AddMember));
        assert!(readonly.can_perform(&TeamOperation::DecryptFile));
    }

    #[tokio::test]
    async fn test_shared_key_opens_only_with_the_members_secret() {
        let f = fixture().await;
        let (alice, alice_secret) = member("alice@example.com", TeamRole::Admin);
        let (bob, bob_secret) = member("bob@example.com", TeamRole::Member);
        f.team.add_member(alice).await.unwrap();
        f.team.add_member(bob).await.unwrap();

        let shared = f
            .team
            .generate_shared_key("test", "alice@example.com")
            .await
            .unwrap();
        assert!(shared.signature.is_empty());
        assert_eq!(shared.encrypted_for_members.len(), 2);

        let for_alice = f
            .team
            .get_shared_key(&shared.id, "alice@example.com", &alice_secret)
            .await
            .unwrap();
        let for_bob = f
            .team
            .get_shared_key(&shared.id, "bob@example.com", &bob_secret)
            .await
            .unwrap();
        assert_eq!(for_alice.key().as_slice(), for_bob.key().as_slice());

        // Bob's secret does not open Alice's copy, and an outsider's opens nothing.
        assert!(f
            .team
            .get_shared_key(&shared.id, "alice@example.com", &bob_secret)
            .await
            .is_err());
        let outsider = RecipientSecretKey::generate().unwrap();
        assert!(f
            .team
            .get_shared_key(&shared.id, "bob@example.com", &outsider)
            .await
            .is_err());
    }

    /// The wrapped copies used to be encrypted under the constant
    /// "team_key_password": anyone with a clone could read every team key.
    #[tokio::test]
    async fn test_wrapped_keys_do_not_open_with_the_old_constant_password() {
        let f = fixture().await;
        let (alice, _) = member("alice@example.com", TeamRole::Admin);
        f.team.add_member(alice).await.unwrap();
        let shared = f
            .team
            .generate_shared_key("test", "alice@example.com")
            .await
            .unwrap();

        let blob = Base64::decode_vec(&shared.encrypted_for_members["alice@example.com"]).unwrap();
        let opened = crate::crypto::EncryptedSecret::from_bytes(&blob)
            .and_then(|secret| secret.decrypt_with_password("team_key_password"));
        assert!(opened.is_err());
    }

    #[tokio::test]
    async fn test_new_member_needs_an_explicit_grant() {
        let f = fixture().await;
        let (alice, alice_secret) = member("alice@example.com", TeamRole::Admin);
        f.team.add_member(alice).await.unwrap();
        let shared = f
            .team
            .generate_shared_key("test", "alice@example.com")
            .await
            .unwrap();

        // Carol joins after the key exists: she gets nothing automatically.
        let (carol, carol_secret) = member("carol@example.com", TeamRole::Member);
        f.team.add_member(carol).await.unwrap();
        assert!(f
            .team
            .get_shared_key(&shared.id, "carol@example.com", &carol_secret)
            .await
            .is_err());

        // A grant needs a holder's secret; Carol cannot grant to herself.
        assert!(f
            .team
            .grant_key(
                &shared.id,
                "carol@example.com",
                &carol_secret,
                "carol@example.com"
            )
            .await
            .is_err());
        // Nor can someone claiming to be Alice without her secret.
        assert!(f
            .team
            .grant_key(
                &shared.id,
                "alice@example.com",
                &carol_secret,
                "carol@example.com"
            )
            .await
            .is_err());

        f.team
            .grant_key(
                &shared.id,
                "alice@example.com",
                &alice_secret,
                "carol@example.com",
            )
            .await
            .unwrap();
        let for_carol = f
            .team
            .get_shared_key(&shared.id, "carol@example.com", &carol_secret)
            .await
            .unwrap();
        let for_alice = f
            .team
            .get_shared_key(&shared.id, "alice@example.com", &alice_secret)
            .await
            .unwrap();
        assert_eq!(for_carol.key().as_slice(), for_alice.key().as_slice());
    }

    #[tokio::test]
    async fn test_wrapped_copy_is_bound_to_its_key_and_member() {
        let f = fixture().await;
        let (alice, alice_secret) = member("alice@example.com", TeamRole::Admin);
        f.team.add_member(alice).await.unwrap();
        let first = f
            .team
            .generate_shared_key("first", "alice@example.com")
            .await
            .unwrap();
        let mut second = f
            .team
            .generate_shared_key("second", "alice@example.com")
            .await
            .unwrap();

        // Splice the first key's wrapped copy into the second key's record.
        second.encrypted_for_members.insert(
            "alice@example.com".to_string(),
            first.encrypted_for_members["alice@example.com"].clone(),
        );
        f.team.store_shared_key(&second).await.unwrap();
        assert!(f
            .team
            .get_shared_key(&second.id, "alice@example.com", &alice_secret)
            .await
            .is_err());
    }
}
