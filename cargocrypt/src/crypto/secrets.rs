//! Encrypted secret storage with automatic zeroization

use crate::crypto::{defaults, CryptoError, CryptoResult, DerivedKey, KdfParams};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::ZeroizeOnDrop;

/// Magic bytes that open every container from format version 2 onwards.
pub const CONTAINER_MAGIC: [u8; 4] = *b"CCRY";

/// Container format written by this version of CargoCrypt.
pub const CONTAINER_VERSION: u8 = 2;

/// Algorithm identifiers stored in the container header.
const ALG_CHACHA20_POLY1305: u8 = 1;
const KDF_ARGON2ID_V13: u8 = 1;

/// Largest metadata block accepted when parsing a container.
const MAX_METADATA_LEN: usize = 64 * 1024;

const fn legacy_version() -> u8 {
    1
}

/// An encrypted secret.
///
/// # Container format (version 2)
///
/// ```text
/// offset  size  field
///      0     4  magic "CCRY"
///      4     1  format version (2)
///      5     1  AEAD id   (1 = ChaCha20-Poly1305)
///      6     1  KDF id    (1 = Argon2id v1.3)
///      7     4  Argon2 memory cost, KiB, little endian
///     11     4  Argon2 passes, little endian
///     15     4  Argon2 lanes, little endian
///     19    32  salt
///     51    12  nonce
///     63     4  metadata length N, little endian
///     67     N  metadata, JSON
///   67+N     …  ciphertext and 16-byte tag
/// ```
///
/// Everything before the ciphertext is passed to the AEAD as associated data,
/// so the header and metadata cannot be altered without failing
/// authentication.
///
/// Version 1 was a bare `bincode` struct with no magic, no version and
/// unauthenticated metadata, always derived with [`KdfParams::V1`]. It is
/// still read, never written.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    /// Encrypted data
    ciphertext: Vec<u8>,
    /// Nonce used for encryption
    nonce: [u8; defaults::NONCE_LENGTH],
    /// Salt used for key derivation
    salt: [u8; defaults::SALT_LENGTH],
    /// Metadata. Not encrypted; authenticated from format version 2.
    #[serde(default)]
    metadata: SecretMetadata,
    /// Container format version
    #[serde(default = "legacy_version")]
    version: u8,
    /// Key derivation cost parameters
    #[serde(default)]
    kdf: KdfParams,
}

/// On-disk layout of a version 1 container.
#[derive(Serialize, Deserialize)]
struct LegacyV1 {
    ciphertext: Vec<u8>,
    nonce: [u8; defaults::NONCE_LENGTH],
    salt: [u8; defaults::SALT_LENGTH],
    metadata: SecretMetadata,
}

/// Metadata associated with an encrypted secret
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Human-readable description
    pub description: Option<String>,
    /// Creation timestamp (Unix timestamp)
    pub created_at: Option<u64>,
    /// Tags for organization
    pub tags: Vec<String>,
    /// Secret type hint
    pub secret_type: Option<SecretType>,
}

/// Types of secrets that can be stored
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SecretType {
    /// Generic secret data
    Generic,
    /// API key or token
    ApiKey,
    /// Password
    Password,
    /// Private key (cryptographic)
    PrivateKey,
    /// Database connection string
    DatabaseUrl,
    /// Configuration data
    Config,
    /// Custom type
    Custom(String),
}

impl fmt::Display for SecretType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretType::Generic => write!(f, "generic"),
            SecretType::ApiKey => write!(f, "api_key"),
            SecretType::Password => write!(f, "password"),
            SecretType::PrivateKey => write!(f, "private_key"),
            SecretType::DatabaseUrl => write!(f, "database_url"),
            SecretType::Config => write!(f, "config"),
            SecretType::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// Plaintext secret data with automatic zeroization
#[derive(Clone, ZeroizeOnDrop)]
pub struct PlaintextSecret {
    /// The secret data
    data: Vec<u8>,
}

impl PlaintextSecret {
    /// Create a new plaintext secret from bytes
    pub fn from_bytes(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new plaintext secret from bytes
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a new plaintext secret from a string
    pub fn from_string(data: String) -> Self {
        Self {
            data: data.into_bytes(),
        }
    }

    /// Get the secret data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the secret data as a string (if valid UTF-8)
    pub fn as_string(&self) -> CryptoResult<&str> {
        std::str::from_utf8(&self.data)
            .map_err(|e| CryptoError::invalid_input(format!("Invalid UTF-8: {}", e)))
    }

    /// Convert to owned string (if valid UTF-8)
    pub fn into_string(self) -> CryptoResult<String> {
        String::from_utf8(self.data.clone())
            .map_err(|e| CryptoError::invalid_input(format!("Invalid UTF-8: {}", e.utf8_error())))
    }

    /// Get the length of the secret data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the secret is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for PlaintextSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaintextSecret")
            .field("data", &format!("[{} bytes, REDACTED]", self.data.len()))
            .finish()
    }
}

impl EncryptedSecret {
    /// Encrypt a plaintext secret with a password
    pub fn encrypt_with_password(
        plaintext: PlaintextSecret,
        password: &str,
        metadata: Option<SecretMetadata>,
    ) -> CryptoResult<Self> {
        let key = DerivedKey::from_password_with_random_salt(password)?;
        Self::encrypt_with_key(plaintext, &key, metadata)
    }

    /// Encrypt a plaintext secret with a derived key
    pub fn encrypt_with_key(
        plaintext: PlaintextSecret,
        key: &DerivedKey,
        metadata: Option<SecretMetadata>,
    ) -> CryptoResult<Self> {
        let nonce_bytes = crate::crypto::keys::SecureRandom::generate_nonce()?;
        let kdf = key.kdf_params();
        kdf.validate()?;

        let mut secret = Self {
            ciphertext: Vec::new(),
            nonce: nonce_bytes,
            salt: *key.salt(),
            metadata: metadata.unwrap_or_default(),
            version: CONTAINER_VERSION,
            kdf,
        };

        let header = secret.header_bytes()?;
        let cipher = ChaCha20Poly1305::new(key.key());
        secret.ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &header,
                },
            )
            .map_err(CryptoError::from)?;

        Ok(secret)
    }

    /// Decrypt the secret with a password
    pub fn decrypt_with_password(&self, password: &str) -> CryptoResult<PlaintextSecret> {
        let key = DerivedKey::derive(password, &self.salt, self.kdf)?;
        self.decrypt_with_key(&key)
    }

    /// Decrypt the secret with a derived key
    pub fn decrypt_with_key(&self, key: &DerivedKey) -> CryptoResult<PlaintextSecret> {
        // Verify the salt matches
        if key.salt() != &self.salt {
            return Err(CryptoError::decryption("Salt mismatch"));
        }

        let nonce = Nonce::from_slice(&self.nonce);
        let cipher = ChaCha20Poly1305::new(key.key());

        let plaintext_bytes = match self.version {
            1 => cipher.decrypt(nonce, self.ciphertext.as_slice()),
            CONTAINER_VERSION => {
                let header = self.header_bytes()?;
                cipher.decrypt(
                    nonce,
                    Payload {
                        msg: self.ciphertext.as_slice(),
                        aad: &header,
                    },
                )
            }
            other => {
                return Err(CryptoError::serialization(format!(
                    "Unsupported container version {}",
                    other
                )))
            }
        }
        .map_err(|_| CryptoError::AuthenticationFailed)?;

        Ok(PlaintextSecret::from_bytes(plaintext_bytes))
    }

    /// The version 2 header: every byte that precedes the ciphertext.
    fn header_bytes(&self) -> CryptoResult<Vec<u8>> {
        let metadata = serde_json::to_vec(&self.metadata).map_err(CryptoError::from)?;
        if metadata.len() > MAX_METADATA_LEN {
            return Err(CryptoError::invalid_input(format!(
                "Metadata is {} bytes; the limit is {}",
                metadata.len(),
                MAX_METADATA_LEN
            )));
        }

        let mut out = Vec::with_capacity(67 + metadata.len());
        out.extend_from_slice(&CONTAINER_MAGIC);
        out.push(self.version);
        out.push(ALG_CHACHA20_POLY1305);
        out.push(KDF_ARGON2ID_V13);
        out.extend_from_slice(&self.kdf.m_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf.t_cost.to_le_bytes());
        out.extend_from_slice(&self.kdf.p_cost.to_le_bytes());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
        out.extend_from_slice(&metadata);
        Ok(out)
    }

    /// Container format version
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Key derivation cost parameters recorded for this secret
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf
    }

    /// Get the metadata
    pub fn metadata(&self) -> &SecretMetadata {
        &self.metadata
    }

    /// Get the salt used for key derivation
    pub fn salt(&self) -> &[u8; defaults::SALT_LENGTH] {
        &self.salt
    }

    /// Get the nonce used for encryption
    pub fn nonce(&self) -> &[u8; defaults::NONCE_LENGTH] {
        &self.nonce
    }

    /// Get the ciphertext length
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> CryptoResult<String> {
        serde_json::to_string(self).map_err(CryptoError::from)
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> CryptoResult<Self> {
        serde_json::from_str(json).map_err(CryptoError::from)
    }

    /// Serialize to the binary container format.
    ///
    /// New secrets are written as version 2. A secret that was read from a
    /// version 1 container is written back as version 1, because its
    /// ciphertext was produced without the authenticated header.
    pub fn to_bytes(&self) -> CryptoResult<Vec<u8>> {
        if self.version == 1 {
            return bincode::serialize(&LegacyV1 {
                ciphertext: self.ciphertext.clone(),
                nonce: self.nonce,
                salt: self.salt,
                metadata: self.metadata.clone(),
            })
            .map_err(|e| CryptoError::serialization(e.to_string()));
        }

        let mut out = self.header_bytes()?;
        out.extend_from_slice(&self.ciphertext);
        Ok(out)
    }

    /// Whether `bytes` starts with the container magic (format version 2+).
    pub fn has_magic(bytes: &[u8]) -> bool {
        bytes.starts_with(&CONTAINER_MAGIC)
    }

    /// Parse a container. Accepts version 2 and legacy version 1.
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if Self::has_magic(bytes) {
            return Self::parse_v2(bytes);
        }

        use bincode::Options;
        let legacy: LegacyV1 = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(bytes.len() as u64)
            .deserialize(bytes)
            .map_err(|e| {
                CryptoError::serialization(format!("Not a CargoCrypt container: {}", e))
            })?;

        Ok(Self {
            ciphertext: legacy.ciphertext,
            nonce: legacy.nonce,
            salt: legacy.salt,
            metadata: legacy.metadata,
            version: 1,
            kdf: KdfParams::V1,
        })
    }

    fn parse_v2(bytes: &[u8]) -> CryptoResult<Self> {
        fn truncated() -> CryptoError {
            CryptoError::serialization("Container is truncated")
        }
        fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> CryptoResult<&'a [u8]> {
            let end = at.checked_add(n).ok_or_else(truncated)?;
            let slice = bytes.get(*at..end).ok_or_else(truncated)?;
            *at = end;
            Ok(slice)
        }
        fn take_u32(bytes: &[u8], at: &mut usize) -> CryptoResult<u32> {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(take(bytes, at, 4)?);
            Ok(u32::from_le_bytes(buf))
        }

        let mut at = CONTAINER_MAGIC.len();
        let version = take(bytes, &mut at, 1)?[0];
        if version != CONTAINER_VERSION {
            return Err(CryptoError::serialization(format!(
                "Unsupported container version {} (this build reads 1 and {})",
                version, CONTAINER_VERSION
            )));
        }
        let alg = take(bytes, &mut at, 1)?[0];
        if alg != ALG_CHACHA20_POLY1305 {
            return Err(CryptoError::serialization(format!(
                "Unsupported AEAD id {}",
                alg
            )));
        }
        let kdf_id = take(bytes, &mut at, 1)?[0];
        if kdf_id != KDF_ARGON2ID_V13 {
            return Err(CryptoError::serialization(format!(
                "Unsupported KDF id {}",
                kdf_id
            )));
        }

        let kdf = KdfParams {
            m_cost: take_u32(bytes, &mut at)?,
            t_cost: take_u32(bytes, &mut at)?,
            p_cost: take_u32(bytes, &mut at)?,
        };
        kdf.validate()?;

        let mut salt = [0u8; defaults::SALT_LENGTH];
        salt.copy_from_slice(take(bytes, &mut at, defaults::SALT_LENGTH)?);
        let mut nonce = [0u8; defaults::NONCE_LENGTH];
        nonce.copy_from_slice(take(bytes, &mut at, defaults::NONCE_LENGTH)?);

        let metadata_len = take_u32(bytes, &mut at)? as usize;
        if metadata_len > MAX_METADATA_LEN {
            return Err(CryptoError::serialization("Metadata block is too large"));
        }
        let metadata_raw = take(bytes, &mut at, metadata_len)?;
        let metadata: SecretMetadata =
            serde_json::from_slice(metadata_raw).map_err(CryptoError::from)?;

        let secret = Self {
            ciphertext: bytes[at..].to_vec(),
            nonce,
            salt,
            metadata,
            version,
            kdf,
        };

        // The header is re-encoded for authentication, so only a canonical
        // encoding of the metadata is accepted.
        if secret.header_bytes()? != bytes[..at] {
            return Err(CryptoError::serialization(
                "Container metadata is not canonically encoded",
            ));
        }

        Ok(secret)
    }

    /// Create a new secret with updated encryption (re-encrypt with new password)
    pub fn reencrypt_with_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> CryptoResult<Self> {
        let plaintext = self.decrypt_with_password(old_password)?;
        Self::encrypt_with_password(plaintext, new_password, Some(self.metadata.clone()))
    }

    /// Verify that the secret can be decrypted with the given password
    pub fn verify_password(&self, password: &str) -> bool {
        self.decrypt_with_password(password).is_ok()
    }
}

impl fmt::Debug for EncryptedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce", &hex::encode(self.nonce))
            .field("salt", &hex::encode(self.salt))
            .field("metadata", &self.metadata)
            .field("version", &self.version)
            .field("kdf", &self.kdf)
            .finish()
    }
}

impl SecretMetadata {
    /// Create new metadata with current timestamp
    pub fn new() -> Self {
        Self {
            description: None,
            created_at: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
            tags: Vec::new(),
            secret_type: None,
        }
    }

    /// Create metadata with description
    pub fn with_description<S: Into<String>>(description: S) -> Self {
        let mut metadata = Self::new();
        metadata.description = Some(description.into());
        metadata
    }

    /// Create metadata with type
    pub fn with_type(secret_type: SecretType) -> Self {
        let mut metadata = Self::new();
        metadata.secret_type = Some(secret_type);
        metadata
    }

    /// Add a tag
    pub fn add_tag<S: Into<String>>(&mut self, tag: S) -> &mut Self {
        self.tags.push(tag.into());
        self
    }

    /// Set the description
    pub fn set_description<S: Into<String>>(&mut self, description: S) -> &mut Self {
        self.description = Some(description.into());
        self
    }

    /// Set the secret type
    pub fn set_type(&mut self, secret_type: SecretType) -> &mut Self {
        self.secret_type = Some(secret_type);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_string() {
        let secret_data = "This is a secret message!";
        let password = "test_password_123";

        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_password(
            plaintext,
            password,
            Some(SecretMetadata::with_description("Test secret")),
        )
        .unwrap();

        let decrypted = encrypted.decrypt_with_password(password).unwrap();
        assert_eq!(decrypted.as_string().unwrap(), secret_data);
    }

    #[test]
    fn test_encrypt_decrypt_bytes() {
        let secret_data = vec![1, 2, 3, 4, 5, 255, 0, 128];
        let password = "test_password_123";

        let plaintext = PlaintextSecret::from_bytes(secret_data.clone());
        let encrypted = EncryptedSecret::encrypt_with_password(plaintext, password, None).unwrap();

        let decrypted = encrypted.decrypt_with_password(password).unwrap();
        assert_eq!(decrypted.as_bytes(), &secret_data);
    }

    #[test]
    fn test_wrong_password() {
        let secret_data = "This is a secret message!";
        let password = "correct_password";
        let wrong_password = "wrong_password";

        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_password(plaintext, password, None).unwrap();

        let result = encrypted.decrypt_with_password(wrong_password);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_password_verification() {
        let secret_data = "secret";
        let password = "test_password";

        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_password(plaintext, password, None).unwrap();

        assert!(encrypted.verify_password(password));
        assert!(!encrypted.verify_password("wrong_password"));
    }

    #[test]
    fn test_json_serialization() {
        let secret_data = "This is a secret message!";
        let password = "test_password_123";

        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted = EncryptedSecret::encrypt_with_password(
            plaintext,
            password,
            Some(SecretMetadata::with_description("Test secret")),
        )
        .unwrap();

        let json = encrypted.to_json().unwrap();
        let deserialized = EncryptedSecret::from_json(&json).unwrap();

        let decrypted = deserialized.decrypt_with_password(password).unwrap();
        assert_eq!(decrypted.as_string().unwrap(), secret_data);
    }

    #[test]
    fn test_container_roundtrip_and_layout() {
        let password = "test_password_123";
        let encrypted = EncryptedSecret::encrypt_with_password(
            PlaintextSecret::from_string("payload".to_string()),
            password,
            Some(SecretMetadata::with_description("Test secret")),
        )
        .unwrap();

        let bytes = encrypted.to_bytes().unwrap();
        assert_eq!(&bytes[..4], b"CCRY");
        assert_eq!(bytes[4], 2);
        assert_eq!(u32::from_le_bytes(bytes[7..11].try_into().unwrap()), 65536);

        let parsed = EncryptedSecret::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version(), 2);
        assert_eq!(parsed.kdf_params(), KdfParams::V1);
        assert_eq!(
            parsed.metadata().description.as_deref(),
            Some("Test secret")
        );
        let decrypted = parsed.decrypt_with_password(password).unwrap();
        assert_eq!(decrypted.as_string().unwrap(), "payload");
    }

    /// Flipping any header byte must fail: either the parser rejects it or
    /// authentication does. Uses a cheap KDF so every position can be tried.
    #[test]
    fn test_header_tampering_is_detected() {
        let salt = [9u8; defaults::SALT_LENGTH];
        let cheap = KdfParams {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let key = DerivedKey::derive("pw", &salt, cheap).unwrap();
        let encrypted = EncryptedSecret::encrypt_with_key(
            PlaintextSecret::from_string("payload".to_string()),
            &key,
            Some(SecretMetadata {
                description: Some("prod".to_string()),
                created_at: Some(1),
                tags: vec![],
                secret_type: None,
            }),
        )
        .unwrap();
        let bytes = encrypted.to_bytes().unwrap();
        let header_len = bytes.len() - encrypted.ciphertext_len();

        assert!(EncryptedSecret::from_bytes(&bytes)
            .unwrap()
            .decrypt_with_key(&key)
            .is_ok());

        for i in 0..header_len {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0x01;
            let opened = EncryptedSecret::from_bytes(&tampered).and_then(|s| {
                // Same password, whatever parameters the header now claims.
                let k = DerivedKey::derive("pw", s.salt(), s.kdf_params())?;
                s.decrypt_with_key(&k)
            });
            assert!(opened.is_err(), "flipping header byte {} went unnoticed", i);
        }
    }

    #[test]
    fn test_metadata_swap_is_detected() {
        let salt = [9u8; defaults::SALT_LENGTH];
        let cheap = KdfParams {
            m_cost: 64,
            t_cost: 1,
            p_cost: 1,
        };
        let key = DerivedKey::derive("pw", &salt, cheap).unwrap();
        let mut encrypted = EncryptedSecret::encrypt_with_key(
            PlaintextSecret::from_string("payload".to_string()),
            &key,
            Some(SecretMetadata::with_description("staging")),
        )
        .unwrap();

        encrypted.metadata.description = Some("production".to_string());
        assert!(matches!(
            encrypted.decrypt_with_key(&key).unwrap_err(),
            CryptoError::AuthenticationFailed
        ));
    }

    #[test]
    fn test_hostile_kdf_parameters_are_rejected_before_derivation() {
        let encrypted = EncryptedSecret::encrypt_with_key(
            PlaintextSecret::from_string("payload".to_string()),
            &DerivedKey::derive(
                "pw",
                &[9u8; defaults::SALT_LENGTH],
                KdfParams {
                    m_cost: 64,
                    t_cost: 1,
                    p_cost: 1,
                },
            )
            .unwrap(),
            None,
        )
        .unwrap();
        let mut bytes = encrypted.to_bytes().unwrap();
        bytes[7..11].copy_from_slice(&u32::MAX.to_le_bytes()); // 4 TiB of memory

        assert!(EncryptedSecret::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_truncated_and_unknown_containers_are_rejected() {
        let encrypted = EncryptedSecret::encrypt_with_password(
            PlaintextSecret::from_string("payload".to_string()),
            "test_password_123",
            None,
        )
        .unwrap();
        let bytes = encrypted.to_bytes().unwrap();

        for len in 0..67 {
            assert!(EncryptedSecret::from_bytes(&bytes[..len]).is_err());
        }

        let mut future = bytes.clone();
        future[4] = 3;
        assert!(EncryptedSecret::from_bytes(&future).is_err());

        assert!(EncryptedSecret::from_bytes(b"API_KEY=hunter2\n").is_err());
    }

    /// A container written by 0.2.3, before the format was versioned.
    #[test]
    fn test_v1_container_still_decrypts() {
        let bytes = include_bytes!("../../tests/fixtures/v1_container.bin");
        let secret = EncryptedSecret::from_bytes(bytes).unwrap();

        assert_eq!(secret.version(), 1);
        assert_eq!(secret.kdf_params(), KdfParams::V1);
        let plaintext = secret
            .decrypt_with_password("correct horse battery staple")
            .unwrap();
        assert_eq!(plaintext.as_bytes(), b"API_KEY=hunter2\n");

        // Re-serialising a v1 secret must not change its bytes.
        assert_eq!(secret.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn test_reencryption() {
        let secret_data = "This is a secret message!";
        let old_password = "old_password";
        let new_password = "new_password";

        let plaintext = PlaintextSecret::from_string(secret_data.to_string());
        let encrypted =
            EncryptedSecret::encrypt_with_password(plaintext, old_password, None).unwrap();

        let reencrypted = encrypted
            .reencrypt_with_password(old_password, new_password)
            .unwrap();

        // Old password should not work
        assert!(!reencrypted.verify_password(old_password));

        // New password should work
        let decrypted = reencrypted.decrypt_with_password(new_password).unwrap();
        assert_eq!(decrypted.as_string().unwrap(), secret_data);
    }

    #[test]
    fn test_metadata() {
        let mut metadata = SecretMetadata::new();
        metadata
            .set_description("API Key for service X")
            .add_tag("production")
            .add_tag("api")
            .set_type(SecretType::ApiKey);

        assert_eq!(
            metadata.description.as_ref().unwrap(),
            "API Key for service X"
        );
        assert_eq!(metadata.tags, vec!["production", "api"]);
        assert_eq!(metadata.secret_type.as_ref().unwrap(), &SecretType::ApiKey);
        assert!(metadata.created_at.is_some());
    }

    #[test]
    fn test_secret_types() {
        assert_eq!(SecretType::Generic.to_string(), "generic");
        assert_eq!(SecretType::ApiKey.to_string(), "api_key");
        assert_eq!(
            SecretType::Custom("jwt".to_string()).to_string(),
            "custom:jwt"
        );
    }

    #[test]
    fn test_plaintext_secret_zeroization() {
        let data = "sensitive_data".to_string();
        let secret = PlaintextSecret::from_string(data);

        assert_eq!(secret.len(), 14);
        assert!(!secret.is_empty());

        // Secret should be automatically zeroized when dropped
        drop(secret);
        // Can't test the actual zeroization as we can't access the memory after drop
    }
}
