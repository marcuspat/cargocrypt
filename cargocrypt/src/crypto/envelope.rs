//! Sealing a secret to one recipient's public key.
//!
//! This is the construction age and HPKE's base mode use: an ephemeral
//! X25519 key agreement with the recipient's static public key, HKDF-SHA256
//! to turn the shared secret into a wrapping key, and XChaCha20-Poly1305 to
//! encrypt. Only the holder of the recipient's secret key can open the
//! result; the sender keeps nothing.
//!
//! # Layout of a sealed value
//!
//! ```text
//! offset  size  field
//!      0     1  version (1)
//!      1    32  ephemeral X25519 public key
//!     33    24  nonce
//!     57     …  ciphertext and 16-byte tag
//! ```
//!
//! The wrapping key is `HKDF-SHA256(ikm = shared secret,
//! salt = ephemeral public || recipient public, info = "cargocrypt/envelope/v1")`.
//! The caller's `context` is the associated data: a value sealed for one
//! purpose does not open under another.

use crate::crypto::{CryptoError, CryptoResult, SecureRandom};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use std::fmt;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const VERSION: u8 = 1;
const NONCE_LENGTH: usize = 24;
const HEADER_LENGTH: usize = 1 + 32 + NONCE_LENGTH;
const INFO: &[u8] = b"cargocrypt/envelope/v1";

/// A recipient's long-term secret key. Never stored in the repository.
pub struct RecipientSecretKey(StaticSecret);

/// A recipient's public key: what a team member publishes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RecipientPublicKey(PublicKey);

impl RecipientSecretKey {
    /// Generate a new key from the operating system's random source.
    pub fn generate() -> CryptoResult<Self> {
        let bytes = Zeroizing::new(SecureRandom::generate_bytes(32)?);
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes);
        Ok(Self(StaticSecret::from(*seed)))
    }

    /// The matching public key.
    pub fn public_key(&self) -> RecipientPublicKey {
        RecipientPublicKey(PublicKey::from(&self.0))
    }

    /// Hex encoding, for the owner to store privately.
    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.0.to_bytes()))
    }

    /// Parse the hex encoding produced by [`RecipientSecretKey::to_hex`].
    pub fn from_hex(text: &str) -> CryptoResult<Self> {
        let bytes = Zeroizing::new(hex::decode(text.trim())?);
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            CryptoError::invalid_input("A secret key is 32 bytes (64 hex characters)")
        })?;
        Ok(Self(StaticSecret::from(array)))
    }
}

impl fmt::Debug for RecipientSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecipientSecretKey([REDACTED])")
    }
}

impl RecipientPublicKey {
    /// Hex encoding, safe to publish.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// Parse a hex-encoded public key.
    pub fn from_hex(text: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(text.trim())
            .map_err(|_| CryptoError::invalid_input("A public key is 64 hex characters"))?;
        let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            CryptoError::invalid_input("A public key is 32 bytes (64 hex characters)")
        })?;
        Ok(Self(PublicKey::from(array)))
    }
}

impl fmt::Debug for RecipientPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecipientPublicKey({})", self.to_hex())
    }
}

struct KeyLength;
impl ring::hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}

fn wrapping_key(
    shared: &[u8; 32],
    ephemeral: &PublicKey,
    recipient: &PublicKey,
) -> CryptoResult<Zeroizing<[u8; 32]>> {
    // An all-zero shared secret means the peer supplied a low-order point.
    if shared.iter().all(|&b| b == 0) {
        return Err(CryptoError::invalid_input("Invalid public key"));
    }
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral.as_bytes());
    salt[32..].copy_from_slice(recipient.as_bytes());

    let mut key = Zeroizing::new([0u8; 32]);
    ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &salt)
        .extract(shared)
        .expand(&[INFO], KeyLength)
        .and_then(|okm| okm.fill(key.as_mut()))
        .map_err(|_| CryptoError::key_derivation("HKDF expansion failed"))?;
    Ok(key)
}

/// Encrypt `plaintext` so that only `recipient` can read it.
pub fn seal(
    plaintext: &[u8],
    recipient: &RecipientPublicKey,
    context: &[u8],
) -> CryptoResult<Vec<u8>> {
    let ephemeral_secret = RecipientSecretKey::generate()?.0;
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient.0);
    let key = wrapping_key(shared.as_bytes(), &ephemeral_public, &recipient.0)?;

    let nonce = SecureRandom::generate_bytes(NONCE_LENGTH)?;
    let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: context,
            },
        )
        .map_err(CryptoError::from)?;

    let mut out = Vec::with_capacity(HEADER_LENGTH + ciphertext.len());
    out.push(VERSION);
    out.extend_from_slice(ephemeral_public.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a value produced by [`seal`] for this recipient and `context`.
pub fn open(
    sealed: &[u8],
    recipient: &RecipientSecretKey,
    context: &[u8],
) -> CryptoResult<Zeroizing<Vec<u8>>> {
    if sealed.len() < HEADER_LENGTH + 16 {
        return Err(CryptoError::serialization("Sealed value is truncated"));
    }
    if sealed[0] != VERSION {
        return Err(CryptoError::serialization(format!(
            "Unsupported envelope version {}",
            sealed[0]
        )));
    }
    let mut ephemeral = [0u8; 32];
    ephemeral.copy_from_slice(&sealed[1..33]);
    let ephemeral_public = PublicKey::from(ephemeral);
    let shared = recipient.0.diffie_hellman(&ephemeral_public);
    let key = wrapping_key(
        shared.as_bytes(),
        &ephemeral_public,
        &PublicKey::from(&recipient.0),
    )?;

    XChaCha20Poly1305::new(Key::from_slice(key.as_ref()))
        .decrypt(
            XNonce::from_slice(&sealed[33..HEADER_LENGTH]),
            Payload {
                msg: &sealed[HEADER_LENGTH..],
                aad: context,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_recipient_can_open() {
        let alice = RecipientSecretKey::generate().unwrap();
        let bob = RecipientSecretKey::generate().unwrap();
        let sealed = seal(b"team key material", &alice.public_key(), b"key-1").unwrap();

        assert_eq!(
            open(&sealed, &alice, b"key-1").unwrap().as_slice(),
            b"team key material"
        );
        assert!(matches!(
            open(&sealed, &bob, b"key-1"),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn context_is_bound() {
        let alice = RecipientSecretKey::generate().unwrap();
        let sealed = seal(b"secret", &alice.public_key(), b"key-1").unwrap();
        assert!(open(&sealed, &alice, b"key-2").is_err());
    }

    #[test]
    fn sealing_is_randomised_and_tamper_evident() {
        let alice = RecipientSecretKey::generate().unwrap();
        let a = seal(b"secret", &alice.public_key(), b"").unwrap();
        let b = seal(b"secret", &alice.public_key(), b"").unwrap();
        assert_ne!(a, b);

        for i in 0..a.len() {
            let mut tampered = a.clone();
            tampered[i] ^= 0x01;
            assert!(
                open(&tampered, &alice, b"").is_err(),
                "byte {} unnoticed",
                i
            );
        }
        for len in 0..a.len() {
            assert!(open(&a[..len], &alice, b"").is_err());
        }
    }

    #[test]
    fn keys_round_trip_through_hex() {
        let secret = RecipientSecretKey::generate().unwrap();
        let restored = RecipientSecretKey::from_hex(&secret.to_hex()).unwrap();
        assert_eq!(restored.public_key(), secret.public_key());

        let public = RecipientPublicKey::from_hex(&secret.public_key().to_hex()).unwrap();
        assert_eq!(public, secret.public_key());

        assert!(RecipientPublicKey::from_hex("public_key_alice").is_err());
        assert!(RecipientPublicKey::from_hex("abcd").is_err());
        assert!(!format!("{:?}", secret).contains(secret.to_hex().as_str()));
    }

    /// RFC 7748 section 6.1: the X25519 implementation agrees with the
    /// published Diffie-Hellman test vector.
    #[test]
    fn x25519_matches_rfc7748() {
        let alice = RecipientSecretKey::from_hex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        )
        .unwrap();
        assert_eq!(
            alice.public_key().to_hex(),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        let bob_public = RecipientPublicKey::from_hex(
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        )
        .unwrap();
        let shared = alice.0.diffie_hellman(&bob_public.0);
        assert_eq!(
            hex::encode(shared.as_bytes()),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[test]
    fn low_order_public_keys_are_rejected() {
        let zero = RecipientPublicKey::from_hex(&"00".repeat(32)).unwrap();
        assert!(seal(b"secret", &zero, b"").is_err());
    }
}
