//! Property tests: round trips hold for arbitrary input, tampering is always
//! detected, and no parser panics on bytes it did not write.

use cargocrypt::crypto::stream::{decrypt_stream, encrypt_stream, HEADER_LENGTH};
use cargocrypt::crypto::{
    DerivedKey, EncryptedSecret, KdfParams, PlaintextSecret, SecretMetadata, SecretType,
};
use cargocrypt::detection::{plausibility, report, SecretDetector};
use proptest::prelude::*;
use std::sync::OnceLock;

const PASSWORD: &str = "property-test-passphrase";
const CHEAP: KdfParams = KdfParams {
    m_cost: 64,
    t_cost: 1,
    p_cost: 1,
};

fn key() -> &'static DerivedKey {
    static KEY: OnceLock<DerivedKey> = OnceLock::new();
    KEY.get_or_init(|| DerivedKey::derive(PASSWORD, &[3u8; 32], CHEAP).unwrap())
}

fn detector() -> &'static SecretDetector {
    static DETECTOR: OnceLock<SecretDetector> = OnceLock::new();
    DETECTOR.get_or_init(SecretDetector::new)
}

fn metadata() -> impl Strategy<Value = Option<SecretMetadata>> {
    proptest::option::of(
        (
            proptest::option::of(".{0,40}"),
            proptest::option::of(any::<u64>()),
            proptest::collection::vec(".{0,12}", 0..4),
            proptest::option::of(prop_oneof![
                Just(SecretType::ApiKey),
                Just(SecretType::Password),
                ".{0,10}".prop_map(SecretType::Custom),
            ]),
        )
            .prop_map(
                |(description, created_at, tags, secret_type)| SecretMetadata {
                    description,
                    created_at,
                    tags,
                    secret_type,
                },
            ),
    )
}

fn seal(data: &[u8], metadata: Option<SecretMetadata>) -> Vec<u8> {
    EncryptedSecret::encrypt_with_key(PlaintextSecret::from_bytes(data.to_vec()), key(), metadata)
        .unwrap()
        .to_bytes()
        .unwrap()
}

fn open(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    let secret = EncryptedSecret::from_bytes(bytes).map_err(|_| ())?;
    // Derive with whatever the header claims, bounded so a mutated cost field
    // cannot make the test allocate gigabytes.
    let kdf = secret.kdf_params();
    if kdf.m_cost > 1024 || kdf.t_cost > 2 || kdf.p_cost > 2 {
        return Err(());
    }
    let key = DerivedKey::derive(PASSWORD, secret.salt(), kdf).map_err(|_| ())?;
    secret
        .decrypt_with_key(&key)
        .map(|p| p.as_bytes().to_vec())
        .map_err(|_| ())
}

fn seal_stream(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encrypt_stream(&mut &data[..], &mut out, PASSWORD, CHEAP).unwrap();
    out
}

fn open_stream(bytes: &[u8]) -> Result<Vec<u8>, ()> {
    // Same guard as above for the stream header's cost fields.
    if bytes.len() >= 19 {
        let m = u32::from_le_bytes(bytes[7..11].try_into().unwrap());
        let t = u32::from_le_bytes(bytes[11..15].try_into().unwrap());
        let p = u32::from_le_bytes(bytes[15..19].try_into().unwrap());
        if m > 1024 || t > 2 || p > 2 {
            return Err(());
        }
    }
    let mut out = Vec::new();
    decrypt_stream(&mut &bytes[..], &mut out, PASSWORD)
        .map(|_| out)
        .map_err(|_| ())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn container_round_trips(data in proptest::collection::vec(any::<u8>(), 0..2048), meta in metadata()) {
        let bytes = seal(&data, meta.clone());
        let parsed = EncryptedSecret::from_bytes(&bytes).unwrap();
        if let Some(meta) = meta {
            prop_assert_eq!(&parsed.metadata().description, &meta.description);
            prop_assert_eq!(&parsed.metadata().tags, &meta.tags);
        }
        // Serialising what was parsed reproduces the input exactly.
        prop_assert_eq!(parsed.to_bytes().unwrap(), bytes.clone());
        prop_assert_eq!(open(&bytes).unwrap(), data);
    }

    #[test]
    fn any_single_byte_change_to_a_container_is_rejected(
        data in proptest::collection::vec(any::<u8>(), 0..512),
        meta in metadata(),
        position in any::<prop::sample::Index>(),
        flip in 1u8..=255,
    ) {
        let mut bytes = seal(&data, meta);
        let i = position.index(bytes.len());
        bytes[i] ^= flip;
        prop_assert!(open(&bytes).is_err(), "byte {} xor {:#04x} was accepted", i, flip);
    }

    #[test]
    fn truncated_or_extended_containers_are_rejected(
        data in proptest::collection::vec(any::<u8>(), 0..512),
        cut in any::<prop::sample::Index>(),
        extra in proptest::collection::vec(any::<u8>(), 1..16),
    ) {
        let bytes = seal(&data, None);
        let len = cut.index(bytes.len());
        prop_assert!(open(&bytes[..len]).is_err());

        let mut longer = bytes;
        longer.extend_from_slice(&extra);
        prop_assert!(open(&longer).is_err());
    }

    #[test]
    fn container_parser_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = EncryptedSecret::from_bytes(&bytes);
        // With the magic in place the version 2 path is exercised too.
        let mut with_magic = b"CCRY\x02\x02\x01".to_vec();
        with_magic.extend_from_slice(&bytes);
        let _ = EncryptedSecret::from_bytes(&with_magic);
    }

    #[test]
    fn stream_decoder_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = open_stream(&bytes);
        let mut with_magic = b"CCRY\x03\x02\x01".to_vec();
        with_magic.extend_from_slice(&bytes);
        let _ = open_stream(&with_magic);
    }

    #[test]
    fn scanner_and_helpers_never_panic(text in "\\PC{0,400}", lines in proptest::collection::vec("[ -~é✓]{0,80}", 0..8)) {
        let _ = detector().scan_content(&text, "input.txt").unwrap();
        let joined = lines.join("\n");
        let findings = detector().scan_content(&joined, ".env").unwrap();
        for f in &findings {
            // Positions must be usable as slice bounds.
            prop_assert!(joined.get(f.secret.start_position..f.secret.end_position).is_some());
            prop_assert!(f.secret.line_number >= 1);
        }
        let _ = plausibility::is_plausible_secret(&text);
        let redacted = report::redact(&text);
        prop_assert!(text.chars().count() <= 4 || !redacted.contains(&text));
    }
}

proptest! {
    // Fewer cases: each one moves a few hundred kilobytes.
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn stream_round_trips(data in proptest::collection::vec(any::<u8>(), 0..200_000)) {
        let sealed = seal_stream(&data);
        prop_assert_eq!(open_stream(&sealed).unwrap(), data);
    }

    #[test]
    fn stream_rejects_any_change(
        data in proptest::collection::vec(any::<u8>(), 0..150_000),
        position in any::<prop::sample::Index>(),
        flip in 1u8..=255,
        cut in any::<prop::sample::Index>(),
    ) {
        let sealed = seal_stream(&data);
        prop_assert!(sealed.len() >= HEADER_LENGTH + 16);

        let mut flipped = sealed.clone();
        let i = position.index(flipped.len());
        flipped[i] ^= flip;
        prop_assert!(open_stream(&flipped).is_err(), "byte {} xor {:#04x} was accepted", i, flip);

        let len = cut.index(sealed.len());
        prop_assert!(open_stream(&sealed[..len]).is_err(), "cut to {} bytes was accepted", len);
    }
}
