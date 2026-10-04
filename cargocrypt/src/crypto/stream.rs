//! Streaming file encryption (container format version 3).
//!
//! Files are encrypted in 64 KiB chunks with the STREAM construction (Hoang,
//! Reyhanitabar, Rogaway, Vizár, 2015) over XChaCha20-Poly1305, so memory use
//! is constant regardless of file size. Each chunk's nonce is a random 19-byte
//! prefix, a 32-bit big-endian chunk counter and a one-byte "last chunk" flag.
//! The counter makes reordering fail authentication; the flag makes
//! truncation fail, including truncation at an exact chunk boundary.
//!
//! # Layout
//!
//! ```text
//! offset  size  field
//!      0     4  magic "CCRY"
//!      4     1  format version (3)
//!      5     1  AEAD id   (2 = XChaCha20-Poly1305)
//!      6     1  KDF id    (1 = Argon2id v1.3)
//!      7     4  Argon2 memory cost, KiB, little endian
//!     11     4  Argon2 passes, little endian
//!     15     4  Argon2 lanes, little endian
//!     19    32  salt
//!     51    19  nonce prefix
//!     70     4  plaintext chunk size, little endian
//!     74     …  chunks: chunk-size bytes of ciphertext plus a 16-byte tag;
//!               the final chunk may be shorter and may be empty
//! ```
//!
//! The 74-byte header is the associated data of every chunk.

use crate::crypto::{defaults, CryptoError, CryptoResult, DerivedKey, KdfParams, SecureRandom};
use chacha20poly1305::{
    aead::{
        generic_array::GenericArray,
        stream::{DecryptorBE32, EncryptorBE32},
        Payload,
    },
    XChaCha20Poly1305,
};
use std::io::{Read, Write};
use zeroize::Zeroizing;

/// Container version of the streaming format.
pub const STREAM_VERSION: u8 = 3;

/// Plaintext bytes per chunk written by this version.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Largest chunk size accepted from an untrusted header.
const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

const MAGIC: [u8; 4] = *b"CCRY";
const ALG_XCHACHA20_POLY1305: u8 = 2;
const KDF_ARGON2ID_V13: u8 = 1;
const NONCE_PREFIX_LENGTH: usize = 19;
const TAG_LENGTH: usize = 16;

/// Length of the stream header in bytes.
pub const HEADER_LENGTH: usize = 74;

/// Whether `prefix` (at least the first five bytes of a file) is a streaming
/// container.
pub fn is_stream_container(prefix: &[u8]) -> bool {
    prefix.len() > MAGIC.len()
        && prefix.starts_with(&MAGIC)
        && prefix[MAGIC.len()] == STREAM_VERSION
}

fn io_err(e: std::io::Error) -> CryptoError {
    CryptoError::Generic {
        message: format!("I/O error: {}", e),
    }
}

/// Read until `buf` is full or the reader is exhausted.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> CryptoResult<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io_err(e)),
        }
    }
    Ok(filled)
}

fn build_header(
    kdf: KdfParams,
    salt: &[u8; defaults::SALT_LENGTH],
    prefix: &[u8],
    chunk_size: u32,
) -> [u8; HEADER_LENGTH] {
    let mut header = [0u8; HEADER_LENGTH];
    header[..4].copy_from_slice(&MAGIC);
    header[4] = STREAM_VERSION;
    header[5] = ALG_XCHACHA20_POLY1305;
    header[6] = KDF_ARGON2ID_V13;
    header[7..11].copy_from_slice(&kdf.m_cost.to_le_bytes());
    header[11..15].copy_from_slice(&kdf.t_cost.to_le_bytes());
    header[15..19].copy_from_slice(&kdf.p_cost.to_le_bytes());
    header[19..51].copy_from_slice(salt);
    header[51..70].copy_from_slice(prefix);
    header[70..74].copy_from_slice(&chunk_size.to_le_bytes());
    header
}

/// Encrypt everything from `reader` into `writer`. Returns the number of
/// plaintext bytes processed.
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &str,
    kdf: KdfParams,
) -> CryptoResult<u64> {
    encrypt_stream_with_chunk_size(reader, writer, password, kdf, CHUNK_SIZE)
}

fn encrypt_stream_with_chunk_size<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &str,
    kdf: KdfParams,
    chunk_size: usize,
) -> CryptoResult<u64> {
    let salt = SecureRandom::generate_salt()?;
    let prefix = SecureRandom::generate_bytes(NONCE_PREFIX_LENGTH)?;
    let key = DerivedKey::derive(password, &salt, kdf)?;
    let header = build_header(kdf, &salt, &prefix, chunk_size as u32);
    writer.write_all(&header).map_err(io_err)?;

    let mut encryptor =
        EncryptorBE32::<XChaCha20Poly1305>::new(key.key(), GenericArray::from_slice(&prefix));

    // One chunk of lookahead: a chunk is final only if nothing follows it.
    let mut current = Zeroizing::new(vec![0u8; chunk_size]);
    let mut next = Zeroizing::new(vec![0u8; chunk_size]);
    let mut current_len = read_full(reader, &mut current)?;
    let mut total = 0u64;

    loop {
        let next_len = if current_len == chunk_size {
            read_full(reader, &mut next)?
        } else {
            0
        };
        total += current_len as u64;
        let payload = Payload {
            msg: &current[..current_len],
            aad: &header,
        };

        if next_len == 0 {
            let ciphertext = encryptor
                .encrypt_last(payload)
                .map_err(|_| CryptoError::encryption("Failed to encrypt final chunk"))?;
            writer.write_all(&ciphertext).map_err(io_err)?;
            break;
        }

        let ciphertext = encryptor
            .encrypt_next(payload)
            .map_err(|_| CryptoError::encryption("File is too large for the stream format"))?;
        writer.write_all(&ciphertext).map_err(io_err)?;

        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }

    writer.flush().map_err(io_err)?;
    Ok(total)
}

/// Decrypt a streaming container from `reader` into `writer`. Returns the
/// number of plaintext bytes written.
///
/// Plaintext is written as each chunk authenticates, so on error the caller
/// must discard whatever `writer` received: an early chunk may be genuine
/// while the stream as a whole is truncated or forged.
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    password: &str,
) -> CryptoResult<u64> {
    let mut header = [0u8; HEADER_LENGTH];
    if read_full(reader, &mut header)? != HEADER_LENGTH {
        return Err(CryptoError::serialization("Container is truncated"));
    }
    if !is_stream_container(&header) {
        return Err(CryptoError::serialization("Not a streaming container"));
    }
    if header[5] != ALG_XCHACHA20_POLY1305 {
        return Err(CryptoError::serialization(format!(
            "Unsupported AEAD id {}",
            header[5]
        )));
    }
    if header[6] != KDF_ARGON2ID_V13 {
        return Err(CryptoError::serialization(format!(
            "Unsupported KDF id {}",
            header[6]
        )));
    }

    let u32_at =
        |i: usize| u32::from_le_bytes([header[i], header[i + 1], header[i + 2], header[i + 3]]);
    let kdf = KdfParams {
        m_cost: u32_at(7),
        t_cost: u32_at(11),
        p_cost: u32_at(15),
    };
    kdf.validate()?;
    let chunk_size = u32_at(70) as usize;
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return Err(CryptoError::serialization("Invalid chunk size"));
    }

    let mut salt = [0u8; defaults::SALT_LENGTH];
    salt.copy_from_slice(&header[19..51]);
    let key = DerivedKey::derive(password, &salt, kdf)?;
    let mut decryptor = DecryptorBE32::<XChaCha20Poly1305>::new(
        key.key(),
        GenericArray::from_slice(&header[51..70]),
    );

    let sealed = chunk_size + TAG_LENGTH;
    let mut current = vec![0u8; sealed];
    let mut next = vec![0u8; sealed];
    let mut current_len = read_full(reader, &mut current)?;
    let mut total = 0u64;

    loop {
        let next_len = if current_len == sealed {
            read_full(reader, &mut next)?
        } else {
            0
        };
        let payload = Payload {
            msg: &current[..current_len],
            aad: &header,
        };

        if next_len == 0 {
            let plaintext = Zeroizing::new(
                decryptor
                    .decrypt_last(payload)
                    .map_err(|_| CryptoError::AuthenticationFailed)?,
            );
            writer.write_all(&plaintext).map_err(io_err)?;
            total += plaintext.len() as u64;
            break;
        }

        let plaintext = Zeroizing::new(
            decryptor
                .decrypt_next(payload)
                .map_err(|_| CryptoError::AuthenticationFailed)?,
        );
        writer.write_all(&plaintext).map_err(io_err)?;
        total += plaintext.len() as u64;

        std::mem::swap(&mut current, &mut next);
        current_len = next_len;
    }

    writer.flush().map_err(io_err)?;
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "stream-test-password";
    const CHEAP: KdfParams = KdfParams {
        m_cost: 64,
        t_cost: 1,
        p_cost: 1,
    };
    /// Small chunks keep the multi-chunk cases quick and easy to index.
    const SMALL: usize = 32;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn seal(plaintext: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let n =
            encrypt_stream_with_chunk_size(&mut &plaintext[..], &mut out, PASSWORD, CHEAP, chunk)
                .unwrap();
        assert_eq!(n, plaintext.len() as u64);
        out
    }

    fn open(container: &[u8], password: &str) -> CryptoResult<Vec<u8>> {
        let mut out = Vec::new();
        decrypt_stream(&mut &container[..], &mut out, password)?;
        Ok(out)
    }

    #[test]
    fn round_trips_at_every_chunk_boundary() {
        for len in [0, 1, SMALL - 1, SMALL, SMALL + 1, 2 * SMALL, 5 * SMALL + 7] {
            let plaintext = data(len);
            let sealed = seal(&plaintext, SMALL);
            let chunks = (len / SMALL) + usize::from(len % SMALL != 0 || len == 0);
            assert_eq!(
                sealed.len(),
                HEADER_LENGTH + len + chunks * TAG_LENGTH,
                "unexpected container size for {} bytes",
                len
            );
            assert_eq!(open(&sealed, PASSWORD).unwrap(), plaintext, "len {}", len);
        }
    }

    #[test]
    fn default_chunk_size_round_trips() {
        let plaintext = data(CHUNK_SIZE * 2 + 123);
        let mut sealed = Vec::new();
        encrypt_stream(&mut &plaintext[..], &mut sealed, PASSWORD, CHEAP).unwrap();
        assert!(is_stream_container(&sealed));
        assert_eq!(open(&sealed, PASSWORD).unwrap(), plaintext);
    }

    #[test]
    fn wrong_password_fails_authentication() {
        let sealed = seal(&data(100), SMALL);
        assert!(matches!(
            open(&sealed, "not-the-password"),
            Err(CryptoError::AuthenticationFailed)
        ));
    }

    #[test]
    fn truncation_is_detected_at_any_length() {
        let sealed = seal(&data(3 * SMALL), SMALL);
        for len in 0..sealed.len() {
            assert!(
                open(&sealed[..len], PASSWORD).is_err(),
                "container cut to {} of {} bytes was accepted",
                len,
                sealed.len()
            );
        }
    }

    #[test]
    fn dropping_whole_trailing_chunks_is_detected() {
        let sealed = seal(&data(3 * SMALL), SMALL);
        let chunk = SMALL + TAG_LENGTH;
        // Exactly one and exactly two chunks left: each is a well-formed
        // chunk, so only the "last" flag can catch this.
        assert!(open(&sealed[..HEADER_LENGTH + chunk], PASSWORD).is_err());
        assert!(open(&sealed[..HEADER_LENGTH + 2 * chunk], PASSWORD).is_err());
    }

    #[test]
    fn reordered_and_appended_chunks_are_detected() {
        let sealed = seal(&data(3 * SMALL), SMALL);
        let chunk = SMALL + TAG_LENGTH;

        let mut swapped = sealed.clone();
        let (a, b) = swapped[HEADER_LENGTH..].split_at_mut(chunk);
        a.swap_with_slice(&mut b[..chunk]);
        assert!(open(&swapped, PASSWORD).is_err());

        let mut appended = sealed.clone();
        appended.extend_from_slice(&sealed[HEADER_LENGTH..HEADER_LENGTH + chunk]);
        assert!(open(&appended, PASSWORD).is_err());

        let mut trailing = sealed;
        trailing.push(0);
        assert!(open(&trailing, PASSWORD).is_err());
    }

    #[test]
    fn every_header_and_body_bit_is_authenticated() {
        let sealed = seal(&data(SMALL + 5), SMALL);
        for i in 0..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 0x01;
            assert!(
                open(&tampered, PASSWORD).is_err(),
                "flipping byte {} went unnoticed",
                i
            );
        }
    }

    #[test]
    fn hostile_header_values_are_rejected() {
        let sealed = seal(&data(10), SMALL);

        let mut huge_memory = sealed.clone();
        huge_memory[7..11].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(open(&huge_memory, PASSWORD).is_err());

        let mut huge_chunk = sealed.clone();
        huge_chunk[70..74].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(open(&huge_chunk, PASSWORD).is_err());

        let mut zero_chunk = sealed;
        zero_chunk[70..74].copy_from_slice(&0u32.to_le_bytes());
        assert!(open(&zero_chunk, PASSWORD).is_err());
    }
}
