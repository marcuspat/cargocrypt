//! The container parser must reject or accept, never panic, and anything it
//! accepts must serialise back to the same bytes.
#![no_main]

use cargocrypt::crypto::EncryptedSecret;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(secret) = EncryptedSecret::from_bytes(data) {
        let again = secret.to_bytes().expect("a parsed container serialises");
        if EncryptedSecret::has_magic(data) {
            assert_eq!(again, data, "version 2 parsing is canonical");
        }
    }
});
