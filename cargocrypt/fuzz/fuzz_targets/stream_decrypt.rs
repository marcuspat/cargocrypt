//! The stream decoder must fail cleanly on arbitrary input.
#![no_main]

use cargocrypt::crypto::stream::decrypt_stream;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Keep Argon2 cheap: skip inputs whose header asks for real work. The
    // bounds check on those fields has its own unit test.
    if data.len() >= 19 {
        let field = |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if field(7) > 256 || field(11) > 2 || field(15) > 2 {
            return;
        }
    }
    let mut out = Vec::new();
    let _ = decrypt_stream(&mut &data[..], &mut out, "fuzz");
});
