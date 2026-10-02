//! The secret scanner must not panic on any text, and every finding must
//! point at a valid range of the input.
#![no_main]

use cargocrypt::detection::SecretDetector;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static DETECTOR: OnceLock<SecretDetector> = OnceLock::new();

fuzz_target!(|text: &str| {
    let detector = DETECTOR.get_or_init(SecretDetector::new);
    let findings = detector.scan_content(text, "fuzz.env").expect("scan succeeds");
    for f in findings {
        assert!(text
            .get(f.secret.start_position..f.secret.end_position)
            .is_some());
    }
});
