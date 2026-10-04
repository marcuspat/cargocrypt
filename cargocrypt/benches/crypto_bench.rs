//! Benchmarks of what CargoCrypt actually does: key derivation, sealing and
//! opening containers, streaming file encryption and secret scanning.
//!
//! Every number here is a measurement of this crate on the machine running
//! it. There is no comparison against other tools.
//!
//! ```text
//! cargo bench --bench crypto_bench
//! ```

use cargocrypt::crypto::stream::{decrypt_stream, encrypt_stream};
use cargocrypt::crypto::{
    DerivedKey, EncryptedSecret, KdfParams, PerformanceProfile, PlaintextSecret,
};
use cargocrypt::detection::SecretDetector;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::Duration;

const PASSWORD: &str = "benchmark-passphrase";
const SALT: [u8; 32] = [7u8; 32];

/// Cheap parameters, so that benchmarks of the cipher are not dominated by
/// the key derivation that precedes it.
const CHEAP_KDF: KdfParams = KdfParams {
    m_cost: 64,
    t_cost: 1,
    p_cost: 1,
};

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 31 % 251) as u8).collect()
}

/// Argon2id cost per profile. Secure and Paranoid are left out by default:
/// they allocate 256 MiB and 1 GiB per iteration.
fn key_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_derivation");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(10));

    for (name, profile) in [
        ("fast", PerformanceProfile::Fast),
        ("balanced", PerformanceProfile::Balanced),
    ] {
        let params = profile.kdf_params();
        group.bench_function(name, |b| {
            b.iter(|| DerivedKey::derive(black_box(PASSWORD), &SALT, params).unwrap())
        });
    }
    group.finish();
}

/// Sealing and opening an in-memory container with an already-derived key.
fn container(c: &mut Criterion) {
    let key = DerivedKey::derive(PASSWORD, &SALT, CHEAP_KDF).unwrap();
    let mut group = c.benchmark_group("container");

    for size in [1024usize, 64 * 1024, 1024 * 1024] {
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("seal", size), &data, |b, data| {
            b.iter(|| {
                EncryptedSecret::encrypt_with_key(
                    PlaintextSecret::from_bytes(data.clone()),
                    &key,
                    None,
                )
                .unwrap()
            })
        });

        let sealed = EncryptedSecret::encrypt_with_key(
            PlaintextSecret::from_bytes(data.clone()),
            &key,
            None,
        )
        .unwrap();
        group.bench_with_input(BenchmarkId::new("open", size), &sealed, |b, sealed| {
            b.iter(|| sealed.decrypt_with_key(&key).unwrap())
        });

        let bytes = sealed.to_bytes().unwrap();
        group.bench_with_input(BenchmarkId::new("parse", size), &bytes, |b, bytes| {
            b.iter(|| EncryptedSecret::from_bytes(black_box(bytes)).unwrap())
        });
    }
    group.finish();
}

/// Streaming file encryption, including its (cheap) key derivation.
fn stream(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream");
    group.sample_size(20);

    for size in [1024 * 1024usize, 16 * 1024 * 1024] {
        let data = payload(size);
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| {
                let mut out = Vec::with_capacity(data.len() + data.len() / 1024);
                encrypt_stream(&mut &data[..], &mut out, PASSWORD, CHEAP_KDF).unwrap();
                out
            })
        });

        let mut sealed = Vec::new();
        encrypt_stream(&mut &data[..], &mut sealed, PASSWORD, CHEAP_KDF).unwrap();
        group.bench_with_input(BenchmarkId::new("decrypt", size), &sealed, |b, sealed| {
            b.iter(|| {
                let mut out = Vec::with_capacity(sealed.len());
                decrypt_stream(&mut &sealed[..], &mut out, PASSWORD).unwrap();
                out
            })
        });
    }
    group.finish();
}

/// Secret scanning over source-like text.
fn scan(c: &mut Criterion) {
    let detector = SecretDetector::new();
    let line = "    let encrypted: EncryptedSecret = EncryptedSecret::from_bytes(&serialized)?;\n";
    let text = line.repeat(2000);

    let mut group = c.benchmark_group("scan");
    group.sample_size(20);
    group.throughput(Throughput::Bytes(text.len() as u64));
    group.bench_function("source_text", |b| {
        b.iter(|| detector.scan_content(black_box(&text), "lib.rs").unwrap())
    });
    group.finish();
}

criterion_group!(benches, key_derivation, container, stream, scan);
criterion_main!(benches);
