use criterion::{criterion_group, criterion_main, Criterion};

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};

use std::io::Write;

mod common;
use common::encrypt;

lazy_static::lazy_static! {
    static ref ZEROS_1_MB: Vec<u8> = vec![0; 1 * 1024 * 1024];
    static ref ZEROS_10_MB: Vec<u8> = vec![0; 10 * 1024 * 1024];
}

pub fn encrypt_to_testy(bytes: &[u8]) -> sequoia_openpgp::Result<Vec<u8>> {
    let testy =
        Cert::from_bytes(&include_bytes!("../tests/data/keys/testy.pgp")[..])?;
    encrypt::encrypt_to_cert(bytes, &testy)
}

pub fn encrypt_with_password(bytes: &[u8]) -> sequoia_openpgp::Result<Vec<u8>> {
    let password = "ściśle tajne";
    encrypt::encrypt_with_password(bytes, password)
}

fn bench_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt message");

    // Encrypt a very short message.
    let bytes = b"Hello world.";
    group.bench_function(format!("password {:?}", bytes.len()), |b| {
        b.iter(|| encrypt_with_password(bytes))
    });
    group.bench_function(format!("recipient {:?}", bytes.len()), |b| {
        b.iter(|| encrypt_to_testy(bytes))
    });

    // Encrypt a medium length message.
    let bytes = &ZEROS_1_MB[..];
    group.bench_function(format!("password {:?}", bytes.len()), |b| {
        b.iter(|| encrypt_with_password(bytes))
    });
    group.bench_function(format!("recipient {:?}", bytes.len()), |b| {
        b.iter(|| encrypt_to_testy(bytes))
    });

    // Encrypt a very long message.
    let bytes = &ZEROS_10_MB[..];
    group.bench_function(format!("password {:?}", bytes.len()), |b| {
        b.iter(|| encrypt_with_password(bytes))
    });
    group.bench_function(format!("recipient {:?}", bytes.len()), |b| {
        b.iter(|| encrypt_to_testy(bytes))
    });

    group.finish();
}

criterion_group!(benches, bench_encrypt);
criterion_main!(benches);
