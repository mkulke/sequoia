use criterion::{criterion_group, criterion_main, Criterion};

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;

mod common;
use common::decrypt;
use common::encrypt;

static PASSWORD: &'static str = "password";

lazy_static::lazy_static! {
    static ref TESTY: Cert =
        Cert::from_bytes(&include_bytes!("../tests/data/keys/testy-private.pgp")[..])
        .unwrap();
    static ref ZEROS_1_MB: Vec<u8> = vec![0; 1 * 1024 * 1024];
    static ref ZEROS_10_MB: Vec<u8> = vec![0; 10 * 1024 * 1024];
}


fn decrypt_cert(bytes: &[u8], cert: &Cert) {
    let mut sink = Vec::new();
    decrypt::decrypt_with_cert(&mut sink, &bytes, cert).unwrap();
}

fn decrypt_password(bytes: &[u8]) {
    let mut sink = Vec::new();
    decrypt::decrypt_with_password(&mut sink, &bytes, PASSWORD).unwrap();
    // TODO test to ensure decryption was successful
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt message");

    // Encrypt a very short, medium and very long message,
    // and then benchmark decryption.
    let messages = [b"Hello world.", &ZEROS_1_MB[..], &ZEROS_10_MB[..]];

    // Encrypt and decrypt with password
    messages
        .iter()
        .map(|m| encrypt::encrypt_with_password(m, PASSWORD).unwrap())
        .for_each(|encrypted| {
            group.bench_function(format!("password {:?}", encrypted.len()), |b| {
                b.iter(|| decrypt_password(&encrypted))
            });
        });

    // Encrypt and decrypt with a cert
    messages
        .iter()
        .map(|m| encrypt::encrypt_to_cert(m, &TESTY).unwrap())
        .for_each(|encrypted| {
            group.bench_function(format!("cert {:?}", encrypted.len()), |b| {
                b.iter(|| decrypt_cert(&encrypted, &TESTY))
            });
        });

    group.finish();
}

criterion_group!(benches, bench_decrypt);
criterion_main!(benches);
