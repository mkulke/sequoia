use criterion::{criterion_group, criterion_main, Criterion};

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;

mod common;
use common::decrypt;
use common::encrypt;

fn decrypt_cert(bytes: &[u8], cert: Cert) {
    let mut sink = Vec::new();
    decrypt::decrypt_with_cert(&mut sink, &bytes, cert).unwrap();
    assert_eq!(sink.as_slice(), b"Hello world.");
}

fn decrypt_password(bytes: &[u8]) {
    let mut sink = Vec::new();
    decrypt::decrypt_with_password(&mut sink, &bytes, "password").unwrap();
    assert_eq!(sink.as_slice(), b"Hello world.");
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("decrypt message");

    // Decrypt a very short message.
    let bytes = b"Hello world.";
    let message = encrypt::encrypt_with_password(bytes, "password").unwrap();

    group.bench_function(format!("password {:?}", message.len()), |b| {
        b.iter(|| decrypt_password(&message))
    });

    let testy =
        Cert::from_bytes(&include_bytes!("../tests/data/keys/testy-private.pgp")[..])
            .unwrap();
    let message = encrypt::encrypt_to_cert(bytes, &testy).unwrap();
    group.bench_function(format!("cert {:?}", bytes.len()), |b| {
        b.iter(|| decrypt_cert(&message, testy.clone()))
    });

    group.finish();
}

criterion_group!(benches, bench_decrypt);
criterion_main!(benches);
