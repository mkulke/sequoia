use criterion::{criterion_group, BenchmarkId, Criterion, Throughput};

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;

use crate::common::{decrypt, encrypt};

lazy_static::lazy_static! {
    static ref SENDER: Cert =
        Cert::from_bytes(&include_bytes!("../tests/data/keys/sender.pgp")[..])
        .unwrap();
    static ref ZEROS_1_MB: Vec<u8> = vec![0; 1 * 1024 * 1024];
    static ref ZEROS_10_MB: Vec<u8> = vec![0; 10 * 1024 * 1024];
}

fn verify(bytes: &[u8], sender: &Cert) {
    let mut sink = Vec::new();
    decrypt::verify(&mut sink, &bytes, sender).unwrap();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify message");

    // Encrypt a very short, medium and very long message,
    // and then benchmark decryption.
    let messages = &[b"Hello world.", &ZEROS_1_MB[..]];

    // Encrypt and decrypt with a cert
    messages
        .iter()
        .map(|m| encrypt::sign(m, &SENDER).unwrap())
        .for_each(|signed| {
            group.throughput(Throughput::Bytes(signed.len() as u64));
            group.bench_with_input(
                BenchmarkId::new("verify", signed.len()),
                &signed,
                |b, s| b.iter(|| verify(&s, &SENDER)),
            );
        });

    group.finish();
}

criterion_group!(benches, bench_verify);
