use criterion::{criterion_group, criterion_main, Criterion};

use sequoia_openpgp::serialize::stream::{Encryptor, LiteralWriter, Message};
use std::io::Write;

lazy_static::lazy_static! {
    static ref ZEROS_1_MB: Vec<u8> = vec![0; 1 * 1024 * 1024];
    static ref ZEROS_10_MB: Vec<u8> = vec![0; 10 * 1024 * 1024];
}

fn encrypt_with_password(bytes: &[u8]) -> sequoia_openpgp::Result<()> {
    let mut sink = vec![];
    let message = Encryptor::with_passwords(
        Message::new(&mut sink),
        Some("ściśle tajne"),
    )
    .build()?;
    let mut w = LiteralWriter::new(message).build()?;
    w.write_all(bytes)?;
    w.finalize()?;
    Ok(())
}

fn bench_encrypt_with_password(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt message");
    let bytes = b"Hello world.";
    group.bench_function(format!("password {:?}", bytes.len()), |b| {
        b.iter(|| encrypt_with_password(bytes))
    });
    let bytes = &ZEROS_1_MB[..];
    group.bench_function(format!("password {:?}", bytes.len()), |b| {
        b.iter(|| encrypt_with_password(bytes))
    });
    let bytes = &ZEROS_10_MB[..];
    group.bench_function(format!("password {:?}", bytes.len()), |b| {
        b.iter(|| encrypt_with_password(bytes))
    });

    group.finish();
}

criterion_group!(benches, bench_encrypt_with_password);
criterion_main!(benches);
