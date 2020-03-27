use criterion::{black_box, criterion_group, criterion_main, AxisScale, Criterion, BenchmarkId, PlotConfiguration};

use sequoia_openpgp::crypto;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::cert::{CertBuilder, Cert};
use sequoia_openpgp::policy::{Policy, StandardPolicy};
use std::io::Write;
use sequoia_openpgp::serialize::stream::{Message, Encryptor, LiteralWriter};

fn run_random(size: usize) {
    let mut buf = vec![0; size];
    crypto::random(&mut buf);
}

/// Encrypts the given message.
fn encrypt(policy: &dyn Policy,
           sink: &mut Write, plaintext: &str, recipient: &Cert)
           -> sequoia_openpgp::Result<()> {
    // Build a vector of recipients to hand to Encryptor.
    let mut recipients =
        recipient.keys().with_policy(policy, None).alive().revoked(false)
            .for_transport_encryption()
            .map(|ka| ka.key().into())
            .collect::<Vec<_>>();

    // Start streaming an OpenPGP message.
    let message = Message::new(sink);

    // We want to encrypt a literal data packet.
    let mut encryptor = Encryptor::for_recipient(
        message, recipients.pop().expect("No encryption key found"));
    for r in recipients {
        encryptor = encryptor.add_recipient(r)
    }
    let encryptor = encryptor.build().expect("Failed to create encryptor");

    // Emit a literal data packet.
    let mut literal_writer = LiteralWriter::new(encryptor).build()?;

    // Encrypt the data.
    literal_writer.write_all(plaintext.as_bytes())?;

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    literal_writer.finalize()?;

    Ok(())
}

fn run_random_use_case() {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_transport_encryption_subkey()
        .generate().unwrap();

    let p = StandardPolicy::new();
    let mut ciphertext = Vec::new();
    encrypt(&p, &mut ciphertext, "foo", &cert);
}

fn bench_random(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_crypto_random");

    //group.sample_size(10);
    for i in (8..33).step_by(8) {
        group.bench_function(format!("crypto::random {:02}", i), |b| b.iter(|| run_random(black_box(i)) ));
    };
    group.finish();
}

fn bench_random_use_case(c: &mut Criterion) {
    c.bench_function("crypto::random create/encrypt", |b| b.iter(|| run_random_use_case() ));
}

criterion_group!(benches, bench_random, bench_random_use_case);
criterion_main!(benches);
