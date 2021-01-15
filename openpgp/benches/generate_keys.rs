use criterion::{criterion_group, criterion_main, Criterion};

use sequoia_openpgp::cert::{Cert, CertBuilder};

// Borrowed from chapter 01 of the guide
// Generates an signing-capable key.
fn generate_signing() -> sequoia_openpgp::Result<Cert> {
    let (cert, _revocation) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_signing_subkey()
        .generate()?;
    Ok(cert)
}

fn bench_generate_keys(c: &mut Criterion) {
    let mut group = c.benchmark_group("generate keys");
    group.bench_function("signing", |b| b.iter(|| generate_signing()));
    group.finish();
}

criterion_group!(benches, bench_generate_keys);
criterion_main!(benches);
