use criterion::{criterion_group, criterion_main, Criterion};

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;

fn read_key(bytes: &[u8]) {
    // Parse the cert, ignore any errors
    let _ = Cert::from_bytes(bytes);
}

macro_rules! bench_parse_key {
    ( $filename: expr, $group: expr ) => {
        let bytes = include_bytes!(concat!("../tests/data/keys/", $filename));
        $group.bench_function($filename, |b| b.iter(|| read_key(bytes)));
    };
}
fn bench_read_keys(c: &mut Criterion) {
    let mut group = c.benchmark_group("read keys");
    bench_parse_key!("dkg.gpg", group);
    bench_parse_key!("neal.pgp", group);
    group.finish();
}

criterion_group!(benches, bench_read_keys);
criterion_main!(benches);
