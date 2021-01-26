use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;

use std::convert::TryInto;

fn read_cert(bytes: &[u8]) {
    // Parse the cert, unwrap to notice errors
    Cert::from_bytes(bytes).unwrap();
}

macro_rules! bench_parse_cert {
    ( $filename: expr, $group: expr ) => {
        let bytes = include_bytes!(concat!("../tests/data/keys/", $filename));
        $group.throughput(Throughput::Bytes(bytes.len().try_into().unwrap()));
        $group.bench_function($filename, |b| b.iter(|| read_cert(bytes)));
    };
}
fn bench_parse_certs(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse flooded cert");
    bench_parse_cert!("dkg.gpg", group);
    group.finish();
    let mut group = c.benchmark_group("parse typical cert");
    bench_parse_cert!("neal.pgp", group);
    group.finish();
}

criterion_group!(benches, bench_parse_certs);
criterion_main!(benches);
