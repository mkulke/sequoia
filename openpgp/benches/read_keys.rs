use criterion::{criterion_group, criterion_main, Criterion};

use sequoia_openpgp::cert::Cert;
use sequoia_openpgp::parse::Parse;

fn read_key(bytes: &[u8]) {
    let _ = Cert::from_bytes(bytes);
}

//fn bench_random(c: &mut Criterion) {
//    let mut group = c.benchmark_group("bench_crypto_random");
//
//    group.sample_size(50);
//    for i in (8..33).step_by(8) {
//        group.throughput(Throughput::Bytes(i as u64));
//        group.bench_function(format!("crypto::random {:02}", i), |b| b.iter(|| run_random(black_box(i)) ));
//    };
//    group.finish();
//}

macro_rules! bench_parse_key {
    ( $filename: expr, $group: expr ) => {
        let bytes = include_bytes!(concat!("../tests/data/keys/", $filename));
        $group.bench_function($filename, |b| b.iter(|| read_key(bytes)));
    }

}
fn bench_read_keys(c: &mut Criterion) {
    let mut group = c.benchmark_group("read keys");
    bench_parse_key!("dkg.gpg", group);
    bench_parse_key!("lutz.gpg", group);
    group.finish();
}

criterion_group!(benches, bench_read_keys);
criterion_main!(benches);
