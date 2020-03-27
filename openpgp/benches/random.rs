use criterion::{black_box, criterion_group, criterion_main, AxisScale, Criterion, BenchmarkId, PlotConfiguration};

use sequoia_openpgp::crypto;
use sequoia_openpgp::parse::Parse;

fn test_random() {
    let mut buf = vec![0; 32];
    crypto::random(&mut buf);
}

fn bench_random(c: &mut Criterion) {
    c.bench_function("crypto::random", |b| b.iter(|| test_random() ));
}

criterion_group!(benches, bench_random);
criterion_main!(benches);
