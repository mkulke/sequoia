use criterion::{black_box, Throughput, criterion_group, criterion_main, Criterion};

use sequoia_openpgp::crypto;
use sequoia_openpgp::cert::Cert;

use sequoia_openpgp::parse::Parse;

fn run_random(size: usize) {
    let mut buf = vec![0; size];
    crypto::random(&mut buf);
}

fn read_lutz_key() {
    let _lutz = Cert::from_bytes(sequoia_openpgp::tests::key("lutz.gpg")).unwrap();
}

fn read_key(bytes: &[u8]) {

    // copied from cert.rs::test_into_packets
    // Tests that Cert::into_packets() and Cert::serialize(..) agree.
    let _dkg = Cert::from_bytes(bytes);

    //let mut buf = Vec::new();
    //for p in dkg.clone().into_packets() {
    //    p.serialize(&mut buf)?;
    //}
    //let dkg = dkg.to_vec()?;
    //if false && buf != dkg {
    //    std::fs::write("/tmp/buf", &buf)?;
    //    std::fs::write("/tmp/dkg", &dkg)?;
    //}
    //assert_eq!(buf, dkg);
    //Ok(())
}

fn bench_random(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_crypto_random");

    group.sample_size(50);
    for i in (8..33).step_by(8) {
        group.throughput(Throughput::Bytes(i as u64));
        group.bench_function(format!("crypto::random {:02}", i), |b| b.iter(|| run_random(black_box(i)) ));
    };
    group.finish();
}

fn bench_read_keys(c: &mut Criterion) {
    let mut group = c.benchmark_group("read keys");
    let foo = ["dkg.gpg", "lutz.gpg"];
    foo.iter().for_each(|&filename| {
        let bytes = sequoia_openpgp::tests::key(filename);
        group.bench_function(filename, |b| b.iter(|| read_key(bytes)));
    });
    group.finish();
}

criterion_group!(benches, bench_read_keys);
criterion_main!(benches);
