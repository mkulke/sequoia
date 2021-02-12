use criterion::{
    criterion_group, BenchmarkGroup, BenchmarkId, Criterion, Throughput,
};

use sequoia_openpgp::cert::{Cert, CertBuilder, CipherSuite};
use sequoia_openpgp::packet::{Signature, UserID};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::SerializeInto;
use sequoia_openpgp::types::{KeyFlags, SignatureType};
use sequoia_openpgp::Result;

use std::convert::TryInto;

fn generate_certifications<'a>(
    userid: &'a UserID,
    cert: &'a Cert,
    count: usize,
) -> Result<impl Iterator<Item = Signature> + 'a> {
    // Generate a Cert, and create a keypair from the primary key.
    let (alice, _) = CertBuilder::new()
        .set_primary_key_flags(KeyFlags::empty().set_certification())
        .add_userid("alice@example.org")
        .set_cipher_suite(CipherSuite::Cv25519)
        .generate()?;
    let mut keypair = alice
        .primary_key()
        .key()
        .clone()
        .parts_into_secret()?
        .into_keypair()?;

    let iter = (0..count).map(move |_| {
        userid
            .certify(
                &mut keypair,
                cert,
                SignatureType::PositiveCertification,
                None,
                None,
            )
            .unwrap()
    });
    Ok(iter)
}

fn generate_flooded_cert(
    cert_count: usize,
    sigs_per_cert: usize,
) -> Result<Vec<u8>> {
    // Generate a Cert for to be flooded
    let (mut floodme, _) = CertBuilder::new()
        .set_primary_key_flags(KeyFlags::empty().set_certification())
        .add_userid("flood.me@example.org")
        .generate()?;

    let userid = floodme.clone();
    let userid = userid.userids().nth(0).unwrap();

    let certs = (0..cert_count)
        .map(|_| {
            generate_certifications(&userid, &floodme, sigs_per_cert).unwrap()
        })
        .flatten()
        .collect::<Vec<Signature>>();

    floodme = floodme.insert_packets(certs)?;
    floodme.export_to_vec()
}

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

fn bench_parse_cert_generated(
    group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    signature_count: usize,
) {
    let bytes = generate_flooded_cert(signature_count/100, 100).unwrap();

    group.throughput(Throughput::Bytes(bytes.len().try_into().unwrap()));

    group.bench_with_input(BenchmarkId::new(name, signature_count), &bytes, |b, bytes| {
        b.iter(|| read_cert(bytes))
    });
}

fn bench_parse_certs(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse flooded cert");
    bench_parse_cert_generated(&mut group, "flooded", 10000);
    group.finish();

    let mut group = c.benchmark_group("parse typical cert");
    bench_parse_cert!("neal.pgp", group);
    group.finish();
}

criterion_group!(benches, bench_parse_certs);
