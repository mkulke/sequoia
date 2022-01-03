use std::fs::{self, File};
use std::io;

use assert_cli::Assert;
use tempfile::TempDir;

use sequoia_openpgp as openpgp;
use crate::openpgp::{Packet, PacketPile, Cert};
use crate::openpgp::crypto::KeyPair;
use crate::openpgp::packet::key::SecretKeyMaterial;
use crate::openpgp::packet::signature::subpacket::NotationData;
use crate::openpgp::packet::signature::subpacket::NotationDataFlags;
use crate::openpgp::types::{CompressionAlgorithm, SignatureType};
use crate::openpgp::parse::Parse;
use crate::openpgp::serialize::stream::{Message, Signer, Compressor, LiteralWriter};

fn artifact(filename: &str) -> String {
    format!("tests/data/{}", filename)
}

#[test]
fn sq_sign() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign message.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--signer-key",
              &artifact("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/dennis-simon-anton.pgp"),
              &sig.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_with_notations() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign message.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--signer-key",
              &artifact("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              "--notation", "foo", "bar",
              "--notation", "!foo", "xyzzy",
              "--notation", "hello@example.org", "1234567890",
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);

        eprintln!("{:?}", sig);

        let hr = NotationDataFlags::empty().set_human_readable();
        let notations = &mut [
            (NotationData::new("foo", "bar", hr.clone()), false),
            (NotationData::new("foo", "xyzzy", hr.clone()), false),
            (NotationData::new("hello@example.org", "1234567890", hr), false)
        ];

        for n in sig.notation_data() {
            if n.name() == "salt@notations.sequoia-pgp.org" {
                continue;
            }

            for (m, found) in notations.iter_mut() {
                if n == m {
                    assert!(!*found);
                    *found = true;
                }
            }
        }
        for (n, found) in notations.iter() {
            assert!(found, "Missing: {:?}", n);
        }
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["--known-notation", "foo",
              "verify",
              "--signer-cert",
              &artifact("keys/dennis-simon-anton.pgp"),
              &sig.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_append() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Sign message.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--signer-key",
              &artifact("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig0.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/dennis-simon-anton.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();

    // Now add a second signature with --append.
    let sig1 = tmp_dir.path().join("sig1");
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--append",
              "--signer-key",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig1.to_string_lossy(),
              &sig0.to_string_lossy()])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig1).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig1).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both signatures of the signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/dennis-simon-anton.pgp"),
              &sig1.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig1.to_string_lossy()])
        .unwrap();
}

#[test]
#[allow(unreachable_code)]
fn sq_sign_append_on_compress_then_sign() {
    use crate::openpgp::policy::StandardPolicy as P;

    let p = &P::new();
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // This is quite an odd scheme, so we need to create such a
    // message by foot.
    let tsk = Cert::from_file(&artifact("keys/dennis-simon-anton-private.pgp"))
        .unwrap();
    let key = tsk.keys().with_policy(p, None).for_signing().next().unwrap().key();
    let sec = match key.optional_secret() {
        Some(SecretKeyMaterial::Unencrypted(ref u)) => u.clone(),
        _ => unreachable!(),
    };
    let keypair = KeyPair::new(key.clone(), sec).unwrap();
    let signer = Signer::new(Message::new(File::create(&sig0).unwrap()),
                             keypair).build().unwrap();
    let compressor = Compressor::new(signer)
        .algo(CompressionAlgorithm::Uncompressed)
        .build().unwrap();
    let mut literal = LiteralWriter::new(compressor).build()
        .unwrap();
    io::copy(
        &mut File::open(&artifact("messages/a-cypherpunks-manifesto.txt")).unwrap(),
        &mut literal)
        .unwrap();
    literal.finalize()
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 3);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::CompressedData(_) = packets[1] {
        // Do nothing.
    } else {
        panic!("expected compressed data");
    }
    if let Packet::Signature(ref sig) = packets[2] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    // Verify signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/dennis-simon-anton.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();

    // Now add a second signature with --append.
    let sig1 = tmp_dir.path().join("sig1");
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--append",
              "--signer-key",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig1.to_string_lossy(),
              &sig0.to_string_lossy()])
        .fails() // XXX: Currently, this is not implemented.
        .unwrap();

    // XXX: Currently, this is not implemented in sq.
    return;

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig1).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::CompressedData(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected compressed data");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig1).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both signatures of the signed message.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/dennis-simon-anton.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_detached() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign detached.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--detached",
              "--signer-key",
              &artifact("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 1);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify detached.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/dennis-simon-anton.pgp"),
              "--detached",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();
}

#[test]
fn sq_sign_detached_append() {
    let tmp_dir = TempDir::new().unwrap();
    let sig = tmp_dir.path().join("sig0");

    // Sign detached.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--detached",
              "--signer-key",
              &artifact("keys/dennis-simon-anton-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 1);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify detached.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/dennis-simon-anton.pgp"),
              "--detached",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that we don't blindly overwrite signatures.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--detached",
              "--signer-key",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .fails()
        .unwrap();

    // Now add a second signature with --append.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--detached",
              "--append",
              "--signer-key",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 2);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[1] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP SIGNATURE-----\n\n"));

    // Verify both detached signatures.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/dennis-simon-anton.pgp"),
              "--detached",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              "--detached",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .unwrap();

    // Finally, check that we don't truncate the file if something
    // goes wrong.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--detached",
              "--append",
              "--signer-key",
              // Not a private key => signing will fail.
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp521.pgp"),
              "--output",
              &sig.to_string_lossy(),
              &artifact("messages/a-cypherpunks-manifesto.txt")])
        .fails()
        .unwrap();

    // Check that the content is still sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig).unwrap().into_children().collect();
    assert_eq!(packets.len(), 2);
    if let Packet::Signature(ref sig) = packets[0] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[1] {
        assert_eq!(sig.typ(), SignatureType::Binary);
    } else {
        panic!("expected signature");
    }
}

// Notarizations ahead.

#[test]
fn sq_sign_append_a_notarization() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--append",
              "--signer-key",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig0.to_string_lossy(),
              &artifact("messages/signed-1-notarized-by-ed25519.pgp")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 7);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(! ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[2] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[3] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[5] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[6] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/neal.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_notarize() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--notarize",
              "--signer-key",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig0.to_string_lossy(),
              &artifact("messages/signed-1.gpg")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 5);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[2] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[3] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/neal.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
}

#[test]
fn sq_sign_notarize_a_notarization() {
    let tmp_dir = TempDir::new().unwrap();
    let sig0 = tmp_dir.path().join("sig0");

    // Now add a third signature with --append to a notarized message.
    Assert::cargo_binary("sq")
        .with_args(
            &["sign",
              "--notarize",
              "--signer-key",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256-private.pgp"),
              "--output",
              &sig0.to_string_lossy(),
              &artifact("messages/signed-1-notarized-by-ed25519.pgp")])
        .unwrap();

    // Check that the content is sane.
    let packets: Vec<Packet> =
        PacketPile::from_file(&sig0).unwrap().into_children().collect();
    assert_eq!(packets.len(), 7);
    if let Packet::OnePassSig(ref ops) = packets[0] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[1] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::OnePassSig(ref ops) = packets[2] {
        assert!(ops.last());
        assert_eq!(ops.typ(), SignatureType::Binary);
    } else {
        panic!("expected one pass signature");
    }
    if let Packet::Literal(_) = packets[3] {
        // Do nothing.
    } else {
        panic!("expected literal");
    }
    if let Packet::Signature(ref sig) = packets[4] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 0);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[5] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 1);
    } else {
        panic!("expected signature");
    }
    if let Packet::Signature(ref sig) = packets[6] {
        assert_eq!(sig.typ(), SignatureType::Binary);
        assert_eq!(sig.level(), 2);
    } else {
        panic!("expected signature");
    }

    let content = fs::read(&sig0).unwrap();
    assert!(&content[..].starts_with(b"-----BEGIN PGP MESSAGE-----\n\n"));

    // Verify both notarizations and the signature.
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/neal.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
    Assert::cargo_binary("sq")
        .with_args(
            &["verify",
              "--signer-cert",
              &artifact("keys/erika-corinna-daniela-simone-antonia-nistp256.pgp"),
              &sig0.to_string_lossy()])
        .unwrap();
}
