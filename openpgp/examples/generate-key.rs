use std::env;
use std::io;
extern crate time;
extern crate openpgp;
extern crate nettle;

use openpgp::{
    armor,
    packet::Tag,
    Key,
    SecretKey,
    UserID,
    Signature,
    mpis::{MPI, MPIs},
    constants::{
        Curve,
        HashAlgorithm,
        PublicKeyAlgorithm,
        SignatureType,
        SymmetricAlgorithm,
    },
    subpacket::KeyFlags,
    serialize::Serialize,
    serialize::SerializeKey,
};
use nettle::{curve25519, ed25519};

fn new_rsa_key() -> Key {
    let mut rng = nettle::Yarrow::default();
    let (pubkey, seckey) = nettle::rsa::generate_keypair(&mut rng, 2048).unwrap();
    let mut key = Key::new()
        .pk_algo(PublicKeyAlgorithm::RSAEncryptSign);
    key.mpis = MPIs::RSAPublicKey {
        e: MPI::new(&pubkey.e()),
        n: MPI::new(&pubkey.n()),
    };
    let (p, q, inv) = seckey.as_rfc4880();
    key.secret = Some(SecretKey::Unencrypted {
        mpis: MPIs::RSASecretKey {
            d: MPI::new(&seckey.d()),
            p: MPI::new(&p),
            q: MPI::new(&q),
            u: MPI::new(&inv),
        },
    });
    key
}

fn new_cv25519_key() -> Key {
    let mut rng = nettle::Yarrow::default();
    let mut seckey = [0; curve25519::CURVE25519_SIZE];
    rng.random(&mut seckey);
    // Note: Nettle ignores the most significant and the three
    // least significant bits, therefore every value is a valid
    // secret key.

    // However, let's be nice and make sure the secret key is nice and
    // proper.
    seckey[0] &= 248;
    seckey[31] &= 127;
    seckey[31] |= 64;

    // Compute the public key.  We need to add an encoding
    // octet in front of the key.
    #[allow(non_snake_case)]
    let mut pubkey = [0; 1 + curve25519::CURVE25519_SIZE];
    pubkey[0] = 0x40;
    curve25519::mul_g(&mut pubkey[1..], &seckey)
        .expect("buffers are of the wrong size");
    let mut key = Key::new()
        .pk_algo(PublicKeyAlgorithm::ECDH);
    key.mpis = MPIs::ECDHPublicKey {
        curve: Curve::Cv25519,
        q: MPI::new(&pubkey),
        hash: HashAlgorithm::SHA512,
        sym: SymmetricAlgorithm::AES256,
    };

    // XXX: This is so bad :( we need to fix this at the proper place,
    // at serialization/deserialization.  But that is tricky.
    &mut seckey.reverse();
    key.secret = Some(SecretKey::Unencrypted {
        mpis: MPIs::ECDHSecretKey {
            scalar: MPI::new(&seckey),
        },
    });
    key
}

fn new_ed25519_key() -> Key {
    let mut rng = nettle::Yarrow::default();
    let mut seckey = [0; ed25519::ED25519_KEY_SIZE];
    rng.random(&mut seckey);
    // Note: Nettle ignores the most significant and the three
    // least significant bits, therefore every value is a valid
    // secret key.

    // However, let's be nice and make sure the secret key is nice and
    // proper.
    seckey[0] &= 248;
    seckey[31] &= 127;
    seckey[31] |= 64;

    // Compute the public key.  We need to add an encoding
    // octet in front of the key.
    #[allow(non_snake_case)]
    let mut pubkey = [0; 1 + ed25519::ED25519_KEY_SIZE];
    pubkey[0] = 0x40;
    ed25519::public_key(&mut pubkey[1..], &seckey)
        .expect("buffers are of the wrong size");
    let mut key = Key::new()
        .pk_algo(PublicKeyAlgorithm::EdDSA);
    key.mpis = MPIs::EdDSAPublicKey {
        curve: Curve::Ed25519,
        q: MPI::new(&pubkey),
    };
    key.secret = Some(SecretKey::Unencrypted {
        mpis: MPIs::EdDSASecretKey {
            scalar: MPI::new(&seckey),
        },
    });
    key
}

fn main() {
    let usage = "Usage: generate-key rsa|ecc normal|null-uid|no-uid|no-bound-uid|direct-key|two|archive|approx|cert-subkeys";
    let args = env::args().collect::<Vec<String>>();
    let (new_signing_key, new_encryption_key): (fn() -> Key, fn() -> Key)  =
        match args.get(1).expect(usage).as_ref() {
            "rsa" => (new_rsa_key, new_rsa_key),
            "ecc" => (new_ed25519_key, new_cv25519_key),
            _ => panic!(usage),
        };

    let now = time::now() - time::Duration::weeks(4);
    let hash_algo = HashAlgorithm::SHA512;
    let mut sink = armor::Writer::new(io::stdout(), armor::Kind::SecretKey);
    let primary = new_signing_key()
        .creation_time(now);
    let primary_secret = if let Some(SecretKey::Unencrypted{ mpis: ref sec }) = primary.secret {
        sec
    } else {
        unreachable!()
    };

    match args.get(2)
        .expect(usage).as_ref()
    {
        "normal" => {
            let uid = UserID::new()
                .userid_from_bytes(b"Joe Sixpack <joe@example.org>");
            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            uid.hash(&mut hash);
            let mut sig = Signature::new(SignatureType::PositiveCertificate);
            sig.set_key_flags(&KeyFlags::default().set_certify(true).set_sign(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_userid_binding(&primary, &primary, &uid).unwrap(),
                       true);

            primary.serialize(&mut sink, Tag::SecretKey).unwrap();
            uid.serialize(&mut sink).unwrap();
            sig.serialize(&mut sink).unwrap();

            let enc = new_encryption_key()
                .creation_time(now);

            let mut sig = Signature::new(SignatureType::SubkeyBinding);
            sig.set_key_flags(&KeyFlags::default()
                              .set_encrypt_at_rest(true)
                              .set_encrypt_for_transport(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            enc.hash(&mut hash);
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_subkey_binding(&primary, &primary, &enc).unwrap(),
                       true);

            enc.serialize(&mut sink, Tag::SecretSubkey).unwrap();
            sig.serialize(&mut sink).unwrap();
        },

        "null-uid" => {
            let uid = UserID::new();
            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            uid.hash(&mut hash);
            let mut sig = Signature::new(SignatureType::PositiveCertificate);
            sig.set_key_flags(&KeyFlags::default().set_certify(true).set_sign(true)).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_userid_binding(&primary, &primary, &uid).unwrap(),
                       true);

            primary.serialize(&mut sink, Tag::SecretKey).unwrap();
            uid.serialize(&mut sink).unwrap();
            sig.serialize(&mut sink).unwrap();

            let enc = new_encryption_key()
                .creation_time(now);

            let mut sig = Signature::new(SignatureType::SubkeyBinding);
            sig.set_key_flags(&KeyFlags::default()
                              .set_encrypt_at_rest(true)
                              .set_encrypt_for_transport(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            enc.hash(&mut hash);
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_subkey_binding(&primary, &primary, &enc).unwrap(),
                       true);

            enc.serialize(&mut sink, Tag::SecretSubkey).unwrap();
            sig.serialize(&mut sink).unwrap();
        },

        "no-uid" => {
            primary.serialize(&mut sink, Tag::SecretKey).unwrap();

            let enc = new_encryption_key()
                .creation_time(now);

            let mut sig = Signature::new(SignatureType::SubkeyBinding);
            sig.set_key_flags(&KeyFlags::default()
                              .set_encrypt_at_rest(true)
                              .set_encrypt_for_transport(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            enc.hash(&mut hash);
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_subkey_binding(&primary, &primary, &enc).unwrap(),
                       true);

            enc.serialize(&mut sink, Tag::SecretSubkey).unwrap();
            sig.serialize(&mut sink).unwrap();
        },

        "no-bound-uid" => {
            primary.serialize(&mut sink, Tag::SecretKey).unwrap();
            let uid = UserID::new()
                .userid_from_bytes(b"Unbound UID <unbound@example.org>");
            uid.serialize(&mut sink).unwrap();

            let enc = new_encryption_key()
                .creation_time(now);

            let mut sig = Signature::new(SignatureType::SubkeyBinding);
            sig.set_key_flags(&KeyFlags::default()
                              .set_encrypt_at_rest(true)
                              .set_encrypt_for_transport(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            enc.hash(&mut hash);
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_subkey_binding(&primary, &primary, &enc).unwrap(),
                       true);

            enc.serialize(&mut sink, Tag::SecretSubkey).unwrap();
            sig.serialize(&mut sink).unwrap();
        },

        "direct-key" => {
            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            let mut sig = Signature::new(SignatureType::DirectKey);
            sig.set_key_flags(&KeyFlags::default().set_certify(true).set_sign(true)).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_primary_key_binding(&primary, &primary).unwrap(),
                       true);

            primary.serialize(&mut sink, Tag::SecretKey).unwrap();
            sig.serialize(&mut sink).unwrap();

            let enc = new_encryption_key()
                .creation_time(now);

            let mut sig = Signature::new(SignatureType::SubkeyBinding);
            sig.set_key_flags(&KeyFlags::default()
                              .set_encrypt_at_rest(true)
                              .set_encrypt_for_transport(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            enc.hash(&mut hash);
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_subkey_binding(&primary, &primary, &enc).unwrap(),
                       true);

            enc.serialize(&mut sink, Tag::SecretSubkey).unwrap();
            sig.serialize(&mut sink).unwrap();
        },

        "two" => {
            let uid = UserID::new()
                .userid_from_bytes(b"Two Fish <two@example.org>");
            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            uid.hash(&mut hash);
            let mut sig = Signature::new(SignatureType::PositiveCertificate);
            sig.set_key_flags(&KeyFlags::default().set_certify(true).set_sign(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_userid_binding(&primary, &primary, &uid).unwrap(),
                       true);

            primary.serialize(&mut sink, Tag::SecretKey).unwrap();
            uid.serialize(&mut sink).unwrap();
            sig.serialize(&mut sink).unwrap();

            for _ in 0..2 {
                let enc = new_encryption_key()
                    .creation_time(now);

                let mut sig = Signature::new(SignatureType::SubkeyBinding);
                sig.set_key_flags(&KeyFlags::default()
                                  .set_encrypt_at_rest(true)
                                  .set_encrypt_for_transport(true)).unwrap();
                sig.set_signature_creation_time(now).unwrap();
                sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
                sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
                sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

                let mut hash = hash_algo.context().unwrap();
                primary.hash(&mut hash);
                enc.hash(&mut hash);
                sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

                assert_eq!(sig.verify_subkey_binding(&primary, &primary, &enc).unwrap(),
                           true);

                enc.serialize(&mut sink, Tag::SecretSubkey).unwrap();
                sig.serialize(&mut sink).unwrap();
            }
        },

        "archive" => {
            let uid = UserID::new()
                .userid_from_bytes(b"Barbara Bookworm <barbara@example.org>");

            let mut sig = Signature::new(SignatureType::PositiveCertificate);
            sig.set_key_flags(&KeyFlags::default().set_certify(true).set_sign(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            uid.hash(&mut hash);
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_userid_binding(&primary, &primary, &uid).unwrap(),
                       true);

            primary.serialize(&mut sink, Tag::SecretKey).unwrap();
            uid.serialize(&mut sink).unwrap();
            sig.serialize(&mut sink).unwrap();

            let archive = new_encryption_key()
                .creation_time(now);

            let mut sig = Signature::new(SignatureType::SubkeyBinding);
            sig.set_key_flags(&KeyFlags::default().set_encrypt_at_rest(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            archive.hash(&mut hash);
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_subkey_binding(&primary, &primary, &archive).unwrap(),
                       true);

            archive.serialize(&mut sink, Tag::SecretSubkey).unwrap();
            sig.serialize(&mut sink).unwrap();

            let weekly = new_encryption_key()
                .creation_time(now);

            let mut sig = Signature::new(SignatureType::SubkeyBinding);
            sig.set_key_flags(&KeyFlags::default().set_encrypt_for_transport(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            weekly.hash(&mut hash);
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_subkey_binding(&primary, &primary, &weekly).unwrap(),
                       true);

            weekly.serialize(&mut sink, Tag::SecretSubkey).unwrap();
            sig.serialize(&mut sink).unwrap();
        },

        "approx" => {
            let uid = UserID::new()
                .userid_from_bytes(b"Futura Proofa <futura@example.org>");

            let mut sig = Signature::new(SignatureType::PositiveCertificate);
            sig.set_key_flags(&KeyFlags::default().set_certify(true).set_sign(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            uid.hash(&mut hash);
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_userid_binding(&primary, &primary, &uid).unwrap(),
                       true);

            primary.serialize(&mut sink, Tag::SecretKey).unwrap();
            uid.serialize(&mut sink).unwrap();
            sig.serialize(&mut sink).unwrap();

            for i in 0..52 {
                // Reverse the order, putting the earlier keys at the
                // end.  This is to prevent implementations merely
                // picking the first key instead of looking at
                // timestamps.
                let i = 51 - i;
                let weekly = new_encryption_key()
                    .creation_time(now + time::Duration::weeks(i));

                let mut sig = Signature::new(SignatureType::SubkeyBinding);
                sig.set_key_flags(&KeyFlags::default().set_encrypt_for_transport(true)).unwrap();
                sig.set_signature_creation_time(now + time::Duration::weeks(i)).unwrap();
                sig.set_key_expiration_time(Some(time::Duration::weeks(1))).unwrap();
                sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
                sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();

                let mut hash = hash_algo.context().unwrap();
                primary.hash(&mut hash);
                weekly.hash(&mut hash);
                sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

                assert_eq!(sig.verify_subkey_binding(&primary, &primary, &weekly).unwrap(),
                           true);

                weekly.serialize(&mut sink, Tag::SecretSubkey).unwrap();
                sig.serialize(&mut sink).unwrap();
            }
        },

        "cert-subkeys" => {
            let uid = UserID::new()
                .userid_from_bytes(b"Recur Sive <recur@example.org>");
            let mut hash = hash_algo.context().unwrap();
            primary.hash(&mut hash);
            uid.hash(&mut hash);
            let mut sig = Signature::new(SignatureType::PositiveCertificate);
            sig.set_key_flags(&KeyFlags::default().set_certify(true)).unwrap();
            sig.set_signature_creation_time(now).unwrap();
            sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
            sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
            sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();
            sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

            assert_eq!(sig.verify_userid_binding(&primary, &primary, &uid).unwrap(),
                       true);

            primary.serialize(&mut sink, Tag::SecretKey).unwrap();
            uid.serialize(&mut sink).unwrap();
            sig.serialize(&mut sink).unwrap();

            for _ in 0..2 {
                let cert = new_signing_key()
                    .creation_time(now);
                let cert_secret = if let Some(SecretKey::Unencrypted{ mpis: ref sec }) = cert.secret {
                    sec
                } else {
                    unreachable!()
                };

                // create a primary key binding signature
                let mut backsig_hash = hash_algo.context().unwrap();
                primary.hash(&mut backsig_hash);
                cert.hash(&mut backsig_hash);
                let mut backsig = Signature::new(SignatureType::PrimaryKeyBinding);
                backsig.set_signature_creation_time(now).unwrap();
                backsig.set_issuer_fingerprint(cert.fingerprint()).unwrap();
                backsig.set_issuer(cert.fingerprint().to_keyid()).unwrap();
                backsig.sign_hash(&cert, cert_secret, hash_algo, backsig_hash).unwrap();

                assert_eq!(backsig.verify_subkey_binding(&cert, &primary, &cert).unwrap(),
                           true);

                // binding signature
                let mut hash = hash_algo.context().unwrap();
                primary.hash(&mut hash);
                cert.hash(&mut hash);
                let mut sig = Signature::new(SignatureType::SubkeyBinding);
                sig.set_key_flags(&KeyFlags::default().set_certify(true)).unwrap();
                sig.set_signature_creation_time(now).unwrap();
                sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
                sig.set_issuer_fingerprint(primary.fingerprint()).unwrap();
                sig.set_issuer(primary.fingerprint().to_keyid()).unwrap();
                sig.set_embedded_signature(backsig).unwrap();
                sig.sign_hash(&primary, primary_secret, hash_algo, hash).unwrap();

                assert_eq!(sig.verify_subkey_binding(&primary, &primary, &cert).unwrap(),
                           true);

                cert.serialize(&mut sink, Tag::SecretSubkey).unwrap();
                sig.serialize(&mut sink).unwrap();

                let enc = new_encryption_key()
                    .creation_time(now);

                let mut sig = Signature::new(SignatureType::SubkeyBinding);
                sig.set_key_flags(&KeyFlags::default()
                                  .set_encrypt_at_rest(true)
                                  .set_encrypt_for_transport(true)).unwrap();
                sig.set_signature_creation_time(now).unwrap();
                sig.set_key_expiration_time(Some(time::Duration::weeks(52))).unwrap();
                sig.set_issuer_fingerprint(cert.fingerprint()).unwrap();
                sig.set_issuer(cert.fingerprint().to_keyid()).unwrap();

                let mut hash = hash_algo.context().unwrap();
                cert.hash(&mut hash);
                enc.hash(&mut hash);
                sig.sign_hash(&cert, cert_secret, hash_algo, hash).unwrap();

                assert_eq!(sig.verify_subkey_binding(&cert, &cert, &enc).unwrap(),
                           true);

                enc.serialize(&mut sink, Tag::SecretSubkey).unwrap();
                sig.serialize(&mut sink).unwrap();
            }
        },

        _ => panic!("unknown action"),
    }
}
