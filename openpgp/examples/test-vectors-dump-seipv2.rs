/// Decrypts asymmetrically-encrypted OpenPGP messages using the
/// openpgp crate, Sequoia's low-level API.

use std::io::{self, Read, Write};

use anyhow::Context;

use sequoia_openpgp as openpgp;

use openpgp::packet::prelude::*;
use openpgp::crypto::{S2K, SessionKey};
use openpgp::types::*;
use openpgp::parse::{
    Parse,
    PacketParser,
    stream::{
        DecryptionHelper,
        DecryptorBuilder,
        VerificationHelper,
        MessageStructure,
    },
};
use openpgp::policy::StandardPolicy as P;
use openpgp::fmt::hex::dump_rfc;
use openpgp::{
    Result,
    serialize::MarshalInto,
};

pub fn main() -> openpgp::Result<()> {
    let p = &P::new();

    let mut m = Vec::new();
    io::stdin().read_to_end(&mut m)?;

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor =
        DecryptorBuilder::from_reader(io::Cursor::new(&m))?
        .mapping(true)
        .with_policy(p, None, Helper::default())?;

    // Finally, stream the decrypted data to stdout.
    io::copy(&mut decryptor, &mut io::sink())
        .context("Decryption failed")?;

    eprintln!("### Complete AEAD-EAX encrypted packet sequence\n");
    eprintln!("~~~");
    io::stderr().write_all(&m)?;
    eprintln!("~~~");
    Ok(())
}

/// This helper provides secrets for the decryption, fetches public
/// keys for the signature verification and implements the
/// verification policy.
#[derive(Default)]
struct Helper {
    bytes: Vec<u8>,
    seip: Option<SEIP2>,
}

impl DecryptionHelper for Helper {
    fn decrypt<D>(&mut self,
                  _pkesks: &[openpgp::packet::PKESK],
                  skesks: &[openpgp::packet::SKESK],
                  _sym_algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D)
                  -> openpgp::Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        eprintln!("### Sample Parameters\n");
        for skesk in skesks {
            let skesk5 = if let SKESK::V5(v5) = skesk { v5 } else { panic!() };
            if let S2K::Iterated { hash, salt, hash_bytes } = skesk5.s2k() {
                eprintln!("S2K:\n\n      Iterated and Salted S2K\n");
                assert_eq!(*hash, HashAlgorithm::SHA256);
                assert_eq!(*hash_bytes, 65011712);
                eprintln!("Iterations:\n\n      65011712 (255), SHA2-256\n");
                dump_rfc("Salt", salt);
            } else {
                panic!("unexpected {:?}", skesk);
            };

            eprintln!("### Sample symmetric-key encrypted session key packet (v5)\n");
            let b = Packet::from(skesk5.clone()).to_vec()?;
            dump_rfc("Packet header", &b[..2]);
            dump_rfc("Version, algorithms, S2K fields", &b[2..2 + 0x12]);
            dump_rfc("Nonce", skesk5.aead_iv());
            dump_rfc("Encrypted session key and AEAD tag", skesk5.esk());

            eprintln!("### Starting AEAD-EAX decryption of the session key\n");
            let (algo, session_key) = skesk.decrypt(&"password".into())?;

            eprintln!("### Sample v2 SEIPD packet\n");
            let b = &self.bytes;
            let seip = self.seip.as_ref().unwrap();
            dump_rfc("Packet header", &b[..2]);
            dump_rfc("Version, AES-128, EAX, Chunk size octet", &b[2..2 + 4]);
            dump_rfc("Salt", seip.salt()); // XXX
            let tag_size = seip.aead().digest_size()?;
            dump_rfc("Chunk #0 encrypted data",
                     &b[2 + 4 + seip.salt().len()..b.len() - 2 * tag_size]);
            dump_rfc("Chunk #0 authentication tag",
                     &b[b.len() - 2 * tag_size..b.len() - 1 * tag_size]);
            dump_rfc("Final (zero-sized chunk #1) authentication tag",
                     &b[b.len() - 1 * tag_size..b.len() - 0 * tag_size]);

            let r = decrypt(algo, &session_key);
            assert!(r);
            break;
        }

        Ok(None)
     }
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                       -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new()) // Feed the Certs to the verifier here.
    }
    fn check(&mut self, _structure: MessageStructure)
             -> openpgp::Result<()> {
        Ok(()) // Implement your verification policy here.
    }
    fn inspect(&mut self, pp: &PacketParser<'_>) -> Result<()> {
        match &pp.packet {
            Packet::SEIP(SEIP::V2(seip)) => {
                let b: Vec<u8> =
                    pp.map().unwrap().iter().flat_map(|e| e.as_bytes().iter().cloned()).collect();
                self.bytes = b;
                self.seip = Some(seip.clone());
            },
            _ => (),
        }
        Ok(())
    }
}
