use std::io::{self, Write};

use anyhow::Context;

use sequoia_openpgp as openpgp;

use crate::openpgp::serialize::stream::Armorer;
use crate::openpgp::crypto::*;
use crate::openpgp::types::*;
use crate::openpgp::parse::Parse;
use openpgp::packet::{Packet, Padding};
use crate::openpgp::serialize::{
    Serialize,
    stream::{
        Message, LiteralWriter, Encryptor,
    },
};
use crate::openpgp::policy::StandardPolicy as P;

const MESSAGE: &[u8] = b"Hello, world!";
const BIG_MESSAGE: [u8; 4096 + 13] = [0; 4096 + 13];

const ALICE: &[u8] = b"-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Alice's OpenPGP certificate
Comment: https://www.ietf.org/id/draft-bre-openpgp-samples-01.html

mDMEXEcE6RYJKwYBBAHaRw8BAQdArjWwk3FAqyiFbFBKT4TzXcVBqPTB3gmzlC/U
b7O1u120JkFsaWNlIExvdmVsYWNlIDxhbGljZUBvcGVucGdwLmV4YW1wbGU+iJAE
ExYIADgCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AWIQTrhbtfozp14V6UTmPy
MVUMT0fjjgUCXaWfOgAKCRDyMVUMT0fjjukrAPoDnHBSogOmsHOsd9qGsiZpgRnO
dypvbm+QtXZqth9rvwD9HcDC0tC+PHAsO7OTh1S1TC9RiJsvawAfCPaQZoed8gK4
OARcRwTpEgorBgEEAZdVAQUBAQdAQv8GIa2rSTzgqbXCpDDYMiKRVitCsy203x3s
E9+eviIDAQgHiHgEGBYIACAWIQTrhbtfozp14V6UTmPyMVUMT0fjjgUCXEcE6QIb
DAAKCRDyMVUMT0fjjlnQAQDFHUs6TIcxrNTtEZFjUFm1M0PJ1Dng/cDW4xN80fsn
0QEA22Kr7VkCjeAEC08VSTeV+QFsmz55/lntWkwYWhmvOgE=
=iIGO
-----END PGP PUBLIC KEY BLOCK-----";

fn main() -> openpgp::Result<()> {
    let p = &P::new();
    let aead_algo = AEADAlgorithm::GCM;

    let cert = openpgp::Cert::from_bytes(ALICE).unwrap();
    // Build a list of recipient subkeys.
    let mut recipients = Vec::new();
    // Make sure we add at least one subkey from every
    // certificate.
    let mut found_one = false;
    for key in cert.keys().with_policy(p, None)
        .supported().alive().revoked(false)
        .for_transport_encryption()
    {
        recipients.push(key);
        found_one = true;
    }

    if ! found_one {
        return Err(anyhow::anyhow!("No suitable encryption subkey for {}",
                                   cert));
    }
    assert_eq!(recipients.len(), 1);

    for (_label, plaintext) in &[
        (format!("{:?}", String::from_utf8_lossy(MESSAGE)), MESSAGE),
        (format!("{} zeros", BIG_MESSAGE.len()), &BIG_MESSAGE[..])
    ] {
        for sym_algo in &[SymmetricAlgorithm::AES128,
                          SymmetricAlgorithm::AES192,
                          SymmetricAlgorithm::AES256] {
            let sk = SessionKey::new(sym_algo.key_size()?);
            let mut sink = io::stdout();
            let message = Message::new(&mut sink);
            let message = Armorer::new(message)
                .build()?;

            // We want to encrypt a literal data packet.
            let message = Encryptor::with_session_key(message, *sym_algo, sk)?
                .add_passwords(vec!["password"])
                .aead_algo(aead_algo)
                .build().context("Failed to create encryptor")?;

            let mut message = LiteralWriter::new(message).build()
                .context("Failed to create literal writer")?;

            message.write_all(plaintext)
                .context("Failed to encrypt")?;

            let mut message = message.finalize_one()?.unwrap();
            Packet::from(
                Padding::new(openpgp::serialize::stream::padding::padme(
                plaintext.len() as u64) as usize))
                .serialize(&mut message)?;

            message.finalize()?;

            return Ok(());
        }
    }

    Ok(())
}
