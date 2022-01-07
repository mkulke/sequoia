use std::io::{self, Write};

use anyhow::Context;

use sequoia_openpgp as openpgp;

use openpgp::{
    crypto::*,
    fmt::hex,
    packet::prelude::*,
    serialize::{Serialize, stream::*},
    types::*,
};

const PASSWORD: &str = "password";
const MESSAGE: &[u8] = b"Hello, world!";

fn main() -> openpgp::Result<()> {
    let password = PASSWORD.into();

    for sym_algo in &[SymmetricAlgorithm::AES128,
                      SymmetricAlgorithm::AES192,
                      SymmetricAlgorithm::AES256] {
        let sk = SessionKey::new(sym_algo.key_size()?);

        let mut sink = io::stdout();
        let message = Message::new(&mut sink);
        let mut message = Armorer::new(message)
            .add_header("Comment", format!("Encrypted using {}", sym_algo))
            .add_header("Comment", format!("Session key: {}", hex::encode(&sk)))
            .build()?;

        let mut salt = Default::default();
        openpgp::crypto::random(&mut salt);
        let skesk4 = SKESK4::with_password(*sym_algo,
                                           *sym_algo,
                                           S2K::Argon2 {
                                               salt,
                                               t: 1,
                                               p: 4,
                                               m: 21,
                                           },
                                           &sk, &password)?;
        Packet::from(skesk4).serialize(&mut message)?;

        let message = Encryptor::with_session_key(message, *sym_algo, sk)?
            .build().context("Failed to create encryptor")?;

        let mut message = LiteralWriter::new(message).build()
            .context("Failed to create literal writer")?;

        message.write_all(MESSAGE)?;

        // Finally, finalize the OpenPGP message by tearing down the
        // writer stack.
        message.finalize()?;
    }

    Ok(())
}
