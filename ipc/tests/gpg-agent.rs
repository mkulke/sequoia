//! Tests gpg-agent interaction.

use std::io::{self, Write};

use anyhow::Context as _;
use futures::StreamExt;

use sequoia_openpgp as openpgp;
use crate::openpgp::{
    packet::{
        Any,
        PKESK,
    },
    PacketPile,
    types::{
        HashAlgorithm,
        SymmetricAlgorithm,
    },
};
use crate::openpgp::crypto::{SessionKey, Decryptor};
use crate::openpgp::parse::{Parse, stream::*};
use crate::openpgp::serialize::{Serialize, stream::*};
use crate::openpgp::cert::prelude::*;
use crate::openpgp::policy::Policy;

use sequoia_ipc as ipc;
use crate::ipc::gnupg::{Context, Agent, KeyPair};

macro_rules! make_context {
    () => {{
        let ctx = match Context::ephemeral() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is GnuPG installed?", e);
                return Ok(());
            },
        };

        std::fs::write(ctx.homedir().unwrap().join("gpg-agent.conf"),
                       "allow-loopback-pinentry\n").unwrap();

        match ctx.start("gpg-agent") {
            Ok(_) => (),
            Err(e) => {
                eprintln!("SKIP: Failed to create GnuPG context: {}\n\
                           SKIP: Is the GnuPG agent installed?", e);
                return Ok(());
            },
        }
        ctx
    }};
}

#[tokio::test]
async fn nop() -> openpgp::Result<()> {
    let ctx = make_context!();
    let mut agent = Agent::connect(&ctx).await.unwrap();
    agent.send("NOP").unwrap();
    let response = agent.collect::<Vec<_>>().await;
    assert_eq!(response.len(), 1);
    response.into_iter().next().unwrap().unwrap();
    Ok(())
}

#[tokio::test]
async fn help() -> openpgp::Result<()>  {
    let ctx = make_context!();
    let mut agent = Agent::connect(&ctx).await.unwrap();
    agent.send("HELP").unwrap();
    let response = agent.collect::<Vec<_>>().await;
    assert!(response.len() > 3);
    response.into_iter().last().unwrap().unwrap();
    Ok(())
}

const MESSAGE: &str = "дружба";
const PASSWORD: &str = "streng geheim";

fn gpg_import(ctx: &Context, what: &[u8]) -> openpgp::Result<()> {
    use std::process::{Command, Stdio};

    let mut gpg = Command::new("gpg")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .arg("--homedir").arg(ctx.homedir().unwrap())
        .arg("--batch")
        .arg("--import")
        .spawn()
        .context("failed to start gpg")?;
    gpg.stdin.as_mut().unwrap().write_all(what)?;
    let output = gpg.wait_with_output()?;

    // We capture stdout and stderr, and use eprintln! so that the
    // output will be captured by Rust's test harness.  This way, the
    // output will be at the right position, instead of out-of-order
    // and garbled by the concurrent tests.
    if ! output.stdout.is_empty() {
        eprintln!("stdout:\n{}", String::from_utf8_lossy(&output.stdout));
    }
    if ! output.stderr.is_empty() {
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&output.stderr));
    }

    let status = output.status;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("gpg --import failed"))
    }
}

#[test]
fn sync_sign() -> openpgp::Result<()> {
    sign()
}

#[test]
fn async_sign() -> openpgp::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        sign()
    })
}

fn sign() -> openpgp::Result<()> {
    use self::CipherSuite::*;
    use openpgp::policy::StandardPolicy as P;

    let p = &P::new();
    let ctx = make_context!();

    for cs in &[RSA2k, Cv25519, P521] {
      for password in vec![None, Some(PASSWORD.into())] {
        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(*cs)
            .add_userid("someone@example.org")
            .add_signing_subkey()
            .set_password(password.clone())
            .generate().unwrap();

        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf)?;

        let mut keypair = KeyPair::new(
            &ctx,
            cert.keys().with_policy(p, None).alive().revoked(false)
                .for_signing().take(1).next().unwrap().key())
            .unwrap();

        if let Some(p) = password.clone() {
            keypair = keypair.with_password(p);
        }

        let mut message = Vec::new();
        {
            // Start streaming an OpenPGP message.
            let message = Message::new(&mut message);

            // We want to sign a literal data packet.
            let signer = Signer::new(message, keypair)
                 // XXX: Is this necessary?  If so, it shouldn't.
                .hash_algo(HashAlgorithm::SHA512).unwrap()
                .build().unwrap();

            // Emit a literal data packet.
            let mut literal_writer = LiteralWriter::new(
                signer).build().unwrap();

            // Sign the data.
            literal_writer.write_all(MESSAGE.as_bytes()).unwrap();

            // Finalize the OpenPGP message to make sure that all data is
            // written.
            literal_writer.finalize().unwrap();
        }

        // Make a helper that that feeds the sender's public key to the
        // verifier.
        let helper = Helper { cert: &cert };

        // Now, create a verifier with a helper using the given Certs.
        let mut verifier = VerifierBuilder::from_bytes(&message)?
            .with_policy(p, None, helper)?;

        // Verify the data.
        let mut sink = Vec::new();
        io::copy(&mut verifier, &mut sink).unwrap();
        assert_eq!(MESSAGE.as_bytes(), &sink[..]);
    }

    struct Helper<'a> {
        cert: &'a openpgp::Cert,
    }

    impl<'a> VerificationHelper for Helper<'a> {
        fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                           -> openpgp::Result<Vec<openpgp::Cert>> {
            // Return public keys for signature verification here.
            Ok(vec![self.cert.clone()])
        }

        fn check(&mut self, structure: MessageStructure)
                 -> openpgp::Result<()> {
            // In this function, we implement our signature verification
            // policy.

            let mut good = false;
            for (i, layer) in structure.into_iter().enumerate() {
                match (i, layer) {
                    // First, we are interested in signatures over the
                    // data, i.e. level 0 signatures.
                    (0, MessageLayer::SignatureGroup { results }) => {
                        // Finally, given a VerificationResult, which only says
                        // whether the signature checks out mathematically, we apply
                        // our policy.
                        match results.into_iter().next() {
                            Some(Ok(_)) => good = true,
                            Some(Err(e)) =>
                                return Err(openpgp::Error::from(e).into()),
                            None => (),
                        }
                    },
                    _ => return Err(anyhow::anyhow!(
                        "Unexpected message structure")),
                }
            }

            if good {
                Ok(()) // Good signature.
            } else {
                Err(anyhow::anyhow!("Signature verification failed"))
            }
        }
      }
    }
    Ok(())
}

#[test]
fn sync_decrypt() -> openpgp::Result<()> {
    decrypt(true)
}

#[test]
fn async_decrypt() -> openpgp::Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        decrypt(false)
    })
}

fn decrypt(also_try_explicit_async: bool) -> openpgp::Result<()> {
    use self::CipherSuite::*;
    use openpgp::policy::StandardPolicy as P;

    let p = &P::new();

    // Make a cert for a second recipient.
    let (other, _) = CertBuilder::new()
        .add_userid("other-recipient@example.org")
        .add_transport_encryption_subkey()
        .generate()?;

    for cs in &[RSA2k, Cv25519, P521] {
      for password in vec![None, Some(PASSWORD.into())] {
        let ctx = make_context!();

        let (cert, _) = CertBuilder::new()
            .set_cipher_suite(*cs)
            .add_userid("someone@example.org")
            .add_transport_encryption_subkey()
            .set_password(password.clone())
            .generate().unwrap();

        let mut buf = Vec::new();
        cert.as_tsk().serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf)?;

        // Import the second recipient.
        let mut buf = Vec::new();
        other.serialize(&mut buf).unwrap();
        gpg_import(&ctx, &buf)?;

        let mut message = Vec::new();
        {
            let recipients =
                [&cert, &other].iter().flat_map(
                    |c| c.keys().with_policy(p, None).alive().revoked(false)
                        .for_transport_encryption()
                        .map(|ka| ka.key()))
                .collect::<Vec<_>>();

            // Start streaming an OpenPGP message.
            let message = Message::new(&mut message);

            // We want to encrypt a literal data packet.
            let encryptor =
                Encryptor2::for_recipients(message, recipients)
                .build().unwrap();

            // Emit a literal data packet.
            let mut literal_writer = LiteralWriter::new(
                encryptor).build().unwrap();

            // Encrypt the data.
            literal_writer.write_all(MESSAGE.as_bytes()).unwrap();

            // Finalize the OpenPGP message to make sure that all data is
            // written.
            literal_writer.finalize().unwrap();
        }

      if also_try_explicit_async {
        // First, test Agent::decrypt.  Using this function we can try
        // multiple decryption requests on the same connection.
        let rt = tokio::runtime::Runtime::new()?;
        let mut agent = rt.block_on(Agent::connect(&ctx))?;
        let pp = PacketPile::from_bytes(&message)?;
        let pkesk_0: &PKESK =
            pp.path_ref(&[0]).unwrap().downcast_ref().unwrap();
        let pkesk_1: &PKESK =
            pp.path_ref(&[1]).unwrap().downcast_ref().unwrap();

        // We only gave the cert to GnuPG, the agent doesn't have the
        // secret.
        let keypair = KeyPair::new(
            &ctx,
            other.keys().with_policy(p, None)
                .for_storage_encryption().for_transport_encryption()
                .take(1).next().unwrap().key())?;
        rt.block_on(agent.decrypt(&keypair, pkesk_1.esk(), None)).unwrap_err();

        // Now try "our" key.
        let mut keypair = KeyPair::new(
            &ctx,
            cert.keys().with_policy(p, None)
                .for_storage_encryption().for_transport_encryption()
                .take(1).next().unwrap().key())?;
        if let Some(p) = password.clone() {
            keypair = keypair.with_password(p);
        }

        rt.block_on(agent.decrypt(&keypair, pkesk_0.esk(), None)).unwrap();

        // Close connection.
        drop(agent);
      }

        // Make a helper that that feeds the recipient's secret key to the
        // decryptor.
        let helper = Helper {
            policy: p, ctx: &ctx, cert: &cert, other: &other,
            password: &password,
        };

        // Now, create a decryptor with a helper using the given Certs.
        let mut decryptor = DecryptorBuilder::from_bytes(&message).unwrap()
            .with_policy(p, None, helper).unwrap();

        // Decrypt the data.
        let mut sink = Vec::new();
        io::copy(&mut decryptor, &mut sink).unwrap();
        assert_eq!(MESSAGE.as_bytes(), &sink[..]);

        struct Helper<'a> {
            policy: &'a dyn Policy,
            ctx: &'a Context,
            cert: &'a openpgp::Cert,
            other: &'a openpgp::Cert,
            password: &'a Option<openpgp::crypto::Password>,
        }

        impl<'a> VerificationHelper for Helper<'a> {
            fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                               -> openpgp::Result<Vec<openpgp::Cert>> {
                // Return public keys for signature verification here.
                Ok(Vec::new())
            }

            fn check(&mut self, _structure: MessageStructure)
                     -> openpgp::Result<()> {
                // Implement your signature verification policy here.
                Ok(())
            }
        }

        impl<'a> DecryptionHelper for Helper<'a> {
            fn decrypt<D>(&mut self,
                          pkesks: &[openpgp::packet::PKESK],
                          _skesks: &[openpgp::packet::SKESK],
                          sym_algo: Option<SymmetricAlgorithm>,
                          mut decrypt: D)
                          -> openpgp::Result<Option<openpgp::Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
            {
                // We only gave the cert to GnuPG, the agent doesn't
                // have the secret.
                let mut keypair = KeyPair::new(
                    self.ctx,
                    self.other.keys().with_policy(self.policy, None)
                        .for_storage_encryption().for_transport_encryption()
                        .take(1).next().unwrap().key())
                    .unwrap();

                for pkesk in pkesks {
                    assert!(pkesk.decrypt(&mut keypair, sym_algo).is_none());
                }

                // Now use "our" key.
                let mut keypair = KeyPair::new(
                    self.ctx,
                    self.cert.keys().with_policy(self.policy, None)
                        .for_storage_encryption().for_transport_encryption()
                        .take(1).next().unwrap().key())
                    .unwrap();

                if let Some(p) = self.password.clone() {
                    keypair = keypair.with_password(p);
                }

                for pkesk in pkesks {
                    if *pkesk.recipient() != keypair.public().keyid() {
                        continue;
                    }

                    let (algo, session_key) =
                        pkesk.decrypt(&mut keypair, sym_algo)
                        .expect("decryption must succeed");
                    assert!(decrypt(algo, &session_key));
                }

                // XXX: In production code, return the Fingerprint of the
                // recipient's Cert here
                Ok(None)
            }
        }
      }
    }
    Ok(())
}
