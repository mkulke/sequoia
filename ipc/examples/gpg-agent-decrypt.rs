/// Decrypts data using the openpgp crate and secrets in gpg-agent.

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

use clap::CommandFactory;
use clap::FromArgMatches;
use clap::Parser;

use sequoia_openpgp as openpgp;
use sequoia_ipc as ipc;

use openpgp::cert::prelude::*;
use openpgp::crypto::SessionKey;
use openpgp::types::SymmetricAlgorithm;
use openpgp::parse::{
    Parse,
    stream::{
        DecryptionHelper,
        DecryptorBuilder,
        VerificationHelper,
        GoodChecksum,
        VerificationError,
        MessageStructure,
        MessageLayer,
    },
};
use openpgp::policy::Policy;
use openpgp::policy::StandardPolicy as P;
use ipc::gnupg::{Context, KeyPair};

/// Defines the CLI.
#[derive(Parser, Debug)]
#[clap(
    name = "gpg-agent-decrypt",
    about = "Connects to gpg-agent and decrypts a message.",
)]
pub struct Cli {
    #[clap(
        long,
        value_name = "PATH",
        env = "GNUPGHOME",
        help = "Use this GnuPG home directory, default: $GNUPGHOME",
    )]
    homedir: Option<PathBuf>,

    #[clap(
        long,
        value_name = "CERT",
        help = "Public part of the secret keys managed by gpg-agent",
        required = true,
    )]
    cert: Vec<PathBuf>,
}

fn main() -> openpgp::Result<()> {
    let p = &P::new();

    let version = format!(
        "{} (sequoia-openpgp {}, using {})",
        env!("CARGO_PKG_VERSION"),
        sequoia_openpgp::VERSION,
        sequoia_openpgp::crypto::backend());
    let cli = Cli::command().version(version);
    let matches = Cli::from_arg_matches(&cli.get_matches())?;

    let ctx = if let Some(homedir) = matches.homedir {
        Context::with_homedir(homedir)?
    } else {
        Context::new()?
    };

    // Read the Certs from the given files.
    let certs =
        matches.cert.into_iter().map(
            openpgp::Cert::from_file
        ).collect::<Result<_, _>>()?;

    // Now, create a decryptor with a helper using the given Certs.
    let mut decryptor = DecryptorBuilder::from_reader(io::stdin())?
        .with_policy(p, None, Helper::new(&ctx, p, certs)?)?;

    // Finally, stream the decrypted data to stdout.
    io::copy(&mut decryptor, &mut io::stdout())?;

    Ok(())
}

/// This helper provides secrets for the decryption, fetches public
/// keys for the signature verification and implements the
/// verification policy.
struct Helper {
    keys: HashMap<openpgp::KeyID, KeyPair>,
}

impl Helper {
    /// Creates a Helper for the given Certs with appropriate secrets.
    fn new(ctx: &Context, policy: &dyn Policy, certs: Vec<openpgp::Cert>)
        -> openpgp::Result<Self>
    {
        // Map (sub)KeyIDs to secrets.
        let mut keys = HashMap::new();
        for cert in certs {
            for ka in cert.keys().with_policy(policy, None)
                .for_storage_encryption().for_transport_encryption()
            {
                let pair = KeyPair::new(ctx, ka.key())?
                    .with_cert(ka.cert());
                keys.insert(ka.key().keyid(), pair);
            }
        }

        Ok(Helper { keys })
    }
}

impl DecryptionHelper for Helper {
    fn decrypt<D>(&mut self,
                  pkesks: &[openpgp::packet::PKESK],
                  _skesks: &[openpgp::packet::SKESK],
                  sym_algo: Option<SymmetricAlgorithm>,
                  mut decrypt: D)
                  -> openpgp::Result<Option<openpgp::Fingerprint>>
        where D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool
    {
        // Try each PKESK until we succeed.
        for pkesk in pkesks {
            if let Some(pair) = self.keys.get_mut(pkesk.recipient()) {
                if pkesk.decrypt(pair, sym_algo)
                    .map(|(algo, session_key)| decrypt(algo, &session_key))
                    .unwrap_or(false)
                {
                    break;
                }
            }
        }
        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
        Ok(None)
    }
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle])
                       -> openpgp::Result<Vec<openpgp::Cert>> {
        Ok(Vec::new()) // Feed the Certs to the verifier here.
    }
    fn check(&mut self, structure: MessageStructure)
             -> openpgp::Result<()> {
        use self::VerificationError::*;
        for layer in structure.iter() {
            match layer {
                MessageLayer::Compression { algo } =>
                    eprintln!("Compressed using {}", algo),
                MessageLayer::Encryption { sym_algo, aead_algo } =>
                    if let Some(aead_algo) = aead_algo {
                        eprintln!("Encrypted and protected using {}/{}",
                                  sym_algo, aead_algo);
                    } else {
                        eprintln!("Encrypted using {}", sym_algo);
                    },
                MessageLayer::SignatureGroup { ref results } =>
                    for result in results {
                        match result {
                            Ok(GoodChecksum { ka, .. }) => {
                                eprintln!("Good signature from {}", ka.cert());
                            },
                            Err(MalformedSignature { error, .. }) => {
                                eprintln!("Signature is malformed: {}", error);
                            },
                            Err(MissingKey { sig, .. }) => {
                                let issuers = sig.get_issuers();
                                eprintln!("Missing key {:X}, which is needed to \
                                           verify signature.",
                                          issuers.first().unwrap());
                            },
                            Err(UnboundKey { cert, error, .. }) => {
                                eprintln!("Signing key on {:X} is not bound: {}",
                                          cert.fingerprint(), error);
                            },
                            Err(BadKey { ka, error, .. }) => {
                                eprintln!("Signing key on {:X} is bad: {}",
                                          ka.cert().fingerprint(),
                                          error);
                            },
                            Err(BadSignature { error, .. }) => {
                                eprintln!("Verifying signature: {}.", error);
                            },
                        }
                    }
            }
        }
        Ok(()) // Implement your verification policy here.
    }
}
