use sequoia_openpgp as openpgp;
use openpgp::Result;

use sequoia_keystore as keystore;
use keystore::Keystore;

use crate::sq_cli;
use crate::Config;

fn list(_config: Config, _c: sq_cli::keystore::ListCommand) -> Result<()> {
    let context = keystore::Context::new()?;
    let mut ks = Keystore::connect(&context)?;

    let mut backends = ks.backends()?;
    for (b, backend) in backends.iter_mut().enumerate() {
        if b > 0 {
            eprintln!("");
        }
        eprintln!("Backend: {}", backend.id()?);
        let devices = backend.list()?;
        for mut device in devices {
            eprintln!("  Device: {}", device.id()?);
            let keys = device.list()?;
            for (k, mut key) in keys.into_iter().enumerate() {
                let pk = key.public_key().clone();
                let ct = pk.creation_time();
                let ct: chrono::DateTime<chrono::Utc> = ct.into();

                use openpgp::types::PublicKeyAlgorithm::*;
                #[allow(deprecated)]
                let bits = match pk.pk_algo() {
                    RSAEncryptSign
                    | RSAEncrypt
                    | RSASign
                    | ElGamalEncrypt
                    | DSA
                    | ElGamalEncryptSign =>
                        pk.mpis().bits().unwrap_or(0).to_string(),
                    _ => "".to_string(),
                };

                let id = if let Ok(id) = key.id() {
                    if id != pk.fingerprint().to_string() {
                        format!(" ({})", id)
                    } else {
                        "".into()
                    }
                } else {
                    "".into()
                };

                eprintln!("    {}. {}{} {} {}{}",
                          k + 1,
                          pk.pk_algo(), bits,
                          pk.fingerprint(),
                          ct.format("%Y-%m-%d"),
                          id);
            }
        }
    }

    Ok(())
}

pub fn dispatch(config: Config, c: sq_cli::keystore::Command) -> Result<()> {
    use sq_cli::keystore::Subcommands::*;
    match c.subcommand {
        List(sc) => {
            list(config, sc)
        },
    }
}
