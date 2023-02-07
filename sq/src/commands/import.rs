use sequoia_openpgp as openpgp;
use openpgp::{
    cert::prelude::*,
    Result,
    parse::Parse,
    serialize::Serialize,
};

use crate::{
    Config,
    open_or_stdin,
};

use crate::sq_cli::import;

pub fn dispatch(config: Config, c: import::Command) -> Result<()> {
    let input = open_or_stdin(c.io.input.as_deref())?;
    let certs = CertParser::from_reader(input)?;

    let mut new = 0;
    let mut unchanged = 0;
    let mut updated = 0;

    if let Some(certd) = config.certd()? {
        for cert in certs {
            let cert = match cert {
                Ok(cert) => cert,
                Err(err) => {
                    let err = anyhow::Error::from(err).context(
                        "Reading certificate from certificate store");
                    crate::print_error_chain(&err);
                    continue;
                }
            };

            // Note: if we got secrets, we discard them.  That's the right
            // choice.
            let mut cert_bytes = Vec::new();
            cert.serialize(&mut cert_bytes)?;

            certd.try_insert(
                cert_bytes.into_boxed_slice(),
                |cert_bytes, disk_bytes| {
                    let disk_bytes = if let Some(disk_bytes) = disk_bytes {
                        disk_bytes
                    } else {
                        // Nothing to merge.
                        new += 1;
                        return Ok(cert_bytes);
                    };

                    match Cert::from_bytes(&disk_bytes) {
                        Ok(disk) => {
                            if cert.fingerprint() != disk.fingerprint() {
                                // cert-d returned data with the wrong
                                // fingerprint.  Don't try to fix the cert-d,
                                // just silently fail.  (It doesn't really
                                // matter, because this is just a cache.)
                                return Ok(disk_bytes);
                            }

                            // If the on-disk version has secrets, we
                            // preserve them.
                            let disk_packets = disk.into_packets();

                            match cert.insert_packets2(disk_packets) {
                                Ok((merged, changed)) => {
                                    if changed {
                                        updated += 1;
                                    } else {
                                        unchanged += 1;
                                    }

                                    let mut bytes = Vec::new();
                                    merged.as_tsk()
                                        .serialize(&mut bytes)
                                        .expect("serializing to a vec");
                                    Ok(bytes.into_boxed_slice())
                                }
                                Err(err) => Err(err.into()),
                            }
                        }
                        Err(err) => {
                            // We failed to parse disk_bytes.
                            let err = anyhow::Error::from(err).context(
                                format!("Parsing {} from certificate store",
                                        cert.fingerprint()));
                            crate::print_error_chain(&err);

                            Ok(cert_bytes)
                        }
                    }
                })?;
        }

        eprintln!("Imported {} new certificates, updated {} certificates, \
                   {} certificates unchanged.",
                  new, updated, unchanged);

        Ok(())
    } else {
        Err(anyhow::anyhow!("certificate store is not configured"))
    }
}
