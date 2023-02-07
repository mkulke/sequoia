use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    armor,
    Cert,
    cert::raw::RawCertParser,
    Fingerprint,
    Result,
    packet::UserID,
    parse::Parse,
    serialize::Serialize,
};

use crate::{
    Config,
};

use crate::sq_cli::export;

pub fn dispatch(config: Config, c: export::Command) -> Result<()> {
    let certd = if let Some(certd) = config.certd()? {
        certd
    } else {
        return Err(anyhow::anyhow!("certificate store is not configured"));
    };

    let userid = c.userid.iter().map(|u| u.as_bytes()).collect::<Vec<&[u8]>>();

    let email = c.email.into_iter()
        .map(|email| {
            // Check that the supplied email is actually a bare email
            // address.
            let email_check = UserID::from(format!("<{}>", email));
            match email_check.email() {
                Ok(Some(email_check)) => {
                    if email != email_check {
                        return Err(anyhow::anyhow!(
                            "{:?} does not appear to be an email address",
                            email));
                    }
                }
                Ok(None) => {
                    return Err(anyhow::anyhow!(
                        "{:?} does not appear to be an email address",
                        email));
                }
                Err(err) => {
                    return Err(err.context(format!(
                        "{:?} does not appear to be an email address",
                        email)));
                }
            }

            match UserID::from(&email[..]).email_normalized() {
                Err(err) => {
                    Err(err.context(format!(
                        "'{}' is not a valid email address", email)))
                }
                Ok(None) => {
                    Err(anyhow::anyhow!("'{}' is not a valid email address", email))
                }
                Ok(Some(email)) => {
                    Ok(email)
                }
            }
        })
        .collect::<Result<Vec<String>>>()?;

    // Performs the checks on a RawCert or a Cert.
    macro_rules! check_cert {
        ($fpr: expr, $cert: expr) => {
            loop {
                let fpr: &Fingerprint = $fpr;
                let cert: &_ = $cert;

                // Check the certificate's fingerprint.
                if c.cert.contains(fpr) {
                    break true;
                }

                if ! c.key.is_empty() {
                    if cert.keys().any(|k| c.key.contains(&k.fingerprint())) {
                        break true;
                    }
                }

                if ! userid.is_empty() || ! email.is_empty() {
                    if cert.userids().any(|u| {
                        if ! email.is_empty() {
                            if let Ok(Some(e)) = u.email_normalized() {
                                if email.contains(&e) {
                                    return true;
                                }
                            }
                        }

                        userid.contains(&u.value())
                    }) {
                        break true;
                    }
                }

                break false;
            }
        }
    }

    let check = |fpr: &Fingerprint, bytes: &[u8]| -> Result<Option<Cert>> {
        let mut parser = RawCertParser::from_bytes(bytes)
            .with_context(|| {
                format!("Parsing {} in certificate directory", fpr)
            })?;

        let raw = parser.next()
            .ok_or_else(|| {
                anyhow::anyhow!("{} is empty in certificate directory", fpr)
            })?
            .with_context(|| {
                format!("Parsing {} from certificate directory", fpr)
            })?;

        if fpr != &raw.fingerprint() {
            return Err(anyhow::anyhow!(
                "{} in certificate directory contains wrong certificate {}",
                fpr, raw.fingerprint()));
        }

        if check_cert!(fpr, &raw) {
            if let Ok(cert) = Cert::try_from(raw) {
                if check_cert!(fpr, &cert) {
                    return Ok(Some(cert));
                }
            }
        }

        Ok(None)
    };

    let mut sink = config.create_or_stdout_pgp(
        c.output.as_deref(), c.binary, armor::Kind::PublicKey)?;

    if c.cert.is_empty() && c.key.is_empty()
        && email.is_empty() && userid.is_empty()
    {
        // Export everything.
        for (fpr, _tag, bytes) in certd.iter()? {
            let cert = Cert::from_bytes(&bytes)
                .with_context(|| {
                    format!("Parsing {} from certificate directory", fpr)
                })?;
            cert.export(&mut sink)?;
        }
    } else if c.key.is_empty() && email.is_empty() && userid.is_empty() {
        // Export by certificate fingerprint.
        for fpr_str in certd.iter_fingerprints()? {
            if let Ok(fpr) = fpr_str.parse::<Fingerprint>() {
                if c.cert.contains(&fpr) {
                    match certd.get(&fpr_str[..]) {
                        Err(err) => {
                            let err = anyhow::Error::from(err)
                                .context(format!(
                                    "Reading {} from certificate directory",
                                    fpr_str));
                            return Err(err);
                        }
                        Ok(None) => {
                            // TOCTOU: Certificate disappeared.
                            // That's okay, silently ignore it.
                        }
                        Ok(Some((_tag, bytes))) => {
                            if let Some(cert) = check(&fpr, &bytes)? {
                                cert.export(&mut sink)?;
                            }
                        }
                    }
                }
            }
        }
    } else {
        // We need to do some parsing: we need to either match on keys
        // or User IDs.
        for (fpr_str, _tag, bytes) in certd.iter()? {
            if let Ok(fpr) = fpr_str.parse::<Fingerprint>() {
                if let Some(cert) = check(&fpr, &bytes)? {
                    cert.export(&mut sink)?;
                }
            }
        }
    }

    sink.finalize().context("Failed to export certificates")?;

    Ok(())
}
