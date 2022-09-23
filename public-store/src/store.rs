use anyhow::Context;

use std::path::{Path, PathBuf};

use openpgp_cert_d::{CertD, Data, TRUST_ROOT};

use openpgp::cert::{CertBuilder, CertParser};
use openpgp::crypto::Password;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::{Serialize, SerializeInto};
use openpgp::types::{KeyFlags, SignatureType};
use openpgp::{Cert, Fingerprint};
use sequoia_openpgp as openpgp;

use crate::error::TrustRootError;
use crate::{Error, Result};

static TRUST_ROOT_USERID: &str = "trust-root";

const TRUST_ROOT_POLICY: StandardPolicy = StandardPolicy::new();

pub struct Store {
    certd: CertD,
}

impl From<CertD> for Store {
    fn from(certd: CertD) -> Self {
        Self { certd }
    }
}

impl Store {
    pub fn new<T: AsRef<Path>>(dir: Option<T>) -> Result<Self> {
        Ok(match dir {
            Some(path) => CertD::with_base_dir(path).map(|x| x.into())?,
            None => CertD::new().map(|x| x.into())?,
        })
    }

    /// Get the path to the certificate store directory.
    ///
    /// Useful for debugging.
    pub fn path(&self) -> PathBuf {
        //TODO requires implementation in openpgp-cert-d.
        todo!()
    }

    /// Query the store for a certificate by fingerprint.
    ///
    /// Writes the raw bytes into `out`.
    pub fn get_raw(
        &self,
        fingerprint: &Fingerprint,
        out: &mut dyn std::io::Write,
    ) -> Result<()> {
        let cert = self.get(fingerprint)?;
        cert.export(out)?;
        Ok(())
    }

    /// Query the store for a certificate by fingerprint.
    ///
    /// Returns the certificate as a [`sequoia_openpgp::Cert`].
    pub fn get(&self, fingerprint: &Fingerprint) -> Result<Cert> {
        if let Some((_tag, cert)) = self.certd.get(&fingerprint.to_hex())? {
            Cert::from_bytes(&cert).map_err(Into::into)
        } else {
            Err(Error::CertNotFound {
                fingerprint: fingerprint.clone(),
            })
        }
    }

    /// Query the store for a certificate's path by fingerprint.
    pub fn get_path(&self, _fingerprint: &Fingerprint) -> Result<PathBuf> {
        //TODO requires implementation in openpgp-cert-d.
        todo!()
    }

    /// Insert or update a certificate in the store.
    // TODO: Should this rather take a Cert?
    pub fn insert<R: std::io::Read + Send + Sync>(&self, src: R) -> Result<()> {
        let new = Cert::from_reader(src)?;

        let f = |new: Data, old: Option<Data>| {
            let merged = match old {
                Some(old) => {
                    let old = Cert::from_bytes(&old)?;
                    let new = Cert::from_bytes(&new)?;
                    old.merge_public(new)?.to_vec()?.into_boxed_slice()
                }
                None => new,
            };
            Ok(merged)
        };

        self.certd.insert(new.to_vec()?.into_boxed_slice(), f)?;
        Ok(())
    }

    /// Export all certs in the store.
    pub fn export(&self, out: &mut dyn std::io::Write) -> Result<()> {
        for (_fp, _tag, cert) in self.certd.iter()? {
            let cert = Cert::from_bytes(&cert)?;
            cert.export(out)?
        }

        Ok(())
    }

    fn trust_root(&self) -> Result<Cert> {
        if let Some((_tag, cert)) = self.certd.get(TRUST_ROOT)? {
            Cert::from_bytes(&cert).map_err(Into::into)
        } else {
            Err(TrustRootError::TrustRootNotFound.into())
        }
    }

    /// Look for a cert by (subkey) fingerprint.
    ///
    /// If no cert is found the resulting vector is empty.
    /// Err is only returned if a problem occurs.
    pub fn search_by_fp(&self, fp: &Fingerprint) -> Result<Vec<Cert>> {
        let certs = self
            .certd
            .iter()?
            .map(|(_fp, _tag, data)| data)
            // TODO don't hide parsing errors?
            .flat_map(|data| Cert::from_bytes(&data))
            .filter(|cert| cert.keys().any(|key| &key.fingerprint() == fp))
            .collect::<Vec<Cert>>();

        Ok(certs)
    }

    /// Look for a cert by userid
    ///
    /// If no cert is found the resulting vector is empty.
    /// Err is only returned if a problem occurs.
    pub fn search_by_userid(&self, userid: &str) -> Result<Vec<Cert>> {
        let userid = openpgp::packet::UserID::from(userid);
        let certs = self
            .certd
            .iter()?
            .map(|(_fp, _tag, data)| data)
            // TODO don't hide parsing errors?
            .flat_map(|data| Cert::from_bytes(&data))
            // TODO this only does exact matches.
            // At least name or email only should work.
            // Substring of fuzzy matching should be discussed.
            .filter(|cert| cert.userids().any(|u| u.userid() == &userid))
            .collect::<Vec<Cert>>();

        Ok(certs)
    }
}

// Mark the cert's Direct Key Signature non-exportable
// Sequoia does not expose the Direct Key Signature's SignatureBuilder,
// so disassemble the Cert into packets, replace the DKS and reassble the Cert.
//
// XXX: This is absolutely not a nice thing to do. Once sequoia's CertBuilder
// offers an interface to customize the primary key signature, use that and
// remove this function.
fn mark_dks_non_exportable(
    cert: Cert,
    pass: Option<&Password>,
) -> Result<Cert> {
    use openpgp::packet::Packet;
    use openpgp::types::SignatureType::DirectKey;

    let primary_key = cert.primary_key().key().parts_as_secret()?.clone();

    let mut signer = match pass {
        Some(pw) => primary_key.decrypt_secret(pw)?.into_keypair()?,
        None => primary_key.into_keypair()?,
    };

    let modified_cert = Cert::from_packets(cert.into_packets().map(|p| {
        if let Packet::Signature(sig) = p {
            if sig.typ() == DirectKey {
                let sb = SignatureBuilder::from(sig);
                let new_sig = sb
                    .set_exportable_certification(false)
                    .and_then(|sb| sb.sign_direct_key(&mut signer, None))
                    .unwrap();
                Packet::Signature(new_sig)
            } else {
                Packet::Signature(sig)
            }
        } else {
            p
        }
    }))?;
    Ok(modified_cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use assert_fs::prelude::*;

    fn test_base() -> assert_fs::TempDir {
        let base = assert_fs::TempDir::new().unwrap();
        match std::env::var_os("CERTD_TEST_PERSIST") {
            Some(_) => {
                eprintln!("Test base dir: {}", &base.path().to_string_lossy());
                base.into_persistent()
            }
            None => base,
        }
    }

    #[test]
    fn get_nonexistent() {
        let base = test_base();
        let certd = Store::new(Some(base.path())).unwrap();
        let fp =
            Fingerprint::from_hex("39d100ab67d5bd8c04010205fb3751f1587daef1")
                .unwrap();

        let res = certd.get(&fp);

        assert!(res.is_err())
    }

    #[test]
    fn get() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path())).unwrap();
        let fp =
            Fingerprint::from_hex("39d100ab67d5bd8c04010205fb3751f1587daef1")?;

        // Get the cert.
        let output_cert = certd.get(&fp)?;

        assert_eq!(output_cert, Cert::from_bytes(data)?);

        // Get the cert again, to check that it does not change.
        let output_cert2 = certd.get(&fp)?;

        assert_eq!(output_cert2, Cert::from_bytes(data)?);
        Ok(())
    }

    #[test]
    fn get_uppercase() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path()))?;
        let fp =
            Fingerprint::from_hex("39d100ab67d5bd8c04010205fb3751f1587daef1")?;

        let output_cert = certd.get(&fp)?;

        assert_eq!(output_cert, Cert::from_bytes(data)?);
        Ok(())
    }

    #[test]
    fn export() -> anyhow::Result<()> {
        // Setup new store with three certs
        let base = test_base();

        let alice = Cert::from_bytes(include_bytes!("../testdata/alice.asc"))?
            .to_vec()?;
        base.child("eb/85bb5fa33a75e15e944e63f231550c4f47e38e")
            .write_binary(&alice)
            .unwrap();
        let bob = Cert::from_bytes(include_bytes!("../testdata/bob.asc"))?
            .to_vec()?;
        base.child("d1/a66e1a23b182c9980f788cfbfcc82a015e7330")
            .write_binary(&bob)
            .unwrap();
        let testy =
            Cert::from_bytes(include_bytes!("../testdata/testy-new.pgp"))?
                .to_vec()?;
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(&testy)
            .unwrap();

        let certd = Store::new(Some(base.path()))?;
        let mut out = Vec::new();
        certd.export(&mut out).unwrap();

        // Check the output.
        // The certs may be in any order.
        if out.starts_with(&alice) {
            if out[alice.len()..].starts_with(&bob) {
                //ABT
                assert!(out[alice.len() + bob.len()..].starts_with(&testy));
                assert!(out.ends_with(&testy))
            } else {
                //ATB
                assert!(out[alice.len()..].starts_with(&testy));
                assert!(out[alice.len() + testy.len()..].starts_with(&bob));
                assert!(out.ends_with(&bob))
            }
        } else if out.starts_with(&bob) {
            if out[bob.len()..].starts_with(&alice) {
                //BAT
                assert!(out[bob.len() + alice.len()..].starts_with(&testy));
                assert!(out.ends_with(&testy))
            } else {
                //BTA
                assert!(out[bob.len()..].starts_with(&testy));
                assert!(out[bob.len() + testy.len()..].starts_with(&alice));
                assert!(out.ends_with(&alice))
            }
        } else {
            assert!(out.starts_with(&testy));
            if out[testy.len()..].starts_with(&alice) {
                //TAB
                assert!(out[testy.len() + alice.len()..].starts_with(&bob));
                assert!(out.ends_with(&bob))
            } else {
                //TBA
                assert!(out[testy.len()..].starts_with(&bob));
                assert!(out[testy.len() + bob.len()..].starts_with(&alice));
                assert!(out.ends_with(&alice))
            }
        };

        Ok(())
    }

    #[test]
    fn export_empty() -> anyhow::Result<()> {
        let base = test_base();

        let certd = Store::new(Some(base.path()))?;
        let mut out = Vec::new();
        certd.export(&mut out)?;

        assert!(out.is_empty());
        Ok(())
    }

    #[test]
    fn test_insert() -> anyhow::Result<()> {
        let cert_bytes = include_bytes!("../testdata/testy-new.pgp");
        let cert =
            Cert::from_bytes(include_bytes!("../testdata/testy-new.pgp"))?;

        let base = test_base();

        let certd = Store::new(Some(base.path()))?;

        // Insert the cert.
        certd.insert(cert_bytes.as_ref())?;

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1"),
        )?)?;
        assert_eq!(cert, read_cert);

        // Insert the cert again.
        certd.insert(cert_bytes.as_ref())?;

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1"),
        )?)?;
        assert_eq!(cert, read_cert);

        Ok(())
    }

    #[test]
    fn trust_root() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        let certd = Store::new(Some(base.path()))?;

        certd.setup_create(None)?;

        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;

        let trust_root_from_file =
            Cert::from_bytes(&std::fs::read(base.child("trust-root"))?)?;
        let trust_root = certd.trust_root()?;

        assert_eq!(trust_root, trust_root_from_file);
        Ok(())
    }

    #[test]
    fn search_fp_primary() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path())).unwrap();

        let fp =
            Fingerprint::from_hex("39d100ab67d5bd8c04010205fb3751f1587daef1")?;

        let result = certd.search_by_fp(&fp).unwrap();
        assert!(result.len() == 1);
        assert_eq!(result[0], Cert::from_bytes(data)?);
        Ok(())
    }

    #[test]
    fn search_fp_subkey() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path())).unwrap();

        let subkey_fp =
            Fingerprint::from_hex("f4d1450b041f622fcefbfdb18bd88e94c0d20333")?;

        let result = certd.search_by_fp(&subkey_fp).unwrap();
        assert!(result.len() == 1);
        assert_eq!(result[0], Cert::from_bytes(data)?);
        Ok(())
    }

    #[test]
    fn search_fp_no_match() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path())).unwrap();

        let subkey_fp =
            Fingerprint::from_hex("ffffffffffffffffffffffffffffffffffffffff")?;

        let result = certd.search_by_fp(&subkey_fp).unwrap();
        assert!(result.len() == 0);
        Ok(())
    }
}
