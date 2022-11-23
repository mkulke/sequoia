use std::path::{Path, PathBuf};

use openpgp::policy::Policy;
use openpgp_cert_d::{CertD, Data, TRUST_ROOT};

use openpgp::parse::Parse;
use openpgp::serialize::{Serialize, SerializeInto};
use openpgp::{Cert, KeyHandle};
use sequoia_openpgp as openpgp;

use crate::error::TrustRootError;
use crate::{Error, Result};

/// A basic store for public PGP certificates.
///
/// No functionality that requires a trust root, use
/// [`into_with_trust_root`](Store::into_with_trust_root) or
/// [`init_trust_root`](Store::init_trust_root) for that.
// TODO link CertD spec
pub struct Store {
    certd: CertD,
}

/// A store for public PGP certificates, with a trust-root.
///
/// Allows for operations that require a trust-root, like interacting with
/// labels.
// TODO link CertD spec, explain labels
pub struct StoreWithTrustRoot {
    certd: CertD,
}

// TODO do we want this?
impl From<CertD> for Store {
    fn from(certd: CertD) -> Self {
        Self { certd }
    }
}

trait BasicStore {
    // TODO write doc
    // Required fn to access the underlying CertD
    fn certd(&self) -> &CertD;

    /// Get the path to the certificate store directory.
    ///
    /// Useful for debugging.
    fn path(&self) -> &Path {
        self.certd().get_base_dir()
    }

    /// Query the store for a certificate by primary fingerprint or KeyID.
    ///
    /// Returns the certificate as a [`sequoia_openpgp::Cert`].
    // TODO: maybe strip internal (non-exportable) stuff
    fn cert(&self, kh: &KeyHandle) -> Result<Cert> {
        if let Some((_tag, cert)) = self.certd().get(&kh.to_hex())? {
            Cert::from_bytes(&cert).map_err(Into::into)
        } else {
            Err(Error::CertNotFound {
                keyhandle: kh.clone(),
            })
        }
    }

    /// Query the store for a certificate's path by primary fingerprint.
    fn cert_path(&self, kh: &KeyHandle) -> Result<PathBuf> {
        Ok(self.certd().get_path(&kh.to_hex())?)
    }

    /// Export all certs in the store.
    fn export(&self, out: &mut dyn std::io::Write) -> Result<()> {
        for item in self.certd().iter() {
            let (_fp, _tag, cert) = item?;
            // Use export to remove non-exportable parts from certificates
            let cert = Cert::from_bytes(&cert)?;
            cert.export(out)?
        }

        Ok(())
    }

    /// Insert or update a certificate in the store.
    fn insert(&self, cert: &Cert) -> Result<()> {
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

        self.certd().insert(cert.to_vec()?.into_boxed_slice(), f)?;
        Ok(())
    }

    /// Iterate over all certificates in the store
    fn certs(&self) -> Box<dyn Iterator<Item = Result<Cert>> + '_> {
        let certs = self.certd().iter().map(|item| {
            let (_fp, _tag, data) = item?;
            Cert::from_bytes(&data).map_err(Into::into)
        });
        Box::new(certs)
    }

    /// Look for a cert by (subkey) KeyHandle (i.e. fingerprint or keyid).
    ///
    /// If no cert is found the resulting vector is empty.
    ///
    /// Ignores any certificate parsing or file-access errors.
    fn find_by_kh(&self, kh: &KeyHandle) -> Vec<Cert> {
        let certs = self
            .certs()
            .flatten()
            .filter(|cert| cert.keys().any(|key| key.key_handle().aliases(kh)))
            .collect::<Vec<Cert>>();
        certs
    }

    /// Look for a cert by exact userid
    ///
    /// If no cert is found the resulting vector is empty.
    ///
    /// Ignores any certificate parsing or file-access errors.
    // TODO maybe userid: sequoia::packet::UserID
    fn find_by_userid(&self, userid: &str) -> Vec<Cert> {
        let userid = openpgp::packet::UserID::from(userid);
        let certs = self
            .certs()
            .flatten()
            .filter(|cert| cert.userids().any(|u| u.userid() == &userid))
            .collect::<Vec<Cert>>();
        certs
    }

    //
    fn find_by_email(&self, _email: &str) -> Vec<Cert> {
        todo!()
    }

    //
    fn find_by_name(&self, _name: &str) -> Vec<Cert> {
        todo!()
    }

    //
    //fn find_by_predicate(&self, _predicate: Fn(sequoia_openpgp::packet::UserID) -> bool) ->
    //    Vec<Cert> {
    //    todo!()
    //}
}

impl BasicStore for Store {
    fn certd(&self) -> &CertD {
        &self.certd
    }
}

impl BasicStore for StoreWithTrustRoot {
    fn certd(&self) -> &CertD {
        &self.certd
    }
}

impl Store {
    // TODO rename
    pub fn new<T: AsRef<Path>>(dir: Option<T>) -> Result<Self> {
        Ok(match dir {
            Some(path) => CertD::with_base_dir(path).map(|x| x.into())?,
            None => CertD::new().map(|x| x.into())?,
        })
    }

    /// Setup a new certificate store and import the trust-root.
    ///
    /// The trust-root must be valid according to the cert-d specification.
    ///
    /// Overrides the current trust root if present. TODO, don't do this!!!
    // TODO: add links
    // Import the trust-root
    //
    // Check that
    // a) the imported Key is valid, according to our TRUST_ROOT_POLICY
    // b) the primary key is certification-capable
    pub fn import_trust_root(
        self,
        cert: &Cert,
        policy: &dyn Policy,
    ) -> Result<StoreWithTrustRoot> {
        let trust_root = cert;

        if !trust_root
            .with_policy(policy, None)?
            .primary_key()
            .for_certification()
        {
            return Err(TrustRootError::NotCertificationCapable.into());
        }

        self.certd().insert_special(
            TRUST_ROOT,
            trust_root.as_tsk().to_vec()?.into_boxed_slice(),
            |ours, _theirs| Ok(ours),
        )?;
        Ok(StoreWithTrustRoot { certd: self.certd })
    }

    // There's already a trust root, transition to the more powerful type
    // TODO: Name this right
    // TODO: I hope this works for users
    pub fn into_with_trust_root(self) -> Result<StoreWithTrustRoot> {
        if self.certd.get(TRUST_ROOT)?.is_some() {
            Ok(StoreWithTrustRoot { certd: self.certd })
        } else {
            // TODO improve Error
            Err(anyhow::anyhow!("no trust root found").into())
        }
    }


    // TODO
    // pub fn has_trust_root -> bool
}

impl StoreWithTrustRoot {
    /// Get the trust-root
    pub fn trust_root(&self) -> Result<Cert> {
        self.certd
            .get(TRUST_ROOT)
            .transpose()
            .unwrap()
            .map(|(_tag, data)| Cert::from_bytes(&data))?
            .map_err(Into::into)
    }

    // add label, remove label, find by label
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use assert_fs::prelude::*;

    use openpgp::Fingerprint;

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
    fn get_cert_nonexistent() {
        let base = test_base();
        let certd = Store::new(Some(base.path())).unwrap();
        let fp =
            Fingerprint::from_hex("39d100ab67d5bd8c04010205fb3751f1587daef1")
                .unwrap();

        let res = certd.get_cert(&fp.into());

        assert!(res.is_err())
    }

    #[test]
    fn get_cert() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path())).unwrap();
        let kh: KeyHandle =
            Fingerprint::from_hex("39d100ab67d5bd8c04010205fb3751f1587daef1")?
                .into();

        // Get the cert.
        let output_cert = certd.get_cert(&kh)?;

        assert_eq!(output_cert, Cert::from_bytes(data)?);

        // Get the cert again, to check that it does not change.
        let output_cert2 = certd.get_cert(&kh)?;

        assert_eq!(output_cert2, Cert::from_bytes(data)?);
        Ok(())
    }

    #[test]
    fn get_cert_uppercase() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path()))?;
        let fp =
            Fingerprint::from_hex("39d100ab67d5bd8c04010205fb3751f1587daef1")?;

        let output_cert = certd.get_cert(&fp.into())?;

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
        let cert =
            Cert::from_bytes(include_bytes!("../testdata/testy-new.pgp"))?;

        let base = test_base();

        let certd = Store::new(Some(base.path()))?;

        // Insert the cert.
        certd.insert(&cert)?;

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1"),
        )?)?;
        assert_eq!(cert, read_cert);

        // Insert the cert again.
        certd.insert(&cert)?;

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1"),
        )?)?;
        assert_eq!(cert, read_cert);

        Ok(())
    }

    #[test]
    fn trust_root() -> Result<()> {
        let data = include_bytes!("../testdata/sender.pgp");

        let base = test_base();
        let certd = Store::new(Some(base.path()))?;

        base.child(TRUST_ROOT).write_binary(data)?;

        let trust_root = certd.into_with_trust_root()?.trust_root()?;

        assert_eq!(Cert::from_bytes(data)?, trust_root);
        Ok(())
    }

    #[test]
    fn no_trust_root() -> Result<()> {
        let base = test_base();
        let certd = Store::new(Some(base.path()))?;

        assert!(certd.into_with_trust_root().is_err());

        Ok(())
    }

    #[test]
    fn find_by_kh_primary() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path())).unwrap();

        let fp =
            Fingerprint::from_hex("39d100ab67d5bd8c04010205fb3751f1587daef1")?;
        let kid = openpgp::KeyID::from(&fp);

        let result = certd.find_by_kh(&fp.into());
        assert!(result.len() == 1);
        assert_eq!(result[0], Cert::from_bytes(data)?);

        let result = certd.find_by_kh(&kid.into());
        assert!(result.len() == 1);
        assert_eq!(result[0], Cert::from_bytes(data)?);
        Ok(())
    }

    #[test]
    fn find_by_kh_subkey() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path())).unwrap();

        let subkey_fp =
            Fingerprint::from_hex("f4d1450b041f622fcefbfdb18bd88e94c0d20333")?;
        let subkey_kid = openpgp::KeyID::from(&subkey_fp);

        let result = certd.find_by_kh(&subkey_fp.into());
        assert!(result.len() == 1);
        assert_eq!(result[0], Cert::from_bytes(data)?);

        let result = certd.find_by_kh(&subkey_kid.into());
        assert!(result.len() == 1);
        assert_eq!(result[0], Cert::from_bytes(data)?);
        Ok(())
    }

    #[test]
    fn find_by_kh_no_match() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path())).unwrap();

        let subkey_fp =
            Fingerprint::from_hex("ffffffffffffffffffffffffffffffffffffffff")?;
        let subkey_kid = openpgp::KeyID::from(&subkey_fp);

        let result = certd.find_by_kh(&subkey_fp.into());
        assert!(result.len() == 0);
        let result = certd.find_by_kh(&subkey_kid.into());
        assert!(result.len() == 0);
        Ok(())
    }
}
