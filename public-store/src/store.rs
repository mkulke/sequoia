use anyhow::Context;

use std::path::Path;

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

const POLICY: StandardPolicy = StandardPolicy::new();

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

    pub fn import<R: std::io::Read + Send + Sync>(&self, src: R) -> Result<()> {
        for cert in CertParser::from_reader(src)? {
            let new = cert.context("Malformed certificate in keyring")?;

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
        }

        Ok(())
    }

    pub fn export(&self, out: &mut dyn std::io::Write) -> Result<()> {
        for (_fp, _tag, cert) in self.certd.iter()? {
            let cert = Cert::from_bytes(&cert)?;
            cert.export(out)?
        }

        Ok(())
    }

    // Setup a new certificate directory and create a trust-root.
    //
    // The created trust-root
    // - has a userid "trust-root", for compatibility
    // - optionally a password
    // - certification capable primary key
    // - no subkeys
    // - the direct key signature and the primary userid's binding signature are
    //   marked non-exportable.
    //
    // See 3.5.1 for the trust-root's specification.
    pub fn setup_create(&self, password: Option<Password>) -> Result<()> {
        let cert_builder = CertBuilder::new()
            .set_primary_key_flags(KeyFlags::empty().set_certification())
            .add_userid_with(
                TRUST_ROOT_USERID,
                SignatureBuilder::new(SignatureType::GenericCertification)
                    .set_exportable_certification(false)?,
            )?
            .set_password(password.clone());

        let (tr_cert, _) = cert_builder.generate()?;

        let tr_cert_fixed =
            mark_dks_non_exportable(tr_cert, password.as_ref())?;
        let tr_tsk = tr_cert_fixed.as_tsk();

        self.certd.insert_special(
            TRUST_ROOT,
            tr_tsk.to_vec()?.into_boxed_slice(),
            |ours, _theirs| Ok(ours),
        )?;

        Ok(())
    }

    // Import the trust-root
    //
    // Check that
    // a) the imported Key is valid, according to our POLICY
    // b) the primary key is certification-capable
    pub fn setup_import_stdin<R: std::io::Read + Send + Sync>(
        &self,
        src: R,
    ) -> Result<()> {
        let trust_root = Cert::from_reader(src)?;

        if !trust_root
            .with_policy(&POLICY, None)
            .context("The imported trust-root must be valid.")?
            .primary_key()
            .for_certification()
        {
            return Err(TrustRootError::NotCertificationCapable.into());
        }

        self.certd.insert_special(
            TRUST_ROOT,
            trust_root.as_tsk().to_vec()?.into_boxed_slice(),
            |ours, _theirs| Ok(ours),
        )?;
        Ok(())
    }

    fn trust_root(&self) -> Result<Cert> {
        if let Some((_tag, cert)) = self.certd.get(TRUST_ROOT)? {
            Cert::from_bytes(&cert).map_err(Into::into)
        } else {
            Err(TrustRootError::TrustRootNotFound.into())
        }
    }

    pub fn add_label<P>(
        &self,
        fingerprint: &Fingerprint,
        label: &str,
        pw_callback: P,
    ) -> Result<()>
    where
        P: FnOnce() -> Result<Password>,
    {
        let cert = self.get(fingerprint)?;
        let userid = openpgp::packet::UserID::from(label);

        let mut tr_key = self
            .trust_root()?
            .with_policy(&POLICY, None)?
            .primary_key()
            .key()
            .clone()
            .parts_into_secret()?;

        if !tr_key.has_unencrypted_secret() {
            tr_key = tr_key.decrypt_secret(&pw_callback()?)?;
        }

        let mut tr_keypair = tr_key.into_keypair()?;
        let sb = SignatureBuilder::new(SignatureType::GenericCertification)
            .set_exportable_certification(false)?;
        let binding = userid.bind(&mut tr_keypair, &cert, sb)?;
        let cert = cert.insert_packets(vec![
            openpgp::Packet::from(userid),
            binding.into(),
        ])?;

        self.insert(cert.to_vec()?.as_slice())
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
    fn import() -> anyhow::Result<()> {
        // 1. Load bytes of several binary certs, just append them
        // 2. Import
        // 3. Assert each cert is in the store
        // 4. Assert not more is in the store
        let testy = include_bytes!("../testdata/testy-new.pgp");
        let alice = include_bytes!("../testdata/alice.pgp");
        let bob = include_bytes!("../testdata/bob.pgp");

        let certring = [testy.as_ref(), alice.as_ref(), bob.as_ref()].concat();

        let base = test_base();
        let certd = Store::new(Some(base.path()))?;

        // Import the keyring.
        certd.import(&certring[..])?;

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1"),
        )?)?;
        assert_eq!(Cert::from_bytes(testy)?, read_cert);

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("eb/85bb5fa33a75e15e944e63f231550c4f47e38e"),
        )?)?;
        assert_eq!(Cert::from_bytes(alice)?, read_cert);

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("d1/a66e1a23b182c9980f788cfbfcc82a015e7330"),
        )?)?;
        assert_eq!(Cert::from_bytes(bob)?, read_cert);

        // Check that nothing else is in the store
        let certd = Store::new(Some(base.path()))?;
        assert_eq!(certd.certd.iter_fingerprints()?.count(), 3);

        // Import the keyring again, no files should be added or changed.
        certd.import(&certring[..])?;

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1"),
        )?)?;
        assert_eq!(Cert::from_bytes(testy)?, read_cert);

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("eb/85bb5fa33a75e15e944e63f231550c4f47e38e"),
        )?)?;
        assert_eq!(Cert::from_bytes(alice)?, read_cert);

        let read_cert = Cert::from_bytes(&std::fs::read(
            base.child("d1/a66e1a23b182c9980f788cfbfcc82a015e7330"),
        )?)?;
        assert_eq!(Cert::from_bytes(bob)?, read_cert);

        // Check that nothing else is in the store
        let certd = Store::new(Some(base.path()))?;
        assert_eq!(certd.certd.iter_fingerprints()?.count(), 3);

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
    fn setup_create_simple() -> anyhow::Result<()> {
        let base = test_base();

        let certd = Store::new(Some(base.path()))?;

        certd.setup_create(None)?;

        let trust_root =
            Cert::from_bytes(&std::fs::read(base.child("trust-root"))?)?;

        let p = &openpgp::policy::StandardPolicy::new();
        let valid_trust_root = trust_root.with_policy(p, None)?;

        // Check the primary userid
        let userid = "trust-root";
        assert_eq!(
            userid,
            valid_trust_root.primary_userid().unwrap().name()?.unwrap()
        );
        // And that there is unecrypted secret key material.
        assert!(valid_trust_root
            .primary_key()
            .key()
            .has_unencrypted_secret());

        assert_created_trust_root_props(valid_trust_root)
    }

    #[test]
    fn setup_create_password() -> Result<()> {
        let base = test_base();

        let certd = Store::new(Some(base.path()))?;

        let pw = Password::from("password");
        certd.setup_create(Some(pw))?;

        let trust_root =
            Cert::from_bytes(&std::fs::read(base.child("trust-root"))?)?;

        let p = &openpgp::policy::StandardPolicy::new();
        let valid_trust_root = trust_root.with_policy(p, None)?;

        // Check the primary userid
        let userid = "trust-root";
        assert_eq!(
            userid,
            valid_trust_root.primary_userid().unwrap().name()?.unwrap()
        );
        // And that there is ecrypted secret key material.
        assert!(!valid_trust_root
            .primary_key()
            .key()
            .has_unencrypted_secret());

        assert_created_trust_root_props(valid_trust_root)
    }

    // Helper, assert the properties a trust-root should have
    fn assert_created_trust_root_props(
        vc: openpgp::cert::ValidCert,
    ) -> anyhow::Result<()> {
        //There's only one userid
        assert_eq!(1, vc.userids().count());

        // The primary key is certification capable
        assert!(vc.primary_key().for_certification());
        // and it has secret key material.
        assert!(vc.primary_key().key().has_secret());

        // There are no subkeys
        assert_eq!(1, vc.keys().count());

        // The Direct Key Signature must be non-exportable
        let dks = vc.direct_key_signature()?;
        assert!(matches!(dks, openpgp::packet::Signature::V4(_)));
        match dks {
            openpgp::packet::Signature::V4(sig) => {
                assert!(sig.exportable().is_err())
            }
            &_ => unreachable!(),
        }

        // Assert that the primary userid's binding signature is non-exportable
        let p = &openpgp::policy::StandardPolicy::new();
        let pu = vc.primary_userid()?;
        let bs = pu.binding_signature(p, None)?;
        assert!(matches!(bs, openpgp::packet::Signature::V4(_)));
        match bs {
            openpgp::packet::Signature::V4(sig) => {
                assert!(sig.exportable().is_err())
            }
            &_ => unreachable!(),
        }
        Ok(())
    }

    #[test]
    fn label() -> Result<()> {
        // Setup new store with one cert
        let data = include_bytes!("../testdata/testy-new.pgp");
        let base = test_base();
        base.child("39/d100ab67d5bd8c04010205fb3751f1587daef1")
            .write_binary(data)?;
        let certd = Store::new(Some(base.path()))?;

        let pw = Password::from("password");
        let fp =
            Fingerprint::from_hex("39d100ab67d5bd8c04010205fb3751f1587daef1")?;

        let label = "label";

        certd.setup_create(Some(pw.clone()))?;

        let cert_before = certd.get(&fp)?;
        let mut names_before = cert_before
            .userids()
            .flat_map(|ca| ca.userid().name())
            .flatten();

        assert!(names_before.all(|x| x != label));

        certd.add_label(&fp, label, || Ok(pw))?;

        let cert_after = certd.get(&fp)?;
        let mut names_after = cert_after
            .userids()
            .flat_map(|ca| ca.userid().name())
            .flatten();

        assert!(names_after.any(|x| x == label));
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
}
