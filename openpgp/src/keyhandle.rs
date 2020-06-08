use std::convert::TryFrom;
use std::cmp;
use std::cmp::Ordering;
use std::borrow::Borrow;

use crate::{
    Error,
    Fingerprint,
    KeyID,
    Result,
};

/// Enum representing an identifier for certificates and keys.
///
/// A `KeyHandle` contains either a [`Fingerprint`] or a [`KeyID`].
/// This is needed because signatures can reference their issuer either by
/// `Fingerprint` or by `KeyID`.
///
/// Currently, sequoia supports *version 4* fingerprints and Key ID only.
/// *Version 3* fingerprints and Key ID were deprecated by [RFC 4880] in 2007.
///
/// A *v4* fingerprint is, essentially, a 20-byte SHA-1 hash over the key's public
/// key packet.
/// A *v4* Key ID is defined as the fingerprint's lower 8 bytes.
///
/// For the exact definition, see [Section 12.2 of RFC 4880].
///
/// Both fingerprint and Key ID are used to identify a key, e.g., the issuer of a
/// signature.
///
///   [RFC 4880]: https://tools.ietf.org/html/rfc4880
///   [Section 12.2 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-12.2
///
///   [`Fingerprint`]: ./enum.Fingerprint.html
///   [`KeyID`]: ./enum.KeyID.html
///
/// # Examples
///
/// ```ignore
/// # use sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::{Fingerprint, KeyHandle};
/// # use openpgp::crypto::KeyPair;
/// # use openpgp::types::{Curve, SignatureType};
/// # use openpgp::packet::signature::Builder;
/// #
/// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
/// # fn load_certs() -> Vec<openpgp::Cert> {
/// #   Vec::new()
/// # }
/// # fn load_signature() -> openpgp::packet::Signature {
/// # panic!()
/// # }
///
/// let key: Fingerprint = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567".parse()?;
///
/// let signature = load_signature();
/// let certs: Vec<openpgp::Cert> = load_certs();
///
/// let issuers = signature.get_issuers();
///
/// let foo = certs
///   .iter()
///   .filter(|cert| issuers.iter().any(|issuer_kh| issuer_kh.aliases(&cert.key_handle())));
/// # return Ok(());
/// # }
/// ```
///
/// ```
/// # use sequoia_openpgp as openpgp;
/// # use openpgp::Result;
/// # use openpgp::{Fingerprint, KeyHandle};
/// # use openpgp::crypto::KeyPair;
/// # use openpgp::types::{Curve, SignatureType};
/// # use openpgp::packet::signature::Builder;
/// # use openpgp::cert::CertParser;
/// # use sequoia_openpgp::parse::Parse;
/// # use crate::policy::StandardPolicy as P;
///
/// # f().unwrap(); fn f() -> sequoia_openpgp::Result<()> {
// TODO generate key, use test macros to read files
/// let mut key_for_sig = CertParser::from_file("/home/nora/Projects/sequoia/openpgp/tests/data/keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")?;
///
/// let foo = &key_for_sig.next().unwrap()?;
/// let self_sig = &foo.userids().self_signatures()[0];
/// let keyring = CertParser::from_file("/home/nora/Projects/sequoia/openpgp/tests/data/keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")?;
/// keyring.unvalidated_cert_filter(|cert, _| {
///     cert.keys().key_handle(self_sig.issuer().unwrap()).next().is_some()
/// });
///
/// self_sig.verify(keyhandle);
/// //assert_eq!(keyhandle, self_sig.issuer())
/// Ok(())
/// }
/// ```
#[derive(Debug, Clone, Hash)]
pub enum KeyHandle {
    /// A Fingerprint.
    Fingerprint(Fingerprint),
    /// A KeyID.
    KeyID(KeyID),
}

impl std::fmt::Display for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            KeyHandle::Fingerprint(v) => v.fmt(f),
            KeyHandle::KeyID(v) => v.fmt(f),
        }
    }
}

impl std::fmt::UpperHex for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            KeyHandle::Fingerprint(ref fpr) => write!(f, "{:X}", fpr),
            KeyHandle::KeyID(ref keyid) => write!(f, "{:X}", keyid),
        }
    }
}

impl std::fmt::LowerHex for KeyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            KeyHandle::Fingerprint(ref fpr) => write!(f, "{:x}", fpr),
            KeyHandle::KeyID(ref keyid) => write!(f, "{:x}", keyid),
        }
    }
}

impl From<KeyID> for KeyHandle {
    fn from(i: KeyID) -> Self {
        KeyHandle::KeyID(i)
    }
}

impl From<&KeyID> for KeyHandle {
    fn from(i: &KeyID) -> Self {
        KeyHandle::KeyID(i.clone())
    }
}

impl From<KeyHandle> for KeyID {
    fn from(i: KeyHandle) -> Self {
        match i {
            KeyHandle::Fingerprint(i) => i.into(),
            KeyHandle::KeyID(i) => i,
        }
    }
}

impl From<&KeyHandle> for KeyID {
    fn from(i: &KeyHandle) -> Self {
        match i {
            KeyHandle::Fingerprint(i) => i.clone().into(),
            KeyHandle::KeyID(i) => i.clone(),
        }
    }
}

impl From<Fingerprint> for KeyHandle {
    fn from(i: Fingerprint) -> Self {
        KeyHandle::Fingerprint(i)
    }
}

impl From<&Fingerprint> for KeyHandle {
    fn from(i: &Fingerprint) -> Self {
        KeyHandle::Fingerprint(i.clone())
    }
}

impl TryFrom<KeyHandle> for Fingerprint {
    type Error = anyhow::Error;
    fn try_from(i: KeyHandle) -> Result<Self> {
        match i {
            KeyHandle::Fingerprint(i) => Ok(i),
            KeyHandle::KeyID(i) => Err(Error::InvalidOperation(
                format!("Cannot convert keyid {} to fingerprint", i)).into()),
        }
    }
}

impl TryFrom<&KeyHandle> for Fingerprint {
    type Error = anyhow::Error;
    fn try_from(i: &KeyHandle) -> Result<Self> {
        match i {
            KeyHandle::Fingerprint(i) => Ok(i.clone()),
            KeyHandle::KeyID(i) => Err(Error::InvalidOperation(
                format!("Cannot convert keyid {} to fingerprint", i)).into()),
        }
    }
}

impl PartialOrd for KeyHandle {
    fn partial_cmp(&self, other: &KeyHandle) -> Option<Ordering> {
        let a = self.as_bytes();
        let b = other.as_bytes();

        let l = cmp::min(a.len(), b.len());

        // Do a little endian comparison so that for v4 keys (where
        // the KeyID is a suffix of the Fingerprint) equivalent KeyIDs
        // and Fingerprints sort next to each other.
        for (a, b) in a[a.len()-l..].iter().zip(b[b.len()-l..].iter()) {
            let cmp = a.cmp(b);
            if cmp != Ordering::Equal {
                return Some(cmp);
            }
        }

        if a.len() == b.len() {
            Some(Ordering::Equal)
        } else {
            // One (a KeyID) is the suffix of the other (a
            // Fingerprint).
            None
        }
    }
}

impl PartialEq for KeyHandle {
    fn eq(&self, other: &Self) -> bool {
        self.partial_cmp(other) == Some(Ordering::Equal)
    }
}

impl KeyHandle {
    /// Returns the raw identifier as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            KeyHandle::Fingerprint(i) => i.as_bytes(),
            KeyHandle::KeyID(i) => i.as_bytes(),
        }
    }

    /// Returns whether `self` and `other` could be aliases of each other.
    ///
    /// `KeyHandle`'s `PartialEq` implementation cannot assert that a
    /// `Fingerprint` and a `KeyID` are equal, because distinct
    /// fingerprints may have the same `KeyID`, and `PartialEq` must
    /// be [transitive], i.e.,
    ///
    /// ```text
    /// a == b and b == c implies a == c.
    /// ```
    ///
    /// [transitive]: https://doc.rust-lang.org/std/cmp/trait.PartialEq.html
    ///
    /// That is, if `fpr1` and `fpr2` are distinct fingerprints with the
    /// same key ID then:
    ///
    /// ```text
    /// fpr1 == keyid and fpr2 == keyid, but fpr1 != fpr2.
    /// ```
    ///
    /// In these cases (and only these cases) `KeyHandle`'s
    /// `PartialOrd` implementation returns `None` to correctly
    /// indicate that a comparison is not possible.
    ///
    /// This definition of equality makes searching for a given
    /// `KeyHandle` using `PartialEq` awkward.  This function fills
    /// that gap.  It answers the question: given two `KeyHandles`,
    /// could they be aliases?  That is, it implements the desired,
    /// non-transitive equality relation:
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use openpgp::KeyID;
    /// # use openpgp::KeyHandle;
    /// #
    /// # let fpr1 : KeyHandle
    /// #     = "8F17 7771 18A3 3DDA 9BA4  8E62 AACB 3243 6300 52D9"
    /// #       .parse::<Fingerprint>().unwrap().into();
    /// #
    /// # let fpr2 : KeyHandle
    /// #     = "0123 4567 8901 2345 6789  0123 AACB 3243 6300 52D9"
    /// #       .parse::<Fingerprint>().unwrap().into();
    /// #
    /// # let keyid : KeyHandle = "AACB 3243 6300 52D9".parse::<KeyID>()
    /// #     .unwrap().into();
    /// #
    /// // fpr1 and fpr2 are different fingerprints with the same KeyID.
    /// assert!(! fpr1.eq(&fpr2));
    /// assert!(fpr1.aliases(&keyid));
    /// assert!(fpr2.aliases(&keyid));
    /// assert!(! fpr1.aliases(&fpr2));
    /// ```
    pub fn aliases<H>(&self, other: H) -> bool
        where H: Borrow<KeyHandle>
    {
        // This works, because the PartialOrd implementation only
        // returns None if one value is a fingerprint and the other is
        // a key id that matches the fingerprint's key id.
        self.partial_cmp(other.borrow()).unwrap_or(Ordering::Equal)
            == Ordering::Equal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upper_hex_formatting() {
        let handle = KeyHandle::Fingerprint(Fingerprint::V4([1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]));
        assert_eq!(format!("{:X}", handle), "0102030405060708090A0B0C0D0E0F1011121314");

        let handle = KeyHandle::Fingerprint(Fingerprint::Invalid(Box::new([10, 2, 3, 4])));
        assert_eq!(format!("{:X}", handle), "0A020304");

        let handle = KeyHandle::KeyID(KeyID::V4([10, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(format!("{:X}", handle), "0A02030405060708");

        let handle = KeyHandle::KeyID(KeyID::Invalid(Box::new([10, 2])));
        assert_eq!(format!("{:X}", handle), "0A02");
    }

    #[test]
    fn lower_hex_formatting() {
        let handle = KeyHandle::Fingerprint(Fingerprint::V4([1, 2, 3, 4, 5, 6, 7,
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]));
        assert_eq!(format!("{:x}", handle), "0102030405060708090a0b0c0d0e0f1011121314");

        let handle = KeyHandle::Fingerprint(Fingerprint::Invalid(Box::new([10, 2, 3, 4])));
        assert_eq!(format!("{:x}", handle), "0a020304");

        let handle = KeyHandle::KeyID(KeyID::V4([10, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(format!("{:x}", handle), "0a02030405060708");

        let handle = KeyHandle::KeyID(KeyID::Invalid(Box::new([10, 2])));
        assert_eq!(format!("{:x}", handle), "0a02");
    }

    #[test]
    fn for_development() -> crate::Result<()> {
        //use sequoia_openpgp as openpgp;
        use crate::Result;
        use crate::{Fingerprint, KeyHandle};
        use crate::crypto::KeyPair;
        use crate::Packet;
        use crate::types::{Curve, SignatureType};
        use crate::cert::CertParser;
        use crate::parse::Parse;
        use crate::policy::StandardPolicy as P;

        let mut sig_packet: Packet = Packet::from_file("/home/nora/Projects/sequoia/openpgp/tests/data/messages/emmelie-dorothea-dina-samantha-awina-detached-signature-of-100MB-of-zeros.sig")?;
        //let Packet::Signature(ref mut self_sig) = sig_packet;
        let detached_sig = match sig_packet {
            Packet::Signature(ref mut self_sig) => self_sig,
            _ => panic!(),
        };

        let key_handle = detached_sig.issuer().unwrap();

        //let foo = &key_for_sig.next().unwrap()?;
        //let sig = &foo.userids().self_signatures()[0];

        let keyring = CertParser::from_file("/home/nora/Projects/sequoia/openpgp/tests/data/keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")?;
        keyring.unvalidated_cert_filter(|cert, _| {
            cert.keys().key_handle(key_handle).next().is_some()
        });

        let foo = detached_sig.verify(&keyring);
        //assert_eq!(keyhandle, self_sig.issuer())
        Ok(())
    }

}
