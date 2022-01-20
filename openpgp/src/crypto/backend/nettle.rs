//! Implementation of Sequoia crypto API using the Nettle cryptographic library.

use crate::types::*;

use nettle::random::{Random, Yarrow};

use crate::crypto::SessionKey;

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

/// Fills the given buffer with random data.
///
/// Fills the given buffer with random data produced by a
/// cryptographically secure pseudorandom number generator (CSPRNG).
/// The output may be used as session keys or to derive long-term
/// cryptographic keys from.  However, to create session keys,
/// consider using [`SessionKey::new`].
///
///   [`SessionKey::new`]: crate::crypto::SessionKey::new()
pub fn random<B: AsMut<[u8]>>(mut buf: B) {
    Yarrow::default().random(buf.as_mut());
}

/// HKDF instantiated with SHA256.
///
/// Used to derive message keys from session keys, and key
/// encapsulating keys from S2K mechanisms.  In both cases, using a
/// KDF that includes algorithm information in the given `info`
/// provides key space separation between cipher algorithms and modes.
///
/// `salt`, if given, SHOULD be 32 bytes of salt matching the digest
/// size of the hash function.  If it is not give, 32 zeros are used
/// instead.
///
/// `okm` must not be larger than 255 * 32 (the size of the hash
/// digest).
pub fn hkdf_sha256(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey)
{
    use nettle::{
        kdf::hkdf,
        hash::Sha256,
    };

    assert!(okm.len() <= 255 * 32);
    const NO_SALT: [u8; 32] = [0; 32];
    let salt = salt.unwrap_or(&NO_SALT);
    hkdf::<Sha256>(&ikm[..], salt, info, okm);
}

impl PublicKeyAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match &self {
            RSAEncryptSign | RSAEncrypt | RSASign | DSA | ECDH | ECDSA | EdDSA
                => true,
            ElGamalEncrypt | ElGamalEncryptSign | Private(_) | Unknown(_)
                => false,
        }
    }
}

impl Curve {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::Curve::*;
        match &self {
            NistP256 | NistP384 | NistP521 | Ed25519 | Cv25519
                => true,
            BrainpoolP256 | BrainpoolP512 | Unknown(_)
                => false,
        }
    }
}

impl AEADAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::AEADAlgorithm::*;
        match &self {
            EAX
                => true,
            OCB
                => nettle::aead::OCB_IS_SUPPORTED,
            GCM
                => true,
            Private(_) | Unknown(_)
                => false,
        }
    }
}
