//! Implementation of Sequoia crypto API using pure Rust cryptographic
//! libraries.

use crate::types::*;

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

/// Returns a short, human-readable description of the backend.
pub fn backend() -> String {
    // XXX: can we include features and the version?
    "RustCrypto".to_string()
}

/// Fills the given buffer with random data.
pub fn random(buf: &mut [u8]) {
    use rand::rngs::OsRng;
    use rand::RngCore;

    OsRng.fill_bytes(buf)
}

impl PublicKeyAlgorithm {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use PublicKeyAlgorithm::*;
        #[allow(deprecated)]
        match &self {
            RSAEncryptSign | RSAEncrypt | RSASign | ECDH | EdDSA | ECDSA
                => true,
            DSA
                => false,
            ElGamalEncrypt | ElGamalEncryptSign | Private(_) | Unknown(_)
                => false,
        }
    }
}

impl Curve {
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::Curve::*;
        match &self {
            NistP256
                => true,
            NistP384 | NistP521
                => false,
            Ed25519 | Cv25519
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
            OCB | Private(_) | Unknown(_)
                => false,
        }
    }
}
