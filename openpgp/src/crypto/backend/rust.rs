//! Implementation of Sequoia crypto API using pure Rust cryptographic
//! libraries.

use generic_array::{ArrayLength, GenericArray};

use crate::{Error, Result};
use crate::types::*;

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

pub struct Backend(());

impl super::interface::Backend for Backend {
    fn backend() -> String {
        // XXX: can we include features and the version?
        "RustCrypto".to_string()
    }
}

trait GenericArrayExt<T, N: ArrayLength<T>> {
    const LEN: usize;

    /// Like [`GenericArray::from_slice`], but fallible.
    fn try_from_slice(slice: &[T]) -> Result<&GenericArray<T, N>> {
        if slice.len() == Self::LEN {
            Ok(GenericArray::from_slice(slice))
        } else {
            Err(Error::InvalidArgument(
                format!("Invalid slice length, want {}, got {}",
                        Self::LEN, slice.len())).into())
        }
    }

    /// Like [`GenericArray::clone_from_slice`], but fallible.
    fn try_clone_from_slice(slice: &[T]) -> Result<GenericArray<T, N>>
        where T: Clone
    {
        if slice.len() == Self::LEN {
            Ok(GenericArray::clone_from_slice(slice))
        } else {
            Err(Error::InvalidArgument(
                format!("Invalid slice length, want {}, got {}",
                        Self::LEN, slice.len())).into())
        }
    }
}

impl<T, N: ArrayLength<T>> GenericArrayExt<T, N> for GenericArray<T, N> {
    const LEN: usize = N::USIZE;
}

/// Fills the given buffer with random data.
pub fn random(buf: &mut [u8]) {
    use rand07::rngs::OsRng;
    use rand07::RngCore;

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
    /// Returns the best AEAD mode supported by the backend.
    ///
    /// This SHOULD return OCB, which is the mandatory-to-implement
    /// algorithm and the most performing one, but fall back to any
    /// supported algorithm.
    pub(crate) const fn const_default() -> AEADAlgorithm {
        AEADAlgorithm::EAX
    }

    pub(crate) fn is_supported_by_backend(&self) -> bool {
        use self::AEADAlgorithm::*;
        match &self {
            EAX => true,
            OCB => false,
            GCM => true,
            Private(_) | Unknown(_)
                => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn supports_symmetric_algo(&self, algo: &SymmetricAlgorithm) -> bool {
        match &self {
            AEADAlgorithm::EAX =>
                match algo {
                    SymmetricAlgorithm::AES128 |
                    SymmetricAlgorithm::AES192 |
                    SymmetricAlgorithm::AES256 |
                    // XXX: Skipping Twofish until Twofish implements Clone
                    // SymmetricAlgorithm::Twofish |
                    SymmetricAlgorithm::Camellia128 |
                    SymmetricAlgorithm::Camellia192 |
                    SymmetricAlgorithm::Camellia256 => true,
                    _ => false,
                },

            AEADAlgorithm::GCM =>
                match algo {
                    SymmetricAlgorithm::AES128 |
                    SymmetricAlgorithm::AES192 |
                    SymmetricAlgorithm::AES256 => true,
                    _ => false,
                },
            _ => false
        }
    }
}
