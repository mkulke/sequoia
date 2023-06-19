//! Implementation of Sequoia crypto API using the kernel's cryptographic library.
#![allow(unused)]
use crate::types::*;

use kcapi::rng;

pub mod aead;
pub mod asymmetric;
pub mod ecdh;
pub mod hash;
pub mod symmetric;

pub struct Backend;

impl super::interface::Backend for Backend {
    fn backend() -> String {
        "Kernel Crypto".to_string()
    }

    fn random(buf: &mut [u8]) -> crate::Result<()> {
        buf.copy_from_slice(&rng::get_bytes(buf.len())?);
        Ok(())
    }
}

impl AEADAlgorithm {
    /// Returns the best AEAD mode supported by the backend.
    ///
    /// This SHOULD return OCB, which is the mandatory-to-implement
    /// algorithm and the most performing one, but fall back to any
    /// supported algorithm.
    pub(crate) const fn const_default() -> AEADAlgorithm {
        AEADAlgorithm::Unknown(99)
    }

    pub(crate) fn is_supported_by_backend(&self) -> bool {
        false
    }

    #[cfg(test)]
    pub(crate) fn supports_symmetric_algo(&self, algo: &SymmetricAlgorithm) -> bool {
        false
    }
}
