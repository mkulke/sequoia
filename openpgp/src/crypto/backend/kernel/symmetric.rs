use crate::crypto::symmetric::Mode;

use crate::types::SymmetricAlgorithm;
use crate::{Error, Result};

impl SymmetricAlgorithm {
    /// Returns whether this algorithm is supported by the crypto backend.
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        false
    }

    /// Creates a OpenSSL context for encrypting in CFB mode.
    pub(crate) fn make_encrypt_cfb(self, key: &[u8], iv: Vec<u8>) -> Result<Box<dyn Mode>> {
        unimplemented!();
    }

    /// Creates a OpenSSL context for decrypting in CFB mode.
    pub(crate) fn make_decrypt_cfb(self, key: &[u8], iv: Vec<u8>) -> Result<Box<dyn Mode>> {
        unimplemented!();
    }

    /// Creates a OpenSSL context for encrypting in ECB mode.
    pub(crate) fn make_encrypt_ecb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        unimplemented!();
    }

    /// Creates a OpenSSL context for decrypting in ECB mode.
    pub(crate) fn make_decrypt_ecb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        unimplemented!();
    }
}
