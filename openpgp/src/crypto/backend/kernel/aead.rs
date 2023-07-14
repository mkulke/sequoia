//! Implementation of AEAD using kernel cryptographic library.

use crate::{Error, Result};

use crate::crypto::aead::{Aead, CipherOp};
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

use kcapi::aead::KcapiAEAD;
use kcapi::{ACCESS_HEURISTIC, INIT_AIO};

struct KernelContext {
    aead: KcapiAEAD,
    nonce: Vec<u8>,
    tag_size: usize,
}

impl Aead for KernelContext {
    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + self.digest_size());

        let ciphertext = self.aead.encrypt(src.into(), self.nonce.clone(), ACCESS_HEURISTIC)?;
        dst[..src.len()].copy_from_slice(&ciphertext.get_data());
        dst[src.len()..].copy_from_slice(&ciphertext.get_tag());
        Ok(())
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert!(src.len() >= self.digest_size());
        debug_assert_eq!(dst.len() + self.digest_size(), src.len());

        let l = self.digest_size();
        let ciphertext = &src[..src.len().saturating_sub(l)];
        let tag = &src[src.len().saturating_sub(l)..];

        self.aead.set_tag(tag.into());
        let plaintext = self.aead.decrypt(ciphertext.into(), self.nonce.clone(), ACCESS_HEURISTIC)?;
        dst.copy_from_slice(&plaintext.get_data());
        Ok(())
    }

    fn digest_size(&self) -> usize {
        self.tag_size
    }
}


impl KernelContext {
    fn new(key: &[u8], aad: &[u8], nonce: &[u8], tag_size: usize) -> Result<Self> {
        let mut aead = KcapiAEAD::new("gcm(aes)", !INIT_AIO)?;
        aead.setkey(key.into());
        aead.set_assocdata(aad.into());
        aead.set_tagsize(tag_size);
        Ok(Self {
            aead,
            nonce: nonce.into(),
            tag_size,
        })
    }
}

impl crate::seal::Sealed for KernelContext {}


impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        aad: &[u8],
        nonce: &[u8],
        op: CipherOp,
    ) -> Result<Box<dyn Aead>> {
        if !self.is_supported() {
            return Err(Error::UnsupportedAEADAlgorithm(*self).into());
        }
        if !self.supports_symmetric_algo(&sym_algo) {
            return Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into());
        }
        Ok(Box::new(KernelContext::new(key, aad, nonce, self.digest_size()?)?))
    }
}
