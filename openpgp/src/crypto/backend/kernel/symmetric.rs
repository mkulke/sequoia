use crate::crypto::symmetric::Mode;

use crate::types::SymmetricAlgorithm;
use crate::{Error, Result};
use unimpl::unimpl;

use kcapi::{INIT_AIO, ACCESS_HEURISTIC};
use kcapi::skcipher::KcapiSKCipher;
use std::sync::Mutex;

fn symmetric_algo_to_skcipher(sk_algo: SymmetricAlgorithm) -> Result<&'static str> {
    Ok(match sk_algo {
        SymmetricAlgorithm::TripleDES => "des3",
        SymmetricAlgorithm::AES128 | SymmetricAlgorithm::AES192 | SymmetricAlgorithm::AES256 => "aes",
        _ => return Err(Error::UnsupportedSymmetricAlgorithm(sk_algo).into()),
    })
}

struct KernelCipher {
    cipher: Option<Mutex<KcapiSKCipher>>,
    block_size: usize,
    iv: Vec<u8>,
    key: Vec<u8>,
    mode: String,
    sk_algo: SymmetricAlgorithm,
}

impl KernelCipher {
    fn new(mode: &str, sk_algo: SymmetricAlgorithm) -> Result<Self> {
        Ok(Self {
            cipher: None,
            block_size: sk_algo.block_size()?,
            sk_algo,
            mode: mode.into(),
            iv: vec![0; sk_algo.block_size()?],
            key: vec![0; sk_algo.block_size()?],
        })
    }

    fn set_key(&mut self, key: &[u8]) {
        self.key = key.into();
    }

    fn set_iv(&mut self, iv: Vec<u8>) {
        self.iv = iv;
    }
}

impl Mode for KernelCipher {
    fn block_size(&self) -> usize {
        self.block_size
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        if let Some(cipher) = &self.cipher {
            let mut cipher = cipher.lock().expect("not to be poisoned");
            if src.len() < self.block_size {
                cipher.stream_update_last(vec![src.into()])?;
            } else {
                cipher.stream_update(vec![src.into()])?;
            }
            dst.copy_from_slice(&cipher.stream_op()?[0]);
        } else {
            let mut cipher = KcapiSKCipher::new_enc_stream(&format!("{}({})", self.mode, symmetric_algo_to_skcipher(self.sk_algo)?), self.key.clone(), self.iv.clone(), vec![src.into()])?;
            dst.copy_from_slice(&cipher.stream_op()?[0]);
            self.cipher = Some(Mutex::new(cipher));
        }
        Ok(())
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        if let Some(cipher) = &self.cipher {
            let mut cipher = cipher.lock().expect("not to be poisoned");
            if src.len() < self.block_size {
                cipher.stream_update_last(vec![src.into()])?;
            } else {
                cipher.stream_update(vec![src.into()])?;
            }
            dst.copy_from_slice(&cipher.stream_op()?[0]);
        } else {
            let mut cipher = KcapiSKCipher::new_dec_stream(&format!("{}({})", self.mode, symmetric_algo_to_skcipher(self.sk_algo)?), self.key.clone(), self.iv.clone(), vec![src.into()])?;
            dst.copy_from_slice(&cipher.stream_op()?[0]);
            self.cipher = Some(Mutex::new(cipher));
        }
        Ok(())
    }
}

impl SymmetricAlgorithm {
    /// Returns whether this algorithm is supported by the crypto backend.
    pub(crate) fn is_supported_by_backend(&self) -> bool {
        KernelCipher::new("ecb", *self).is_ok()
    }

    /// Creates a OpenSSL context for encrypting in CFB mode.
    pub(crate) fn make_encrypt_cfb(self, key: &[u8], iv: Vec<u8>) -> Result<Box<dyn Mode>> {
        let mut cipher = KernelCipher::new("cfb", self)?;
        cipher.set_key(key);
        cipher.set_iv(iv);
        Ok(Box::new(cipher))
    }

    /// Creates a OpenSSL context for decrypting in CFB mode.
    pub(crate) fn make_decrypt_cfb(self, key: &[u8], iv: Vec<u8>) -> Result<Box<dyn Mode>> {
        self.make_encrypt_cfb(key, iv)
    }

    /// Creates a OpenSSL context for encrypting in ECB mode.
    pub(crate) fn make_encrypt_ecb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        let mut cipher = KernelCipher::new("ecb", self)?;
        cipher.set_key(key);
        Ok(Box::new(cipher))
    }

    /// Creates a OpenSSL context for decrypting in ECB mode.
    pub(crate) fn make_decrypt_ecb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        self.make_encrypt_ecb(key)
    }
}
