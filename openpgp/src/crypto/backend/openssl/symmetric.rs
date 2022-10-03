use crate::crypto::symmetric::Mode;

use crate::types::SymmetricAlgorithm;
use crate::{Error, Result};

use openssl::cipher::{Cipher, CipherRef};
use openssl::cipher_ctx::CipherCtx;

struct OpenSslMode {
    ctx: CipherCtx,
}

impl OpenSslMode {
    fn new(ctx: CipherCtx) -> Self {
        Self { ctx }
    }
}

impl Mode for OpenSslMode {
    fn block_size(&self) -> usize {
        self.ctx.block_size()
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        self.ctx.cipher_update(src, Some(dst))?;
        Ok(())
    }

    fn decrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        self.encrypt(dst, src)
    }
}

impl SymmetricAlgorithm {
    /// Returns whether this algorithm is supported by the crypto backend.
    ///
    /// All backends support all the AES variants.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::types::SymmetricAlgorithm;
    ///
    /// assert!(SymmetricAlgorithm::AES256.is_supported());
    /// assert!(SymmetricAlgorithm::TripleDES.is_supported());
    ///
    /// assert!(!SymmetricAlgorithm::Twofish.is_supported());
    /// assert!(!SymmetricAlgorithm::Unencrypted.is_supported());
    /// assert!(!SymmetricAlgorithm::Private(101).is_supported());
    /// ```
    pub fn is_supported(&self) -> bool {
        let cipher: &CipherRef = if let Ok(cipher) = (*self).make_cfb_cipher() {
            cipher
        } else {
            return false;
        };

        let mut ctx = if let Ok(ctx) = CipherCtx::new() {
            ctx
        } else {
            return false;
        };
        ctx.encrypt_init(Some(cipher), None, None).is_ok()
    }

    /// Length of a key for this algorithm in bytes.
    ///
    /// Fails if Sequoia does not support this algorithm.
    pub fn key_size(self) -> Result<usize> {
        Ok(self.make_cfb_cipher()?.key_length())
    }

    /// Length of a block for this algorithm in bytes.
    ///
    /// Fails if Sequoia does not support this algorithm.
    pub fn block_size(self) -> Result<usize> {
        Ok(self.make_ecb_cipher()?.block_size())
    }

    /// Creates a OpenSSL context for encrypting in CFB mode.
    pub(crate) fn make_encrypt_cfb(self, key: &[u8], iv: Vec<u8>) -> Result<Box<dyn Mode>> {
        let cipher = self.make_cfb_cipher()?;
        let mut ctx = CipherCtx::new()?;
        ctx.encrypt_init(Some(cipher), Some(key), Some(&iv))?;
        Ok(Box::new(OpenSslMode::new(ctx)))
    }

    /// Creates a OpenSSL context for decrypting in CFB mode.
    pub(crate) fn make_decrypt_cfb(self, key: &[u8], iv: Vec<u8>) -> Result<Box<dyn Mode>> {
        let cipher = self.make_cfb_cipher()?;
        let mut ctx = CipherCtx::new()?;
        ctx.decrypt_init(Some(cipher), Some(key), Some(&iv))?;
        Ok(Box::new(OpenSslMode::new(ctx)))
    }

    /// Creates a OpenSSL context for encrypting in ECB mode.
    pub(crate) fn make_encrypt_ecb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        let cipher = self.make_ecb_cipher()?;
        let mut ctx = CipherCtx::new()?;
        ctx.encrypt_init(Some(cipher), Some(key), None)?;
        ctx.set_padding(false);
        Ok(Box::new(OpenSslMode::new(ctx)))
    }

    /// Creates a OpenSSL context for decrypting in ECB mode.
    pub(crate) fn make_decrypt_ecb(self, key: &[u8]) -> Result<Box<dyn Mode>> {
        let cipher = self.make_ecb_cipher()?;
        let mut ctx = CipherCtx::new()?;
        ctx.decrypt_init(Some(cipher), Some(key), None)?;
        ctx.set_padding(false);
        Ok(Box::new(OpenSslMode::new(ctx)))
    }

    fn make_cfb_cipher(self) -> Result<&'static CipherRef> {
        Ok(match self {
            #[cfg(not(osslconf = "OPENSSL_NO_IDEA"))]
            SymmetricAlgorithm::IDEA => Cipher::idea_cfb64(),

            SymmetricAlgorithm::AES128 => Cipher::aes_128_cfb128(),
            SymmetricAlgorithm::AES192 => Cipher::aes_192_cfb128(),
            SymmetricAlgorithm::AES256 => Cipher::aes_256_cfb128(),

            SymmetricAlgorithm::TripleDES => Cipher::des_ede3_cfb64(),

            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia128 => Cipher::camellia128_cfb128(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia192 => Cipher::camellia192_cfb128(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia256 => Cipher::camellia256_cfb128(),

            #[cfg(not(osslconf = "OPENSSL_NO_BF"))]
            SymmetricAlgorithm::Blowfish => Cipher::bf_cfb64(),

            SymmetricAlgorithm::CAST5 => Cipher::cast5_cfb64(),
            _ => return Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        })
    }

    fn make_ecb_cipher(self) -> Result<&'static CipherRef> {
        Ok(match self {
            #[cfg(not(osslconf = "OPENSSL_NO_IDEA"))]
            SymmetricAlgorithm::IDEA => Cipher::idea_ecb(),

            SymmetricAlgorithm::AES128 => Cipher::aes_128_ecb(),
            SymmetricAlgorithm::AES192 => Cipher::aes_192_ecb(),
            SymmetricAlgorithm::AES256 => Cipher::aes_256_ecb(),

            SymmetricAlgorithm::TripleDES => Cipher::des_ecb(),

            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia128 => Cipher::camellia128_ecb(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia192 => Cipher::camellia192_ecb(),
            #[cfg(not(osslconf = "OPENSSL_NO_CAMELLIA"))]
            SymmetricAlgorithm::Camellia256 => Cipher::camellia256_ecb(),

            #[cfg(not(osslconf = "OPENSSL_NO_BF"))]
            SymmetricAlgorithm::Blowfish => Cipher::bf_ecb(),

            SymmetricAlgorithm::CAST5 => Cipher::cast5_ecb(),
            _ => Err(Error::UnsupportedSymmetricAlgorithm(self))?,
        })
    }
}
