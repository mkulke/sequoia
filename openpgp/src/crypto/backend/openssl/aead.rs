//! Implementation of AEAD using OpenSSL cryptographic library.

use crate::{Error, Result};

use crate::crypto::aead::{Aead, CipherOp};
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

use openssl::cipher::Cipher;
use openssl::cipher_ctx::{CipherCtx, CipherCtxRef};
use openssl::error::ErrorStack;
use openssl_sys::c_int;

struct OpenSslContextEncrypt {
    ctx: CipherCtx,
    // The last chunk to be processed does not call `encrypt` thus
    // leaves the crypter in non-finalized state.  This makes the
    // `get_tag` function of the crypter panic when calling `digest`.
    // If this flag is set to `false` it means the crypter needs to be
    // finalized.
    finalized: bool,
}

fn cvt(r: c_int) -> std::result::Result<c_int, ErrorStack> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

// Uses the same logic as `CipherCtxRef::cipher_update` to calculate the
// required size of the output buffer.  This fix will be upstreamed.
fn safe_cipher_final(ctx: &CipherCtxRef, output: &mut [u8]) -> Result<usize> {
    let min_output_size = ctx.minimal_output_size(0);
    assert!(
        output.len() >= min_output_size,
        "Output buffer size should be at least {} bytes.",
        min_output_size
    );

    let mut outl = 0;
    unsafe {
        use foreign_types_shared::ForeignTypeRef;
        cvt(openssl_sys::EVP_CipherFinal(
            ctx.as_ptr(),
            output.as_mut_ptr(),
            &mut outl,
        ))?;
    }

    Ok(outl as usize)
}

impl Aead for OpenSslContextEncrypt {
    fn update(&mut self, ad: &[u8]) -> Result<()> {
        self.ctx.cipher_update(ad, None)?;
        Ok(())
    }

    fn encrypt(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        let size = self.ctx.cipher_update(src, Some(dst))?;
        safe_cipher_final(&self.ctx, &mut dst[size..])?;
        self.finalized = true;
        Ok(())
    }

    fn decrypt_verify(&mut self, _dst: &mut [u8], _src: &[u8], _valid_digest: &[u8]) -> Result<()> {
        panic!("Decrypt called in encrypt context");
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        if !self.finalized {
            safe_cipher_final(&self.ctx, &mut [])?;
        }
        self.ctx.tag(digest)?;
        Ok(())
    }

    fn digest_size(&self) -> usize {
        panic!("Unsupported op");
    }
}

impl crate::seal::Sealed for OpenSslContextEncrypt {}

struct OpenSslContextDecrypt {
    ctx: CipherCtx,
}

impl Aead for OpenSslContextDecrypt {
    fn update(&mut self, ad: &[u8]) -> Result<()> {
        self.ctx.cipher_update(ad, None)?;
        Ok(())
    }

    fn encrypt(&mut self, _dst: &mut [u8], _src: &[u8]) -> Result<()> {
        panic!("Encrypt called in decrypt context");
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8], valid_digest: &[u8]) -> Result<()> {
        let size = self.ctx.cipher_update(src, Some(dst))?;
        self.ctx.set_tag(valid_digest)?;
        safe_cipher_final(&self.ctx, &mut dst[size..])?;
        Ok(())
    }

    fn digest(&mut self, _digest: &mut [u8]) -> Result<()> {
        panic!("Unsupported op, use decrypt_verify");
    }

    fn digest_size(&self) -> usize {
        panic!("Unsupported operation");
    }
}

impl crate::seal::Sealed for OpenSslContextDecrypt {}

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        nonce: &[u8],
        op: CipherOp,
    ) -> Result<Box<dyn Aead>> {
        match self {
            AEADAlgorithm::OCB => {
                let cipher = match sym_algo {
                    SymmetricAlgorithm::AES128 => Cipher::aes_128_ocb(),
                    SymmetricAlgorithm::AES192 => Cipher::aes_192_ocb(),
                    SymmetricAlgorithm::AES256 => Cipher::aes_256_ocb(),
                    _ => return Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
                };
                let mut ctx = CipherCtx::new()?;
                ctx.set_padding(false);
                match op {
                    CipherOp::Encrypt => {
                        ctx.encrypt_init(Some(cipher), Some(key), Some(nonce))?;
                        Ok(Box::new(OpenSslContextEncrypt {
                            ctx,
                            finalized: false,
                        }))
                    }
                    CipherOp::Decrypt => {
                        ctx.decrypt_init(Some(cipher), Some(key), Some(nonce))?;
                        Ok(Box::new(OpenSslContextDecrypt { ctx }))
                    }
                }
            }
            _ => Err(Error::UnsupportedAEADAlgorithm(*self).into()),
        }
    }
}
