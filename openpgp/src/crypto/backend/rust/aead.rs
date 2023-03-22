//! Implementation of AEAD using pure Rust cryptographic libraries.

use std::cmp;
use std::cmp::Ordering;

use cipher::{BlockCipher, NewBlockCipher};
use cipher::block::Block;
use cipher::consts::U16;
use eax::online::{Eax, Encrypt, Decrypt};
use generic_array::{ArrayLength, GenericArray};

use crate::{Error, Result};
use crate::crypto::aead::{Aead, CipherOp};
use crate::crypto::mem::secure_cmp;
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

/// Disables authentication checks.
///
/// This is DANGEROUS, and is only useful for debugging problems with
/// malformed AEAD-encrypted messages.
const DANGER_DISABLE_AUTHENTICATION: bool = false;

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
}

impl<T, N: ArrayLength<T>> GenericArrayExt<T, N> for GenericArray<T, N> {
    const LEN: usize = N::USIZE;
}

impl<Cipher> Aead for Eax<Cipher, Encrypt>
where
    Cipher: BlockCipher<BlockSize = U16> + NewBlockCipher + Clone,
    Cipher::ParBlocks: ArrayLength<Block<Cipher>>,
{
    fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len(), src.len() + eax::Tag::LEN);
        let len = cmp::min(dst.len(), src.len());
        dst[..len].copy_from_slice(&src[..len]);
        Self::encrypt(self, &mut dst[..len]);
        let tag = self.tag_clone();
        dst[src.len()..].copy_from_slice(&tag[..]);
        Ok(())
    }

    fn decrypt_verify(&mut self, _dst: &mut [u8], _src: &[u8]) -> Result<()> {
        panic!("AEAD decryption called in the encryption context")
    }
}

impl<Cipher> Aead for Eax<Cipher, Decrypt>
where
    Cipher: BlockCipher<BlockSize = U16> + NewBlockCipher + Clone,
    Cipher::ParBlocks: ArrayLength<Block<Cipher>>,
{
    fn encrypt_seal(&mut self, _dst: &mut [u8], _src: &[u8]) -> Result<()> {
        panic!("AEAD encryption called in the decryption context")
    }

    fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
        debug_assert_eq!(dst.len() + eax::Tag::LEN, src.len());

        // Split src into ciphertext and digest.
        let l = eax::Tag::LEN;
        let digest = &src[src.len().saturating_sub(l)..];
        let src = &src[..src.len().saturating_sub(l)];

        let len = core::cmp::min(dst.len(), src.len());
        dst[..len].copy_from_slice(&src[..len]);
        self.decrypt_unauthenticated_hazmat(&mut dst[..len]);

        let chunk_digest = self.tag_clone();
        if secure_cmp(&chunk_digest[..], digest)
             != Ordering::Equal && ! DANGER_DISABLE_AUTHENTICATION
            {
                 return Err(Error::ManipulatedMessage.into());
            }
        Ok(())
    }
}

impl<Cipher, Op> seal::Sealed for Eax<Cipher, Op>
where
    Cipher: BlockCipher<BlockSize = U16> + NewBlockCipher + Clone,
    Cipher::ParBlocks: ArrayLength<Block<Cipher>>,
    Op: eax::online::CipherOp,
{}

impl AEADAlgorithm {
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        aad: &[u8],
        nonce: &[u8],
        op: CipherOp,
    ) -> Result<Box<dyn Aead>> {
        match self {
            AEADAlgorithm::EAX => match sym_algo {
                SymmetricAlgorithm::AES128 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<aes::Aes128, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<aes::Aes128, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::AES192 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<aes::Aes192, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<aes::Aes192, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::AES256 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<aes::Aes256, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<aes::Aes256, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                | SymmetricAlgorithm::IDEA
                | SymmetricAlgorithm::TripleDES
                | SymmetricAlgorithm::CAST5
                | SymmetricAlgorithm::Blowfish
                | SymmetricAlgorithm::Twofish
                | SymmetricAlgorithm::Camellia128
                | SymmetricAlgorithm::Camellia192
                | SymmetricAlgorithm::Camellia256
                | SymmetricAlgorithm::Private(_)
                | SymmetricAlgorithm::Unknown(_)
                | SymmetricAlgorithm::Unencrypted =>
                    Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },
            AEADAlgorithm::OCB | AEADAlgorithm::Private(_) | AEADAlgorithm::Unknown(_) =>
                Err(Error::UnsupportedAEADAlgorithm(*self).into()),
        }
    }
}
