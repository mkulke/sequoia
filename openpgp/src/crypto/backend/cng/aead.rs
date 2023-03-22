//! Implementation of AEAD using Windows CNG API.
use std::cmp::Ordering;

use crate::{Error, Result};
use crate::crypto::aead::{Aead, CipherOp};
use crate::crypto::mem::secure_cmp;
use crate::seal;
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

use eax::online::{Eax, Encrypt, Decrypt};
use win_crypto_ng::symmetric::{BlockCipherKey, Aes};
use win_crypto_ng::symmetric::block_cipher::generic_array::{GenericArray, ArrayLength};
use win_crypto_ng::symmetric::block_cipher::generic_array::typenum::{U128, U192, U256};

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
                            Eax::<BlockCipherKey<Aes, U128>, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<BlockCipherKey<Aes, U128>, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::AES192 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<BlockCipherKey<Aes, U192>, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<BlockCipherKey<Aes, U192>, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                SymmetricAlgorithm::AES256 => match op {
                    CipherOp::Encrypt => {
                        let mut ctx =
                            Eax::<BlockCipherKey<Aes, U256>, Encrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                    CipherOp::Decrypt => {
                        let mut ctx =
                            Eax::<BlockCipherKey<Aes, U256>, Decrypt>::with_key_and_nonce(
                                GenericArray::try_from_slice(key)?,
                                GenericArray::try_from_slice(nonce)?);
                        ctx.update_assoc(aad);
                        Ok(Box::new(ctx))
                    },
                },
                _ => Err(Error::UnsupportedSymmetricAlgorithm(sym_algo).into()),
            },
            _ => Err(Error::UnsupportedAEADAlgorithm(self.clone()).into()),
        }
    }
}

macro_rules! impl_aead {
    ($($type: ty),*) => {
        $(
        impl Aead for Eax<$type, Encrypt> {
            fn encrypt_seal(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
                debug_assert_eq!(dst.len(), src.len() + <eax::Tag as GenericArrayExt<_, _>>::LEN);
                let len = core::cmp::min(dst.len(), src.len());
                dst[..len].copy_from_slice(&src[..len]);
                Eax::<$type, Encrypt>::encrypt(self, &mut dst[..len]);

                let tag = self.tag_clone();
                dst[src.len()..].copy_from_slice(&tag[..]);
                Ok(())
            }
            fn decrypt_verify(&mut self, _dst: &mut [u8], _src: &[u8]) -> Result<()> {
                panic!("AEAD decryption called in the encryption context")
            }
        }
        impl seal::Sealed for Eax<$type, Encrypt> {}
        )*
        $(
        impl Aead for Eax<$type, Decrypt> {
            fn encrypt_seal(&mut self, _dst: &mut [u8], _src: &[u8]) -> Result<()> {
                panic!("AEAD encryption called in the decryption context")
            }
            fn decrypt_verify(&mut self, dst: &mut [u8], src: &[u8]) -> Result<()> {
                let digest_size = <eax::Tag as GenericArrayExt<_, _>>::LEN;
                debug_assert_eq!(dst.len() + digest_size, src.len());

                // Split src into ciphertext and digest.
                let l = digest_size;
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
        impl seal::Sealed for Eax<$type, Decrypt> {}
        )*
    };
}

impl_aead!(BlockCipherKey<Aes, U128>, BlockCipherKey<Aes, U192>, BlockCipherKey<Aes, U256>);
