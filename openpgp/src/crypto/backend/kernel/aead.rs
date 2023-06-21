//! Implementation of AEAD using kernel cryptographic library.

use crate::{Error, Result};

use crate::crypto::aead::{Aead, CipherOp};
use crate::types::{AEADAlgorithm, SymmetricAlgorithm};

impl AEADAlgorithm {
    #[unimpl::unimpl]
    pub(crate) fn context(
        &self,
        sym_algo: SymmetricAlgorithm,
        key: &[u8],
        aad: &[u8],
        nonce: &[u8],
        op: CipherOp,
    ) -> Result<Box<dyn Aead>>;
}
