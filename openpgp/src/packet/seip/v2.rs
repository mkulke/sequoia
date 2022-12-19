//! Symmetrically Encrypted Integrity Protected data packets version 2.
//!
//! An encrypted data packet is a container.  See [XXX] for details.

use crate::{
    packet::{
        self,
        Packet,
        SEIP,
    },
    Result,
    types::{
        AEADAlgorithm,
        SymmetricAlgorithm,
    },
};

/// Holds an encrypted data packet.
///
/// An encrypted data packet is a container.  See [XXX] for details.
///
/// # A note on equality
///
/// An unprocessed (encrypted) `SEIP2` packet is never considered equal
/// to a processed (decrypted) one.  Likewise, a processed (decrypted)
/// packet is never considered equal to a structured (parsed) one.
// IMPORTANT: If you add fields to this struct, you need to explicitly
// IMPORTANT: implement PartialEq, Eq, and Hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SEIP2 {
    /// CTB packet header fields.
    pub(crate) common: packet::Common,

    /// Symmetric algorithm.
    sym_algo: SymmetricAlgorithm,
    /// AEAD algorithm.
    aead: AEADAlgorithm,
    /// Salt.
    salt: [u8; 32],

    /// This is a container packet.
    container: packet::Container,
}

assert_send_and_sync!(SEIP2);

impl std::ops::Deref for SEIP2 {
    type Target = packet::Container;
    fn deref(&self) -> &Self::Target {
        &self.container
    }
}

impl std::ops::DerefMut for SEIP2 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.container
    }
}

impl SEIP2 {
    /// The size of chunks that are encrypted and integrity protected.
    pub const CHUNK_SIZE: usize = 16384;

    /// Creates a new SEIP2 packet.
    pub fn new(sym_algo: SymmetricAlgorithm,
               aead: AEADAlgorithm,
               salt: [u8; 32]) -> Result<Self> {
        Ok(SEIP2 {
            common: Default::default(),
            sym_algo,
            aead,
            salt,
            container: Default::default(),
        })
    }

    /// Gets the symmetric algorithm.
    pub fn symmetric_algo(&self) -> SymmetricAlgorithm {
        self.sym_algo
    }

    /// Sets the symmetric algorithm.
    pub fn set_symmetric_algo(&mut self, sym_algo: SymmetricAlgorithm)
                              -> SymmetricAlgorithm {
        std::mem::replace(&mut self.sym_algo, sym_algo)
    }

    /// Gets the AEAD algorithm.
    pub fn aead(&self) -> AEADAlgorithm {
        self.aead
    }

    /// Sets the AEAD algorithm.
    pub fn set_aead(&mut self, aead: AEADAlgorithm) -> AEADAlgorithm {
        std::mem::replace(&mut self.aead, aead)
    }

    /// Gets the salt.
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    /// Sets the salt.
    pub fn set_salt(&mut self, salt: [u8; 32]) -> [u8; 32] {
        std::mem::replace(&mut self.salt, salt)
    }
}

impl From<SEIP2> for SEIP {
    fn from(p: SEIP2) -> Self {
        SEIP::V2(p)
    }
}

impl From<SEIP2> for Packet {
    fn from(s: SEIP2) -> Self {
        Packet::SEIP(s.into())
    }
}
