//! Authenticated encryption mode with associated data.

pub use nettle::aead::Aead;

pub use nettle::aead::Eax;
pub use nettle::aead::Gcm;
pub use nettle::aead::Ccm;
pub use nettle::aead::ChaChaPoly1305;
