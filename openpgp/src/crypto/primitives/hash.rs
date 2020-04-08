//! Cryptographic hash functions.

pub use nettle::hash::insecure_do_not_use;

pub use nettle::hash::Hash;
pub use nettle::hash::{Sha224, Sha256, Sha384, Sha512};
