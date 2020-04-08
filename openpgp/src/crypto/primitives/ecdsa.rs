//! Elliptic curve variant of the Digital Signature Standard.

pub use nettle::ecdsa::{generate_keypair};
pub use nettle::ecdsa::{sign, verify};
