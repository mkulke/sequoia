//! The Digital Signature Algorithm (DSA) described in FIPS 186.

pub use nettle::dsa::Signature;
pub use nettle::dsa::Params;
pub use nettle::dsa::{sign, verify};
pub use nettle::dsa::{PrivateKey, PublicKey};
