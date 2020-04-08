//! D.J. Bernstein's "Twisted" Edwards curve Ed25519.

pub use nettle::ed25519::{
    ED25519_KEY_SIZE,
    ED25519_SIGNATURE_SIZE,
    private_key,
    public_key,
    sign,
    verify
};
