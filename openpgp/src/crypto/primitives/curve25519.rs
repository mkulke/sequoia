//! Elliptic curve Diffie-Hellman using D.J. Bernstein's Curve25519.

pub use nettle::curve25519::{
    CURVE25519_SIZE,
    private_key,
    mul_g,
    mul,
};
