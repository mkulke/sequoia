//! Types for ECs in Weierstraß form.

pub use nettle::ecc::{Point, Scalar};
pub use nettle::ecc::{
    Curve, Secp192r1, Secp224r1, Secp256r1, Secp384r1, Secp521r1,
};
