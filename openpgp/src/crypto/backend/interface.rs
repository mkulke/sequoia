//! The crypto-backend abstraction.

use crate::{
    Result,
    crypto::{
        SessionKey,
        mem::Protected,
    },
    types::{Curve, PublicKeyAlgorithm},
};

/// Abstracts over the cryptographic backends.
pub trait Backend: Asymmetric + Kdf {
    /// Returns a short, human-readable description of the backend.
    ///
    /// This starts with the name of the backend, possibly a version,
    /// and any optional features that are available.  This is meant
    /// for inclusion in version strings to improve bug reports.
    fn backend() -> String;

    /// Fills the given buffer with random data.
    ///
    /// Fills the given buffer with random data produced by a
    /// cryptographically secure pseudorandom number generator
    /// (CSPRNG).  The output may be used as session keys or to derive
    /// long-term cryptographic keys from.
    fn random(buf: &mut [u8]) -> Result<()>;
}

/// Public-key cryptography interface.
pub trait Asymmetric {
    /// Returns whether the given public key cryptography algorithm is
    /// supported by this backend.
    ///
    /// Note: when implementing this function, match exhaustively on
    /// `algo`, do not use a catch-all.  This way, when new algorithms
    /// are introduced, we will see where we may need to add support.
    fn supports_algo(algo: PublicKeyAlgorithm) -> bool;

    /// Returns whether the given elliptic curve is supported by this
    /// backend.
    ///
    /// Note: when implementing this function, match exhaustively on
    /// `curve`, do not use a catch-all.  This way, when new algorithms
    /// are introduced, we will see where we may need to add support.
    fn supports_curve(curve: &Curve) -> bool;

    /// Generates an X25519 key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn x25519_generate_key() -> Result<(Protected, [u8; 32])>;

    /// Computes the public key for a given secret key.
    fn x25519_derive_public(secret: &Protected) -> Result<[u8; 32]>;

    /// Computes the shared point.
    fn x25519_shared_point(secret: &Protected, public: &[u8; 32])
                           -> Result<Protected>;

    /// Generates an Ed25519 key pair.
    ///
    /// Returns a tuple containing the secret and public key.
    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])>;

    /// Computes the public key for a given secret key.
    fn ed25519_derive_public(secret: &Protected) -> Result<[u8; 32]>;

    /// Creates an Ed25519 signature.
    fn ed25519_sign(secret: &Protected, public: &[u8; 32], digest: &[u8])
                    -> Result<[u8; 64]>;

    /// Verifies an Ed25519 signature.
    fn ed25519_verify(public: &[u8; 32], digest: &[u8], signature: &[u8; 64])
                      -> Result<bool>;
}

/// Key-Derivation-Functions.
pub trait Kdf {
    /// HKDF instantiated with SHA256.
    ///
    /// Used to derive message keys from session keys, and key
    /// encapsulating keys from S2K mechanisms.  In both cases, using
    /// a KDF that includes algorithm information in the given `info`
    /// provides key space separation between cipher algorithms and
    /// modes.
    ///
    /// `salt`, if given, SHOULD be 32 bytes of salt matching the
    /// digest size of the hash function.  If it is not give, 32 zeros
    /// are used instead.
    ///
    /// `okm` must not be larger than 255 * 32 (the size of the hash
    /// digest).
    fn hkdf_sha256(ikm: &SessionKey, salt: Option<&[u8]>, info: &[u8],
                   okm: &mut SessionKey) -> Result<()>;
}
