use crate::{Error, Result};

use crate::crypto::asymmetric::KeyPair;
use crate::crypto::backend::interface::Asymmetric;
use crate::crypto::mpi;
use crate::crypto::mpi::{ProtectedMPI, MPI};
use crate::crypto::mem::Protected;
use crate::crypto::SessionKey;
use crate::packet::key::{Key4, SecretParts};
use crate::packet::{key, Key};
use crate::types::{Curve, HashAlgorithm, PublicKeyAlgorithm};
use std::convert::{TryFrom, TryInto};
use std::time::SystemTime;
use unimpl::unimpl;

impl Asymmetric for super::Backend {
    fn supports_algo(algo: PublicKeyAlgorithm) -> bool {
        false
    }

    fn supports_curve(curve: &Curve) -> bool {
        false
    }

    #[unimpl]
    fn x25519_generate_key() -> Result<(Protected, [u8; 32])>;

    #[unimpl]
    fn x25519_derive_public(secret: &Protected) -> Result<[u8; 32]>;

    #[unimpl]
    fn x25519_shared_point(secret: &Protected, public: &[u8; 32])
                           -> Result<Protected>;

    #[unimpl]
    fn ed25519_generate_key() -> Result<(Protected, [u8; 32])>;

    #[unimpl]
    fn ed25519_derive_public(secret: &Protected) -> Result<[u8; 32]>;

    #[unimpl]
    fn ed25519_sign(secret: &Protected, _public: &[u8; 32], digest: &[u8])
                    -> Result<[u8; 64]>;

    #[unimpl]
    fn ed25519_verify(public: &[u8; 32], digest: &[u8], signature: &[u8; 64])
                      -> Result<bool>;
}


impl KeyPair {
    #[unimpl]
    pub(crate) fn decrypt_backend(
        &self,
        secret: &mpi::SecretKeyMaterial,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> Result<SessionKey>;

    #[unimpl]
    pub(crate) fn sign_backend(&self,
                               secret: &mpi::SecretKeyMaterial,
                               hash_algo: HashAlgorithm,
                               digest: &[u8])
                               -> Result<mpi::Signature>;
}

impl<P: key::KeyParts, R: key::KeyRole> Key<P, R> {
    /// Encrypts the given data with this key.
    #[unimpl]
    pub(crate) fn encrypt_backend(&self, data: &SessionKey) -> Result<mpi::Ciphertext>;

    /// Verifies the given signature.
    #[unimpl]
    pub(crate) fn verify_backend(
        &self,
        sig: &mpi::Signature,
        hash_algo: HashAlgorithm,
        digest: &[u8],
    ) -> Result<()>;
}


impl<R> Key4<SecretParts, R>
where
    R: key::KeyRole,
{
    /// Creates a new OpenPGP public key packet for an existing RSA key.
    ///
    /// The RSA key will use public exponent `e` and modulo `n`. The key will
    /// have it's creation date set to `ctime` or the current time if `None`
    /// is given.
    #[allow(clippy::many_single_char_names)]
    #[unimpl]
    pub fn import_secret_rsa<T>(d: &[u8], p: &[u8], q: &[u8], ctime: T) -> Result<Self>
    where
        T: Into<Option<SystemTime>>,
    ;

    /// Generates a new RSA key with a public modulos of size `bits`.
    #[allow(clippy::many_single_char_names)]
    #[unimpl]
    pub fn generate_rsa(bits: usize) -> Result<Self>;

    /// Generates a new ECC key over `curve`.
    ///
    /// If `for_signing` is false a ECDH key, if it's true either a
    /// EdDSA or ECDSA key is generated.  Giving `for_signing == true` and
    /// `curve == Cv25519` will produce an error. Likewise
    /// `for_signing == false` and `curve == Ed25519` will produce an error.
    #[unimpl]
    pub fn generate_ecc(for_signing: bool, curve: Curve) -> Result<Self>;
}
