use std::fmt;
use time;

use mpis::MPIs;
use Tag;
use Key;
use Packet;
use PublicKeyAlgorithm;
use SymmetricAlgorithm;
use s2k::S2K;
use Result;
use conversions::Time;

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Key")
            .field("fingerprint", &self.fingerprint())
            .field("version", &self.version)
            .field("creation_time", &format!("{}", self.creation_time.rfc3339()))
            .field("pk_algo", &self.pk_algo)
            .field("mpis", &self.mpis)
            .field("secret", &self.secret)
            .finish()
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fingerprint())
    }
}

impl Default for Key {
    fn default() -> Self {
        Key {
            common: Default::default(),
            version: 4,
            creation_time: time::now().canonicalize(),
            pk_algo: PublicKeyAlgorithm::Unknown(0),
            mpis: MPIs::empty(),
            secret: None,
        }
    }
}

impl Key {
    /// Returns a new `Key` packet.  This can be used to hold either a
    /// public key, a public subkey, a private key, or a private subkey.
    pub fn new(pk_algo: PublicKeyAlgorithm) -> Result<Self> {
        use nettle::{
            rsa,
            Yarrow,
            ed25519,ed25519::ED25519_KEY_SIZE,
            curve25519,curve25519::CURVE25519_SIZE,
        };
        use mpis::MPI;
        use constants::{HashAlgorithm, SymmetricAlgorithm, Curve};
        use PublicKeyAlgorithm::*;
        use Error;

        #[allow(deprecated)]
        let (mpis, secret) = match pk_algo {
            RSASign | RSAEncrypt | RSAEncryptSign => {
                let mut rng = Yarrow::default();
                let (public,private) = rsa::generate_keypair(&mut rng, 3072)?;
                let (p,q,u) = private.as_rfc4880();
                let public_mpis = MPIs::RSAPublicKey{
                    e: MPI::new(&*public.e()),
                    n: MPI::new(&*public.n()),
                };
                let private_mpis = MPIs::RSASecretKey{
                    d: MPI::new(&*private.d()),
                    p: MPI::new(&*p),
                    q: MPI::new(&*q),
                    u: MPI::new(&*u),
                };
                let sec = Some(SecretKey::Unencrypted{
                    mpis: private_mpis
                });

                (public_mpis, sec)
            }

            EdDSA => {
                let mut rng = Yarrow::default();
                let mut public = [0u8; ED25519_KEY_SIZE + 1];
                let mut private = [0u8; ED25519_KEY_SIZE];

                public[0] = 0x40;
                rng.random(&mut private);
                ed25519::public_key(&mut public[1..], &private)?;

                let public_mpis = MPIs::EdDSAPublicKey{
                    curve: Curve::Ed25519,
                    q: MPI::new(&public),
                };
                let private_mpis = MPIs::EdDSASecretKey{
                    scalar: MPI::new(&private),
                };
                let sec = Some(SecretKey::Unencrypted{
                    mpis: private_mpis,
                });

                (public_mpis, sec)
            }

            ECDH => {
                let mut rng = Yarrow::default();
                let mut public = [0u8; CURVE25519_SIZE + 1];
                let mut private = [0u8; CURVE25519_SIZE];

                public[0] = 0x40;
                rng.random(&mut private);
                curve25519::mul_g(&mut public[1..], &private)?;

                let public_mpis = MPIs::ECDHPublicKey{
                    curve: Curve::Cv25519,
                    q: MPI::new(&public),
                    hash: HashAlgorithm::SHA256,
                    sym: SymmetricAlgorithm::AES256,
                };
                let private_mpis = MPIs::ECDHSecretKey{
                    scalar: MPI::new(&private),
                };
                let sec = Some(SecretKey::Unencrypted{
                    mpis: private_mpis,
                });

                (public_mpis, sec)
            }

            pk => {
                return Err(Error::UnsupportedPublicKeyAlgorithm(pk).into());
            }
        };

        Ok(Key {
            common: Default::default(),
            version: 4,
            creation_time: time::now().canonicalize(),
            pk_algo: pk_algo,
            mpis: mpis,
            secret: secret,
        })
    }

    /// Gets the key packet's version field.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Gets the key packet's creation time field.
    pub fn creation_time(&self) -> &time::Tm {
        &self.creation_time
    }

    /// Sets the key packet's creation time field.
    pub fn set_creation_time(&mut self, timestamp: time::Tm) {
        self.creation_time = timestamp.canonicalize();
    }

    /// Gets the public key algorithm.
    pub fn pk_algo(&self) -> PublicKeyAlgorithm {
        self.pk_algo
    }

    /// Sets the public key algorithm.
    pub fn set_pk_algo(&mut self, pk_algo: PublicKeyAlgorithm) {
        self.pk_algo = pk_algo;
    }

    /// Gets the key packet's MPIs.
    pub fn mpis(&self) -> &MPIs {
        &self.mpis
    }

    /// Gets a mutable reference to the key packet's MPIs.
    pub fn mpis_mut(&mut self) -> &mut MPIs {
        &mut self.mpis
    }

    /// Sets the key packet's MPIs.
    pub fn set_mpis(&mut self, mpis: MPIs) {
        self.mpis = mpis;
    }

    /// Gets the key packet's SecretKey.
    pub fn secret(&self) -> Option<&SecretKey> {
        self.secret.as_ref()
    }

    /// Gets a mutable reference to the key packet's SecretKey.
    pub fn secret_mut(&mut self) -> Option<&mut SecretKey> {
        self.secret.as_mut()
    }

    /// Sets the key packet's SecretKey.
    pub fn set_secret(&mut self, secret: Option<SecretKey>) {
        self.secret = secret;
    }

    /// Convert the `Key` struct to a `Packet`.
    pub fn to_packet(self, tag: Tag) -> Packet {
        match tag {
            Tag::PublicKey => Packet::PublicKey(self),
            Tag::PublicSubkey => Packet::PublicSubkey(self),
            Tag::SecretKey => Packet::SecretKey(self),
            Tag::SecretSubkey => Packet::SecretSubkey(self),
            _ => panic!("Expected Tag::PublicKey, Tag::PublicSubkey, \
                         Tag::SecretKey, or Tag::SecretSubkey. \
                         Got: Tag::{:?}",
                        tag),
        }
    }
}

/// Holds the secret potion of a OpenPGP secret key or secret subkey packet.
///
/// This type allows postponing the decryption of the secret key until we need to use it.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub enum SecretKey {
    /// Unencrypted secret key. Can be used as-is.
    Unencrypted {
        /// MPIs of the secret key. Must be a *SecretKey enum variant.
        mpis: MPIs
    },
    /// The secret key is encrypted with a password.
    Encrypted {
        /// Key derivation mechanism to use.
        s2k: S2K,
        /// Symmetric algorithm used for encryption the secret key.
        algorithm: SymmetricAlgorithm,
        /// Encrypted MPIs prefixed with the IV.
        ciphertext: Box<[u8]>,
    },
}

impl SecretKey {
    /// Decrypts this secret key using `password`. The SecretKey type
    /// does not know what kind of key it is, so `pk_algo` is needed
    /// to parse the correct number of MPIs.
    pub fn decrypt(&mut self, pk_algo: PublicKeyAlgorithm, password: &[u8])
                   -> Result<()> {
        use std::io::{Cursor, Read};
        use symmetric::Decryptor;

        let new = match &*self {
            &SecretKey::Unencrypted { .. } => None,
            &SecretKey::Encrypted { ref s2k, algorithm, ref ciphertext } => {
                let key = s2k.derive_key(password, algorithm.key_size()?)?
                    .into_boxed_slice();
                let mut cur = Cursor::new(ciphertext);
                let mut dec = Decryptor::new(algorithm, &key, cur)?;
                let mut trash = vec![0u8; algorithm.block_size()?];

                dec.read_exact(&mut trash)?;
                let mpis = MPIs::parse_chksumd_secret_key(pk_algo, &mut dec)?;

                Some(SecretKey::Unencrypted{ mpis: mpis })
            }
        };

        if let Some(new) = new {
            *self = new;
        }

        Ok(())
    }

    /// Returns true if this secret key is encrypted.
    pub fn is_encrypted(&self) -> bool {
        match self {
            &SecretKey::Encrypted { .. } => true,
            &SecretKey::Unencrypted { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use mpis::MPIs;
    use packet::Tag;
    use TPK;
    use SecretKey;
    use std::path::PathBuf;
    use super::*;
    use PacketPile;
    use serialize::SerializeKey;

    fn path_to(artifact: &str) -> PathBuf {
        [env!("CARGO_MANIFEST_DIR"), "tests", "data", "keys", artifact]
            .iter().collect()
    }

    #[test]
    fn encrypted_rsa_key() {
        let mut tpk = TPK::from_file(
            path_to("testy-new-encrypted-with-123.pgp")).unwrap();
        let pair = tpk.primary_mut();
        let secret = pair.secret.as_mut().unwrap();

        assert!(secret.is_encrypted());
        secret.decrypt(pair.pk_algo, &b"123"[..]).unwrap();
        assert!(!secret.is_encrypted());

        match secret {
            &mut SecretKey::Unencrypted { mpis: MPIs::RSASecretKey { .. } } =>
                {}
            _ => { unreachable!() }
        }
    }

    #[test]
    fn eq() {
        for &pk_algo in &[PublicKeyAlgorithm::RSAEncryptSign,
                          PublicKeyAlgorithm::EdDSA,
                          PublicKeyAlgorithm::ECDH] {
            let key = Key::new(pk_algo).unwrap();
            let clone = key.clone();
            assert_eq!(key, clone);
        }
    }

    #[test]
    fn roundtrip() {
        for &pk_algo in &[PublicKeyAlgorithm::RSAEncryptSign,
                          PublicKeyAlgorithm::EdDSA,
                          PublicKeyAlgorithm::ECDH] {
            let mut key = Key::new(pk_algo).unwrap();

            let mut b = Vec::new();
            key.serialize(&mut b, Tag::SecretKey).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::SecretKey(ref parsed_key)) = pp.path_ref(&[0]) {
                assert_eq!(key.common, parsed_key.common);
                assert_eq!(key.version, parsed_key.version);
                assert_eq!(key.creation_time, parsed_key.creation_time);
                assert_eq!(key.pk_algo, parsed_key.pk_algo);
                assert_eq!(key.mpis, parsed_key.mpis);
                assert_eq!(key.secret, parsed_key.secret);

                assert_eq!(&key, parsed_key);
            } else {
                panic!("bad packet: {:?}", pp.path_ref(&[0]));
            }

            let mut b = Vec::new();
            key.serialize(&mut b, Tag::PublicKey).unwrap();

            let pp = PacketPile::from_bytes(&b).unwrap();
            if let Some(Packet::PublicKey(ref parsed_key)) = pp.path_ref(&[0]) {
                assert!(parsed_key.secret().is_none());

                key.set_secret(None);
                assert_eq!(&key, parsed_key);
            } else {
                panic!("bad packet: {:?}", pp.path_ref(&[0]));
            }
        }
    }
}
