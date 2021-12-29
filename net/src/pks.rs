//! Private Key Store communication.
//!
//! Functions in this module can be used to sign and decrypt using
//! remote keys using the [Private Key Store][PKS] protocol.
//!
//! [PKS]: https://gitlab.com/wiktor/pks
//! # Examples
//! ```
//! use sequoia_net::pks;
//! # let p: sequoia_openpgp::crypto::Password = vec![1, 2, 3].into();
//! # let key = sequoia_openpgp::cert::CertBuilder::general_purpose(None, Some("alice@example.org"))
//! #     .generate().unwrap().0.keys().next().unwrap().key().clone();
//!
//! match pks::unlock_signer("http://localhost:3000/", key, &p) {
//!     Ok(signer) => { /* use signer for signing */ },
//!     Err(e) => { eprintln!("Could not unlock signer: {:?}", e); }
//! }
//! ```

use std::convert::{TryFrom, TryInto};

use sequoia_openpgp as openpgp;

use openpgp::packet::Key;
use openpgp::packet::key::{PublicParts, UnspecifiedRole};
use openpgp::crypto::{Password, Decryptor, Signer, mpi, SessionKey, ecdh};
use openpgp::types::HashAlgorithm;

use hyper::{Body, Client, Uri, client::HttpConnector, Request, HeaderMap, header::HeaderValue};
use hyper_tls::HttpsConnector;

use super::Result;
use url::Url;

/// Contains a description of the unlocked key.
struct KeyDescriptor {
    /// URL of the endpoint that can be used to interact with the key.
    url: Uri,
    /// List of content types that this key accepts. This value is `None` if the key
    /// did not indicate accepted content types.
    accepted_types: Option<Vec<String>>,
}

impl TryFrom<&HeaderMap<HeaderValue>> for KeyDescriptor {
    type Error = anyhow::Error;

    fn try_from(headers: &HeaderMap<HeaderValue>) -> Result<Self> {
        if let Some(location) = headers.get("Location") {
            let accepted_types = if let Some(accepted_types) = headers.get("Accept-Post") {
                Some(
                    accepted_types
                        .to_str()?
                        .split(',')
                        .map(|typ| typ.trim().to_string())
                        .collect::<Vec<_>>(),
                )
            } else {
                None
            };
            Ok(Self {
                url: location.to_str()?.parse()?,
                accepted_types,
            })
        } else {
            Err(anyhow::anyhow!("Key unlock did not return a Location header."))
        }
    }
}

/// Returns an unlocked key descriptor.
///
/// Unlocks a key using given password and on success returns a key descriptor
/// that can be used for signing or decryption.
fn create_descriptor(store_uri: &str, key: &Key<PublicParts, UnspecifiedRole>,
                      p: &Password, capability: &str) -> Result<KeyDescriptor> {
    let mut url = Url::parse(store_uri)?;
    let auth = if !url.username().is_empty() {
        let credentials = format!("{}:{}", url.username(), url.password().unwrap_or_default());
        Some(format!("Basic {}", base64::encode(credentials)))
    } else {
        None
    };

    let client = Client::builder().build(HttpsConnector::new());

    url.query_pairs_mut().append_pair("capability", capability);

    let uri: hyper::Uri = url.join(&key.fingerprint().to_hex())?.as_str().parse()?;
    let mut request = Request::builder()
        .method("POST")
        .uri(uri);

    if let Some(auth) = auth {
        request = request.header(hyper::header::AUTHORIZATION, auth);
    }

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;

    let request = request.body(Body::from(p.map(|p|p.as_ref().to_vec())))?;
    let response = rt.block_on(client.request(request))?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!("PKS Key unlock failed: {}", response.status()));
    }

    response.headers().try_into()
}

/// Unlock a remote key for signing.
///
/// Look up a private key corresponding to the public key passed as a
/// parameter and return a [`Signer`] trait object that will utilize
/// that private key for signing.
///
/// # Errors
///
/// This function fails if the key cannot be found on the remote store
/// or if the password is not correct.
///
/// # Examples
/// ```
/// use sequoia_net::pks;
/// # let p: sequoia_openpgp::crypto::Password = vec![1, 2, 3].into();
/// # let key = sequoia_openpgp::cert::CertBuilder::general_purpose(None, Some("alice@example.org"))
/// #     .generate().unwrap().0.keys().next().unwrap().key().clone();
///
/// match pks::unlock_signer("http://localhost:3000/", key, &p) {
///     Ok(signer) => { /* use signer for signing */ },
///     Err(e) => { eprintln!("Could not unlock signer: {:?}", e); }
/// }
/// ```
pub fn unlock_signer(store_uri: impl AsRef<str>, key: Key<PublicParts, UnspecifiedRole>,
                     p: &Password) -> Result<Box<dyn Signer + Send + Sync>> {
    let description = create_descriptor(store_uri.as_ref(), &key, p, "sign")?;
    Ok(Box::new(PksClient::new(key, description)?))
}

/// Unlock a remote key for decryption.
///
/// Look up a private key corresponding to the public key passed as a
/// parameter and return a [`Decryptor`] trait object that will utilize
/// that private key for decryption.
///
/// # Errors
///
/// This function fails if the key cannot be found on the remote store
/// or if the password is not correct.
///
/// # Examples
/// ```
/// use sequoia_net::pks;
/// # let p: sequoia_openpgp::crypto::Password = vec![1, 2, 3].into();
/// # let key = sequoia_openpgp::cert::CertBuilder::general_purpose(None, Some("alice@example.org"))
/// #     .generate().unwrap().0.keys().next().unwrap().key().clone();
///
/// match pks::unlock_decryptor("http://localhost:3000/", key, &p) {
///     Ok(decryptor) => { /* use decryptor for decryption */ },
///     Err(e) => { eprintln!("Could not unlock decryptor: {:?}", e); }
/// }
/// ```
pub fn unlock_decryptor(store_uri: impl AsRef<str>, key: Key<PublicParts, UnspecifiedRole>,
                     p: &Password) -> Result<Box<dyn Decryptor + Send + Sync>> {
    let description = create_descriptor(store_uri.as_ref(), &key, p, "decrypt")?;
    Ok(Box::new(PksClient::new(key, description)?))
}

struct PksClient {
    location: Uri,
    public: Key<PublicParts, UnspecifiedRole>,
    client: hyper::client::Client<HttpsConnector<HttpConnector>>,
    acceptable_hashes: Vec<HashAlgorithm>,
    rt: tokio::runtime::Runtime,
}

impl PksClient {
    fn new(
           public: Key<PublicParts, UnspecifiedRole>,
           description: KeyDescriptor,
    ) -> Result<Self> {
        let client = Client::builder().build(HttpsConnector::new());

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;

        let acceptable_types = description.accepted_types.unwrap_or_default();
        let mut acceptable_hashes = acceptable_types.iter().flat_map(|typ| match typ.as_ref() {
            "application/vnd.pks.digest.sha1" => Some(HashAlgorithm::SHA1),
            "application/vnd.pks.digest.sha256" => Some(HashAlgorithm::SHA256),
            "application/vnd.pks.digest.sha384" => Some(HashAlgorithm::SHA384),
            "application/vnd.pks.digest.sha512" => Some(HashAlgorithm::SHA512),
            _ => None,
        }).collect::<Vec<_>>();
        acceptable_hashes.sort();

        Ok(Self { location: description.url, public, client, rt, acceptable_hashes })
    }

    fn make_request(&mut self, body: Vec<u8>, content_type: &str) -> Result<Vec<u8>> {
        let request = Request::builder()
            .method("POST")
            .uri(&self.location)
            .header("Content-Type", content_type)
            .body(Body::from(body))?;
        let response = self.rt.block_on(self.client.request(request))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("PKS operation failed: {}", response.status()));
        }

        Ok(self.rt.block_on(hyper::body::to_bytes(response))?.to_vec())
    }
}

impl Decryptor for PksClient {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn decrypt(
        &mut self,
        ciphertext: &mpi::Ciphertext,
        _plaintext_len: Option<usize>,
    ) -> openpgp::Result<SessionKey> {
        match (ciphertext, self.public.mpis()) {
            (mpi::Ciphertext::RSA { c }, mpi::PublicKey::RSA { .. }) =>
                Ok(self.make_request(c.value().to_vec(), "application/vnd.pks.rsa.ciphertext")?.into())
            ,
            (mpi::Ciphertext::ECDH { e, .. }, mpi::PublicKey::ECDH { .. }) => {
                #[allow(non_snake_case)]
                let S = self.make_request(e.value().to_vec(), "application/vnd.pks.ecdh.point")?.into();
                Ok(ecdh::decrypt_unwrap(&self.public, &S, ciphertext)?)
            },
            (ciphertext, public) => Err(anyhow::anyhow!(
                "Unsupported combination of ciphertext {:?} \
                     and public key {:?} ",
                ciphertext,
                public
            )),
        }
    }
}

impl Signer for PksClient {
    fn public(&self) -> &Key<PublicParts, UnspecifiedRole> {
        &self.public
    }

    fn acceptable_hashes(&self) -> &[HashAlgorithm] {
        &self.acceptable_hashes
    }

    fn sign(
        &mut self,
        hash_algo: openpgp::types::HashAlgorithm,
        digest: &[u8],
    ) -> openpgp::Result<openpgp::crypto::mpi::Signature> {
        use openpgp::types::PublicKeyAlgorithm;

        let content_type = match hash_algo {
            HashAlgorithm::SHA1 => "application/vnd.pks.digest.sha1",
            HashAlgorithm::SHA256 => "application/vnd.pks.digest.sha256",
            HashAlgorithm::SHA384 => "application/vnd.pks.digest.sha384",
            HashAlgorithm::SHA512 => "application/vnd.pks.digest.sha512",
            _ => "application/octet-stream",
        };

        let sig = self.make_request(digest.into(), content_type)?;

        match (self.public.pk_algo(), self.public.mpis()) {
            #[allow(deprecated)]
            (PublicKeyAlgorithm::RSASign, mpi::PublicKey::RSA { .. })
            | (
                PublicKeyAlgorithm::RSAEncryptSign,
                mpi::PublicKey::RSA { .. },
            ) =>
                Ok(mpi::Signature::RSA { s: mpi::MPI::new(&sig) }),
            (PublicKeyAlgorithm::EdDSA, mpi::PublicKey::EdDSA { .. }) => {
                let r = mpi::MPI::new(&sig[..32]);
                let s = mpi::MPI::new(&sig[32..]);

                Ok(mpi::Signature::EdDSA { r, s })
            }
            (
                PublicKeyAlgorithm::ECDSA,
                mpi::PublicKey::ECDSA { .. },
            ) => {
                let len_2 = sig.len() / 2;
                let r = mpi::MPI::new(&sig[..len_2]);
                let s = mpi::MPI::new(&sig[len_2..]);

                Ok(mpi::Signature::ECDSA { r, s })
            }

            (pk_algo, _) => Err(anyhow::anyhow!(
                "Unsupported combination of algorithm {:?} and pubkey {:?}",
                pk_algo,
                self.public
            )),
        }
    }
}
