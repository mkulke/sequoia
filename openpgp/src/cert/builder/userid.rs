use std::time;
use std::time::{Duration, SystemTime};

use crate::packet::{
    Key,
    key,
};

use crate::Result;
use crate::Packet;
use crate::packet::signature::{
    self,
    SignatureBuilder,
};
use crate::cert::prelude::*;
use crate::Error;
use crate::crypto::{Password, Signer};
use crate::types::{
    HashAlgorithm,
    KeyFlags,
    SignatureType,
    RevocationStatus,
};

/// A User ID builder.
///
/// This builder can be used to attach a new User ID to a certificate,
/// or update an existing User ID's binding signature.
///
/// ## Adding or Updating a User ID
///
/// [`UserIDBuilder::new`] adds a User ID to the certificate or
/// updates an existing User ID.  This updates the binding signature
/// of each of the non-revoked User IDs, and the direct key signature,
/// not just the new or updated User ID's binding signature.  This is
/// because normally all User ID binding signatures carry the same
/// information, and therefore all of the signatures should be
/// identical.  Given this, if the key is used on multiple devices, it
/// is strongly recommended to check for updates before calling this
/// function.
///
/// It is possible to only update or add a binding signature for the
/// specified User ID by calling `only_update_this_userid`.  This can
/// cause the settings on other User IDs to get out of sync and is
/// thus strongly *not* recommended.
///
/// [`CertBuilder::refresh`] can be used to update the binding
/// signature of each User ID.
///
/// ## Binding Signature Template
///
/// The Primary User ID's active binding signature is unconditionally
/// used as the template.  If the certificate does not have any valid
/// User IDs, then the direct key signature is used.  Note: a valid
/// certificate must have a User ID with a valid self signature, or a
/// direct key signature.
///
/// If the current binding signature and the primary User ID's binding
/// signature conflict, there is no attempt to resolve the difference;
/// the primary User ID's binding signature is used as is.
///
/// Expiration: primary key / cert expiration: if the certificate
/// would be considered expired as of the signature creation time,
/// then attach fails.
///
/// There are a number of signature subpackets that are meaningful in
/// the context of a User ID binding signature.  They are handled as
/// follows.
///
/// ### Subpackets Set by Default
///
///   - [Signature Creation Time](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.4)
///
///   - [Issuer](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.5)
///   - [Primary User ID](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.19)
///
///
/// ### Subpackets Taken from the Signature Template
///
///   - [Key Expiration Time](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.6)
///   - [Exportable Certification](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.11)
///   - [Revocation Key](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.15)
///   - [Notation Data](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.16)
///   - [Key Server Preferences](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.17)
///   - [Preferred Key Server](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.18)
///   - [Key Flags](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.21)
///
/// ### Subpackets Cleared by Default
///
///   - [Signature Expiration Time](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.10)
///
/// ### Subpackets Updated by Default
///
///   - [Preferred Symmetric Algorithms](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.6)
///   - [Preferred Hash Algorithms](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.8)
///   - [Preferred Compression Algorithms](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.9)
///   - [Features](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.24)
///
/// These subpackets are set to secure defaults, which most OpenPGP
/// implementations support.  This ensures that reasonable algorithms
/// are used.
pub struct UserIDBuilder<'a> {
    vc: ValidCert<'a>,
    primary_signer: Option<Box<dyn Signer + Send + Sync + 'a>>,

    userid: UserID,

    template: SignatureBuilder,
}
assert_send_and_sync!(UserIDBuilder<'_>);

impl<'a> UserIDBuilder<'a> {
    /// Returns a UserIDBuilder that will add the User ID to the
    /// specified certificate.
    ///
    /// If the User ID is already present on the certificate, then the
    /// `UserIDBuilder` effectively adds a new binding signature to
    /// the certificate.
    ///
    /// ## Binding Signature and Expiration
    ///
    /// It is possible to use your own binding signature by calling
    /// [`UserIDBuilder::add_signature_template`].  In general, you
    /// should use an existing binding signature as a template to
    /// preserve any customizations that the user may have made.
    ///
    /// It is essential to use a reasonable expiration.  If a binding
    /// signature is accidentally published without an expiration
    /// time, it is not completely possible to retract this by
    /// publishing a new binding signature that has an expiration,
    /// because an attacker may be able to withhold the newer
    /// signature and thereby cause the victim to use an expired key.
    ///
    /// ## Heuristic
    ///
    /// This builder uses a heuristic to select a binding signature to
    /// use as a template.  If possible, the user interface should show
    /// the expiration time, and allow the user to adjust it manually.
    ///
    /// - If the subkey is already present on the certificate, the
    ///   default binding signature is based on the subkey's active
    ///   binding signature, and the key expiration time is reused.
    ///   If the key would expire before the binding signature becomes
    ///   valid then [`SubkeyBuider::attach`] will fail.  Note: if the
    ///   subkey is present, but it does not have a valid binding
    ///   signature, then the subkey is treated as a new subkey.
    ///
    /// - If the subkey is new, then the active binding signature of
    ///   the newest live, non-revoked, valid subkey is used as the
    ///   binding signature template.  Newest means the the key with
    ///   the latest Key Creation Time and not newest binding
    ///   signature.  Again, if the key would expire before the
    ///   binding signature becomes valid then
    ///   [`SubkeyBuider::attach`] will fail.
    ///
    ///   If the certificate does not have a User ID, then a default
    ///   binding signature is created.
    ///
    /// ## Examples
    ///
    /// Add a new User ID to a certificate:
    ///
    /// ```
    /// use sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::KeyFlags;
    ///
    /// # fn main() -> openpgp::Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// #
    /// let vc = cert.with_policy(p, None)?;
    /// let cert2 = UserIDBuilder::new("Alice")
    ///     .attach_cert()?;
    /// # assert_eq!(cert.userids().count() + 1, cert2.userids().count());
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(vc: ValidCert<'a>, userid: UserID)
        -> Result<Self>
    {
        // If the key is already present on the certificate, then we
        // use the current self signature on that subkey as the
        // template.
        let (template, key_expiration): (SignatureBuilder, Option<SystemTime>)
            = vc.keys().subkeys()
            .filter_map(|ka| {
                if ka.key().parts_as_unspecified().public_eq(&subkey) {
                    let sig = ka.binding_signature().clone();
                    let e = sig.key_validity_period().map(|v| {
                        ka.key().creation_time() + v
                    });
                    Some((sig.into(), e))
                } else {
                    None
                }
            })
            .next()
            .or_else(|| {
                // The key is completely new.  Use the active self
                // signature on the newest, non-revoked, non-expired
                // subkey.
                vc.keys().subkeys()
                    .filter(|ka| {
                        if ! matches!(ka.revocation_status(),
                                      RevocationStatus::NotAsFarAsWeKnow) {
                            // Revoked.
                            false
                        } else if ka.alive().is_err() {
                            // Not alive.
                            false
                        } else {
                            true
                        }
                    })
                    .max_by_key(|ka| ka.key().creation_time())
                    .map(|ka| {
                        let sig = ka.binding_signature().clone();
                        let e = sig.key_validity_period().map(|v| {
                            ka.key().creation_time() + v
                        });
                        ((sig.into(), e))
                    })
            })
            .unwrap_or_else(|| {
                // The certificate doesn't have any valid subkeys, so
                // we don't have existing signatures that we can use
                // as a template.  In this case, we use a default
                // binding signature, and the primary key's expiration
                // time.
                (SignatureBuilder::new(SignatureType::SubkeyBinding),
                 vc.primary_key().key_validity_period().map(|v| {
                     vc.primary_key().creation_time() + v
                 }))
            });

        let template = template.set_key_flags(subkey_flags)?;

        let builder = SubkeyBuilder {
            vc,
            primary_signer: None,
            subkey: subkey.parts_into_unspecified(),
            subkey_signer: None,
            template,
            key_expiration,
        };

        Ok(builder)
    }

    /// Like SubkeyBuilder::new, but the binding signature is supplied.
    ///
    /// The key expiration time is taken from the supplied signature
    /// template, as is.
    pub fn new_with<P, T>(vc: ValidCert<'a>,
                          subkey: Key<P, key::SubordinateRole>,
                          template: T)
        -> Self
    where P: key::KeyParts,
          T: Into<SignatureBuilder>,
    {
        let template = template.into();
        let key_expiration = template.key_validity_period().map(|v| {
            subkey.creation_time() + v
        });

        SubkeyBuilder {
            vc,
            primary_signer: None,
            subkey: subkey.parts_into_unspecified(),
            subkey_signer: None,
            template,
            key_expiration,
        }
    }

    /// Sets the signature template that will be used for the binding
    /// signature.
    ///
    /// To attach a subkey to a certificate, the primary key needs to
    /// issue a [subkey binding signature].  This signature provides
    /// information about the key including its validity, and may
    /// contain auxiliary information like notations.  A subkey
    /// binding signature usually contains the following information:
    ///
    ///   - The hash algorithm
    ///   - [Signature creation time](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.4)
    ///
    ///   - [Key flags](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.21)
    ///
    ///   - [Issuer](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.5) and Issuer Fingerprint.
    ///
    ///   - [Primary key binding signature](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.26) (if the key is signing capable)
    ///
    /// The following information is also meaningful in the context of
    /// a subkey binding signature:
    ///
    ///   - [Key expiration time](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.6)
    ///     (relative to the key's creation time, not the signature's
    ///     creation time!)
    ///
    ///   - [Signature exiration time](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.10)
    ///
    ///   - [Exportable certification](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.11)
    ///
    ///   - [Notations](https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.16)
    ///
    /// ## Policy
    ///
    /// In addition to the changes made by the [`SignatureBuilder`],
    /// this function the key's expiration time is set to the
    /// expiration time in original the signature template, if it
    /// hasn't been explicitly set using
    /// [`SubkeyBuilder::set_expiration_time`],
    /// [`SubkeyBuilder::set_validity_period`],
    /// [`SubkeyBuilder::preserve_validity_period`].  When
    /// [`SubkeyBuilder::attach`] is executed, that function checks if
    /// the expiration time would cause the key to expire before the
    /// binding signature's expiration time.  If so, then
    /// [`SubkeyBuilder::attach`] returns an error.
    pub fn add_signature_template<T, V>(mut self, template: T,
                                        expiration: V)
        -> Self
    where T: Into<SignatureBuilder>,
          V: Into<Option<SystemTime>>,
    {
        self.template = template.into();
        self.key_expiration = expiration.into();

        self
    }

    /// Allows a function to directly modify the signature builder.
    ///
    /// This function does not fail; it merely returns the result of
    /// the callback function.
    pub fn with_signature_template<F>(&mut self, f: F) -> Result<()>
    where F: FnOnce(&mut SignatureBuilder) -> Result<()>
    {
        f(&mut self.template)
    }

    /// Sets the binding signature's creation time.
    ///
    /// This just calls
    /// [`SignatureBuilder::set_signature_creation_time`].
    pub fn set_signature_creation_time<T>(mut self, creation_time: T)
        -> Result<Self>
    where T: Into<SystemTime>
    {
        self.template
            = self.template.set_signature_creation_time(creation_time.into())?;
        Ok(self)
    }

    /// Preserves the signature creation time set in the template.
    ///
    /// This is just calls
    /// [`SignatureBuilder::preserve_signature_creation_time`].
    pub fn preserve_signature_creation_time(mut self) -> Result<Self>
    {
        self.template
            = self.template.preserve_signature_creation_time()?;
        Ok(self)
    }

    /// Sets the key's expiration time.
    pub fn set_expiration_time<T>(mut self, expiration_time: T)
        -> Result<Self>
    where T: Into<Option<SystemTime>>
    {
        self.key_expiration = expiration_time.into();
        Ok(self)
    }

    /// Sets the key's validity period.
    ///
    /// The validity period is the amount of time after the key's
    /// creation time that the key is considered fresh (i.e., not
    /// expired).
    pub fn set_validity_period<T>(mut self, validity: T)
        -> Result<Self>
    where T: Into<Option<Duration>>
    {
        match validity.into() {
            None =>
                self.key_expiration = None,
            Some(v) => {
                self.key_expiration
                    = Some(self.key().creation_time() + v);
            }
        }
        Ok(self)
    }

    /// Preserves the key validity period set in the template.
    ///
    /// Normally
    pub fn preserve_validity_period(self) -> Result<Self>
    {
        // XXX
        unimplemented!();
        //Ok(self)
    }

    /// Returns a reference to the key material that will be used.
    pub fn key(&self) -> &Key<key::UnspecifiedParts, key::SubordinateRole> {
        &self.subkey
    }

    /// Adds a signer for the primary key.
    ///
    /// In order to attach a subkey to a certificate one or more
    /// signatures need to be issued.  First, the primary key needs to
    /// issue a [subkey binding signature].  If the subkey is signing
    /// capable, then it also needs to issue a [primary key binding
    /// signature].  By default, [`SubkeyBuilder::attach`] will
    /// automatically derive the signers from the key material.  This
    /// only works, however, if the key material is present, and it is
    /// unencrypted.  This method allows you to explicitly provide a
    /// signer for the primary key.
    ///
    ///   [subkey binding signature]: https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
    ///   [primary binding signature]: https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
    pub fn set_primary_key_signer<S>(mut self, signer: S) -> Self
    where S: Signer + Send + Sync + 'a,
    {
        self.primary_signer = Some(Box::new(signer));
        self
    }

    /// Adds a signer for the subkey.
    ///
    /// In order to attach a subkey to a certificate one or more
    /// signatures need to be issued.  First, the primary key needs to
    /// issue a [subkey binding signature].  If the subkey is signing
    /// capable, then it also needs to issue a [primary key binding
    /// signature].  By default, [`SubkeyBuilder::attach`] will
    /// automatically derive the signers from the key material.  This
    /// only works, however, if the key material is present, and it is
    /// unencrypted.  This method allows you to explicitly provide a
    /// signer for the subkey.
    ///
    ///   [subkey binding signature]: https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
    ///   [primary binding signature]: https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
    pub fn set_subkey_signer<S>(mut self, signer: S) -> Self
    where S: Signer + Send + Sync + 'a,
    {
        self.subkey_signer = Some(Box::new(signer));
        self
    }

    /// Attachs the subkey to the certificate.
    ///
    /// This method generates the appropriate signatures to attach the
    /// subkey to the certificate.
    ///
    /// This method returns a number of packets, which need to be
    /// merged into the cert.
    pub fn attach(self) -> Result<Vec<Packet>> {
        let SubkeyBuilder {
            vc,
            primary_signer,
            subkey,
            subkey_signer,
            template,
            key_expiration,
        } = self;

        // GnuPG wants at least a 512-bit hash for P521 keys.
        let template = template.set_hash_algo(HashAlgorithm::SHA512);

        let mut builder = template
            .set_key_validity_period(
                key_expiration.map(|e| {
                    e.duration_since(subkey.creation_time())
                })
                .transpose()?)?;

        let creation_time = builder.effective_signature_creation_time();

        if let Some(flags) = builder.key_flags() {
            if flags.for_certification() || flags.for_signing() {
                // We need to create a primary key binding signature.
                let mut subkey_signer = if let Some(signer) = subkey_signer {
                    signer
                } else {
                    Box::new(
                        subkey.clone().parts_into_secret()?.into_keypair()?)
                };

                let mut backsig =
                    signature::SignatureBuilder::new(
                        SignatureType::PrimaryKeyBinding)
                    // GnuPG wants at least a 512-bit hash for P521 keys.
                    .set_hash_algo(HashAlgorithm::SHA512);
                if let Some(creation_time) = creation_time {
                    backsig = backsig.set_signature_creation_time(creation_time)?;
                }
                let backsig = backsig.sign_primary_key_binding(
                    &mut *subkey_signer, &vc.primary_key(), &subkey)?;
                builder = builder.set_embedded_signature(backsig)?;
            }
        }

        let mut primary_signer = if let Some(signer) = primary_signer {
            signer
        } else {
            Box::new(
                vc.primary_key().key().clone()
                    .parts_into_secret()?.into_keypair()?)
        };

        let signature = subkey.bind(
            &mut *primary_signer, &vc.cert(), builder)?;

        let subkey = if subkey.has_secret() {
            Packet::SecretSubkey(subkey.parts_into_secret().unwrap())
        } else {
            Packet::PublicSubkey(subkey.parts_into_public())
        };

        Ok(vec![subkey, signature.into()])
    }

    /// Attachs the subkey directly to the certificate.
    ///
    /// This function is like [`SubkeyBuilder::attach`], but it merges
    /// the resulting packets into the certificate.
    ///
    /// Note: if you are adding multiple components to a certificate,
    /// it is usually more efficient to use [`SubkeyBuilder::attach`]
    /// and then merge all of the packets at once.
    pub fn attach_cert(self) -> Result<Cert> {
        let cert = self.vc.cert().clone();
        let packets = self.attach()?;
        Ok(cert.insert_packets(packets)?)
    }
}

impl<'a, P> From<ValidPrimaryKeyAmalgamation<'a, P>> for SubkeyBuilder<'a>
where
    P: key::KeyParts + Clone,
{
    fn from(ka: ValidPrimaryKeyAmalgamation<'a, P>) -> Self {
        ValidErasedKeyAmalgamation::from(ka).into()
    }
}

impl<'a, P> From<ValidSubordinateKeyAmalgamation<'a, P>> for SubkeyBuilder<'a>
where
    P: key::KeyParts + Clone,
{
    fn from(ka: ValidSubordinateKeyAmalgamation<'a, P>) -> Self {
        ValidErasedKeyAmalgamation::from(ka).into()
    }
}

impl<'a, P> From<ValidErasedKeyAmalgamation<'a, P>> for SubkeyBuilder<'a>
where
    P: key::KeyParts + Clone,
{
    fn from(ka: ValidErasedKeyAmalgamation<'a, P>) -> SubkeyBuilder<'a> {
        let key = ka.key().clone().role_into_subordinate();
        SubkeyBuilder::new_with(
            ka.cert().clone(), key, ka.binding_signature().clone())
    }
}
