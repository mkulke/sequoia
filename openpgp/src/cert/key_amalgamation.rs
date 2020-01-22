use std::time;
use std::time::SystemTime;
use std::convert::TryInto;
use std::convert::TryFrom;
use std::borrow::Borrow;
use std::ops::Deref;

use crate::{
    Cert,
    cert::components::KeyBinding,
    Error,
    packet::key,
    packet::key::SecretKeyMaterial,
    packet::Key,
    packet::Signature,
    Result,
    RevocationStatus,
    types::KeyFlags,
};

/// The underlying `KeyAmalgamation` type.
///
/// We don't make this type public, because an enum's variant types
/// must also all be public, and we don't want that here.  Wrapping
/// this in a struct means that we can hide that.
#[derive(Debug, Clone)]
enum KeyAmalgamationBinding<'a, P: key::KeyParts> {
    Primary(),
    Subordinate(&'a KeyBinding<P, key::SubordinateRole>),
}

/// A `Key` and its associated data.
#[derive(Debug, Clone)]
pub struct KeyAmalgamation<'a, P: key::KeyParts, R: key::KeyRole> {
    cert: &'a Cert,
    binding: KeyAmalgamationBinding<'a, P>,
    _r: std::marker::PhantomData<R>,
}

impl<'a, P: key::KeyParts> Deref
    for KeyAmalgamation<'a, P, key::PrimaryRole>
    where &'a Key<P, key::PrimaryRole>:
              From<&'a Key<key::PublicParts, key::PrimaryRole>>
{
    type Target = Key<P, key::PrimaryRole>;
    fn deref(&self) -> &Self::Target {
        self.key()
    }
}

impl<'a, P: key::KeyParts> Deref
    for KeyAmalgamation<'a, P, key::SubordinateRole>
{
    type Target = Key<P, key::SubordinateRole>;
    fn deref(&self) -> &Self::Target {
        self.key().into()
    }
}

impl<'a, P: key::KeyParts> Deref
    for KeyAmalgamation<'a, P, key::UnspecifiedRole>
    where &'a Key<P, key::UnspecifiedRole>:
              From<&'a Key<key::PublicParts, key::PrimaryRole>>
{
    type Target = Key<P, key::UnspecifiedRole>;
    fn deref(&self) -> &Self::Target {
        self.key().into()
    }
}

// We can't make the key parts generic, because then the impl would
// conflict with 'impl<T> std::convert::From<T> for T'.
impl<'a, R: key::KeyRole> From<KeyAmalgamation<'a, key::PublicParts, R>>
    for KeyAmalgamation<'a, key::UnspecifiedParts, R>
{
    fn from(ka: KeyAmalgamation<'a, key::PublicParts, R>) -> Self {
        match ka {
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Primary(),
                ..
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Primary(),
                    _r: std::marker::PhantomData,
                },
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Subordinate(binding),
                ..
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Subordinate(binding.into()),
                    _r: std::marker::PhantomData,
                },
        }
    }
}

impl<'a, R: key::KeyRole> From<KeyAmalgamation<'a, key::SecretParts, R>>
    for KeyAmalgamation<'a, key::PublicParts, R>
{
    fn from(ka: KeyAmalgamation<'a, key::SecretParts, R>) -> Self {
        match ka {
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Primary(),
                ..
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Primary(),
                    _r: std::marker::PhantomData,
                },
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Subordinate(binding),
                ..
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Subordinate(binding.into()),
                    _r: std::marker::PhantomData,
                },
        }
    }
}

impl<'a, R: key::KeyRole> TryFrom<KeyAmalgamation<'a, key::PublicParts, R>>
    for KeyAmalgamation<'a, key::SecretParts, R>
{
    type Error = failure::Error;

    fn try_from(ka: KeyAmalgamation<'a, key::PublicParts, R>) -> Result<Self> {
        Ok(match ka {
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Primary(),
                ..
            } => {
                // Error out if the primary key does not have secret
                // key material.
                let _ : &KeyBinding<key::SecretParts, key::PrimaryRole>
                    = (&cert.primary).try_into()?;
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Primary(),
                    _r: std::marker::PhantomData,
                }
            }
            KeyAmalgamation {
                cert,
                binding: KeyAmalgamationBinding::Subordinate(binding),
                ..
            } =>
                KeyAmalgamation {
                    cert,
                    binding: KeyAmalgamationBinding::Subordinate(binding.try_into()?),
                    _r: std::marker::PhantomData,
                },
        })
    }
}

impl<'a, P: 'a + key::KeyParts> KeyAmalgamation<'a, P, key::PrimaryRole>
    where &'a Key<P, key::PrimaryRole>:
              From<&'a Key<key::PublicParts, key::PrimaryRole>>
{
    /// Returns the key.
    pub fn key(&self) -> &'a Key<P, key::PrimaryRole> {
        match self.binding {
            KeyAmalgamationBinding::Primary() => self.cert.primary.key().into(),
            KeyAmalgamationBinding::Subordinate(_) => unreachable!(),
        }
    }
}

impl<'a, P: 'a + key::KeyParts> KeyAmalgamation<'a, P, key::SubordinateRole> {
    /// Returns the key.
    pub fn key(&self) -> &'a Key<P, key::PrimaryRole> {
        match self.binding {
            KeyAmalgamationBinding::Primary() => unreachable!(),
            KeyAmalgamationBinding::Subordinate(binding) => binding.key().into(),
        }
    }
}

impl<'a, P: 'a + key::KeyParts> KeyAmalgamation<'a, P, key::UnspecifiedRole>
    where &'a Key<P, key::UnspecifiedRole>:
              From<&'a Key<key::PublicParts, key::PrimaryRole>>
{
    /// Returns the key.
    pub fn key(&self) -> &'a Key<P, key::UnspecifiedRole> {
        match self.binding {
            KeyAmalgamationBinding::Primary() => self.cert.primary_key().key().into(),
            KeyAmalgamationBinding::Subordinate(binding) => binding.key().into(),
        }
    }
}

impl<'a, P: 'a + key::KeyParts, R: 'a + key::KeyRole> KeyAmalgamation<'a, P, R> {
    pub(crate) fn new_primary(cert: &'a Cert) -> Self {
        KeyAmalgamation {
            cert: cert,
            binding: KeyAmalgamationBinding::Primary(),
            _r: std::marker::PhantomData,
        }
    }

    pub(crate) fn new_subordinate(
        cert: &'a Cert, binding: &'a KeyBinding<P, key::SubordinateRole>)
        -> Self
    {
        KeyAmalgamation {
            cert: cert,
            binding: KeyAmalgamationBinding::Subordinate(binding),
            _r: std::marker::PhantomData,
        }
    }

    /// Returns the key, but without conversion to P, R.
    fn generic_key(&self)
                   -> &'a Key<key::UnspecifiedParts, key::UnspecifiedRole> {
        match self {
            KeyAmalgamation { binding: KeyAmalgamationBinding::Primary(), .. } =>
                self.cert.primary.key().into(),
            KeyAmalgamation { binding: KeyAmalgamationBinding::Subordinate(ref binding), .. } =>
                binding.key().mark_parts_unspecified_ref().into(),
        }
    }

    /// Returns the certificate that the key came from.
    pub fn cert(&self) -> &'a Cert
    {
        self.cert
    }

    /// Returns whether the key contains secret key material.
    pub fn has_secret(&self) -> bool
    {
        self.generic_key().secret().is_some()
    }

    /// Returns whether the key contains unencrypted secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool
    {
        if let Some(secret) = self.generic_key().secret() {
            if let SecretKeyMaterial::Unencrypted { .. } = secret {
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Returns this key's binding.
    pub fn binding(&self) -> &'a KeyBinding<P, key::UnspecifiedRole>
        where &'a KeyBinding<P, key::UnspecifiedRole>:
            From<&'a KeyBinding<key::PublicParts, key::PrimaryRole>>
    {
        match self {
            KeyAmalgamation { binding: KeyAmalgamationBinding::Primary(), .. } =>
                (&self.cert.primary).into(),
            KeyAmalgamation { binding: KeyAmalgamationBinding::Subordinate(binding), .. } =>
                (*binding).into(),
        }
    }

    /// Returns the key's binding signature as of the reference time,
    /// if any.
    ///
    /// Note: this function is not exported.  Users of this interface
    /// should do: ka.policy(time)?.binding_signature().
    fn binding_signature<T>(&self, time: T) -> Option<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        match self {
            KeyAmalgamation {
                binding: KeyAmalgamationBinding::Primary(),
                ..
            } =>
                self.cert.primary_key_signature(time),
            KeyAmalgamation {
                binding: KeyAmalgamationBinding::Subordinate(ref binding),
                ..
            } =>
                binding.binding_signature(time),
        }
    }

    /// Sets the reference time for the amalgamation.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// This transforms the `KeyAmalgamation` into a
    /// `ValidKeyAmalgamation`.
    pub fn policy<T>(self, time: T)
        -> Result<ValidKeyAmalgamation<'a, P, R>>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        if let Some(binding_signature) = self.binding_signature(time) {
            Ok(ValidKeyAmalgamation {
                a: self,
                time: time,
                binding_signature: binding_signature,
            })
        } else {
            Err(Error::NoBindingSignature(time).into())
        }
    }
}

/// A `Key` and its associated data.
///
/// A `ValidKeyAmalgamation` includes a reference time, and is
/// guaranteed to have a live binding signature at that time.
#[derive(Debug, Clone)]
pub struct ValidKeyAmalgamation<'a, P: key::KeyParts, R: key::KeyRole> {
    a: KeyAmalgamation<'a, P, R>,

    // The reference time.
    time: SystemTime,
    // The binding signature at time `time`.  (This is just a cache.)
    binding_signature: &'a Signature,
}

impl<'a, P: key::KeyParts, R: key::KeyRole> Deref for ValidKeyAmalgamation<'a, P, R> {
    type Target = KeyAmalgamation<'a, P, R>;

    fn deref(&self) -> &Self::Target {
        &self.a
    }
}

// We can't make the key parts generic, because then the impl would
// conflict with 'impl<T> std::convert::From<T> for T'.
impl<'a, R: key::KeyRole> From<ValidKeyAmalgamation<'a, key::PublicParts, R>>
    for ValidKeyAmalgamation<'a, key::UnspecifiedParts, R>
{
    fn from(ka: ValidKeyAmalgamation<'a, key::PublicParts, R>) -> Self {
        ValidKeyAmalgamation {
            a: ka.a.into(),
            time: ka.time,
            binding_signature: ka.binding_signature,
        }
    }
}

impl<'a, R: key::KeyRole> From<ValidKeyAmalgamation<'a, key::SecretParts, R>>
    for ValidKeyAmalgamation<'a, key::PublicParts, R>
{
    fn from(ka: ValidKeyAmalgamation<'a, key::SecretParts, R>) -> Self {
        ValidKeyAmalgamation {
            a: ka.a.into(),
            time: ka.time,
            binding_signature: ka.binding_signature,
        }
    }
}

impl<'a, R: key::KeyRole> TryFrom<ValidKeyAmalgamation<'a, key::PublicParts, R>>
    for ValidKeyAmalgamation<'a, key::SecretParts, R>
{
    type Error = failure::Error;

    fn try_from(ka: ValidKeyAmalgamation<'a, key::PublicParts, R>)
                -> Result<Self> {
        Ok(ValidKeyAmalgamation {
            a: ka.a.try_into()?,
            time: ka.time,
            binding_signature: ka.binding_signature,
        })
    }
}

impl<'a, P: 'a + key::KeyParts, R: 'a + key::KeyRole>
    ValidKeyAmalgamation<'a, P, R>
{
    /// Returns the amalgamation's reference time.
    ///
    /// For queries that are with respect to a point in time, this
    /// determines that point in time.  For instance, if a key is
    /// created at `t_c` and expires at `t_e`, then
    /// `ValidKeyAmalgamation::alive` will return true if the reference
    /// time is greater than or equal to `t_c` and less than `t_e`.
    pub fn time(&self) -> SystemTime {
        self.time
    }

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    pub fn policy<T>(self, time: T) -> Result<Self>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        self.a.policy(time)
    }

    /// Returns the key's binding signature as of the reference time,
    /// if any.
    pub fn binding_signature(&self) -> &'a Signature
    {
        self.binding_signature
    }

    /// Returns the key's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// Note: this function only returns whether the key has been
    /// revoked, it does not return whether the certificate has been
    /// revoked.
    pub fn revoked(&self) -> RevocationStatus<'a>
    {
        match self {
            ValidKeyAmalgamation {
                a: KeyAmalgamation {
                    binding: KeyAmalgamationBinding::Primary(),
                    ..
                },
                ..
            } =>
                self.cert.revoked(self.time()),
            ValidKeyAmalgamation {
                a: KeyAmalgamation {
                    binding: KeyAmalgamationBinding::Subordinate(ref binding),
                    ..
                },
                ..
            } =>
                binding.revoked(self.time()),
        }
    }

    /// Returns the certificate's revocation status as of the
    /// amalgamtion's reference time.
    pub fn cert_revoked(&self) -> RevocationStatus<'a>
    {
        self.cert().revoked(self.time())
    }

    /// Returns the key's key flags as of the amalgamtion's
    /// reference time.
    pub fn key_flags(&self) -> Option<KeyFlags> {
        self.binding_signature.key_flags()
    }

    /// Returns whether the key has at least one of the specified key
    /// flags as of the amalgamtion's reference time.
    pub fn has_any_key_flag<F>(&self, flags: F) -> bool
        where F: Borrow<KeyFlags>
    {
        let our_flags = self.key_flags().unwrap_or_default();
        !(&our_flags & flags.borrow()).is_empty()
    }

    /// Returns whether key is certification capable as of the
    /// amalgamtion's reference time.
    pub fn for_certification(&self) -> bool {
        self.has_any_key_flag(KeyFlags::empty().set_certification(true))
    }

    /// Returns whether key is signing capable as of the amalgamtion's
    /// reference time.
    pub fn for_signing(&self) -> bool {
        self.has_any_key_flag(KeyFlags::empty().set_signing(true))
    }

    /// Returns whether key is authentication capable as of the
    /// amalgamtion's reference time.
    pub fn for_authentication(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_authentication(true))
    }

    /// Returns whether key is intended for storage encryption as of
    /// the amalgamtion's reference time.
    pub fn for_storage_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_storage_encryption(true))
    }

    /// Returns whether key is intended for transport encryption as of the
    /// amalgamtion's reference time.
    pub fn for_transport_encryption(&self) -> bool
    {
        self.has_any_key_flag(KeyFlags::empty().set_transport_encryption(true))
    }

    /// Returns whether the certificateis alive as of the
    /// amalgamtion's reference time.
    pub fn cert_alive(&self) -> Result<()>
    {
        self.cert().alive(self.time())
    }

    /// Returns whether the key is alive as of the amalgamtion's
    /// reference time.
    ///
    /// Note: this does not return whether the certificate is valid.
    pub fn alive(&self) -> Result<()>
    {
        self.binding_signature.key_alive(self.generic_key(), self.time())
    }

    /// Returns whether the key contains secret key material.
    pub fn has_secret(&self) -> bool
    {
        self.generic_key().secret().is_some()
    }

    /// Returns whether the key contains unencrypted secret key
    /// material.
    pub fn has_unencrypted_secret(&self) -> bool
    {
        if let Some(secret) = self.generic_key().secret() {
            if let SecretKeyMaterial::Unencrypted { .. } = secret {
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Returns this key's binding.
    pub fn binding(&self) -> &'a KeyBinding<P, key::UnspecifiedRole>
        where &'a KeyBinding<P, key::UnspecifiedRole>:
            From<&'a KeyBinding<key::PublicParts, key::PrimaryRole>>
    {
        match self {
            ValidKeyAmalgamation {
                a: KeyAmalgamation {
                    binding: KeyAmalgamationBinding::Primary(), ..
                },
                ..
            } =>
                (&self.cert.primary).into(),
            ValidKeyAmalgamation {
                a: KeyAmalgamation {
                    binding: KeyAmalgamationBinding::Subordinate(binding),
                    ..
                },
                ..
            } =>
                (*binding).into(),
        }
    }
}
