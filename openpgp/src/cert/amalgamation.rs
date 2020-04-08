//! Components, their associated signatures, and some useful methods.
//!
//! Whereas a [`ComponentBundle`] owns a `Component` and its
//! associated [`Signature`]s, a [`ComponentAmalgamation`] references
//! a `ComponentBundle` and its containing [`Cert`].  This additional
//! context means that a `ComponentAmalgamation` can implement more of
//! OpenPGP's high-level semantics than a `ComponentBundle` can.  For
//! instance, most of the information about a primary key, such as its
//! capabilities, is on the primary User ID's binding signature.  A
//! `ComponentAmalgamation` can find the certificate's primary User
//! ID; a `ComponentBundle` can't.  Similarly, when looking up a
//! subpacket, if it isn't present in the component's binding
//! signature, then an OpenPGP implementation is supposed to consult
//! the certificate's direct key signatures.  A
//! `ComponentAmalgamation` has access to this information; a
//! `ComponentBundle` doesn't.
//!
//! Given the limitations of a `ComponentBundle`, it would seem more
//! useful to just change it to include a reference to its containing
//! certificate.  That change would make `ComponentAmalgamation`s
//! redundant.  Unfortunately, this isn't possible, because it would
//! result in a self-referential data structure, which Rust doesn't
//! allow.  To understand how this arises, consider a certificate `C`,
//! which contains a `ComponentBundle` `B`.  If `B` contains a
//! reference to `C`, then `C` references itself, because `C` contains
//! `B`!
//!
//! # Policy
//!
//! Although a `ComponentAmalgamation` contains the information
//! necessary to realize high-level OpenPGP functionality, components
//! can have multiple self signatures, and functions that consult the
//! binding signature need to determine the best one to use.  There
//! are two mains concerns here.
//!
//! First, we need to protect the user from forgeries.  As attacks
//! improve, cryptographic algorithms that were once considered secure
//! now provide insufficient security margins.  For instance, in 2007
//! it was possible to find [MD5 collisions] using just a few seconds
//! of computing time on a commodity computer.  Sequoia provides a
//! flexible mechanism, called [Policy] objects, that allow users to
//! implement this type of filtering: before a self signature is used,
//! a policy object is queried to determine whether the `Signature`
//! should be rejected.  If so, the `Signature` is skipped.
//!
//! Second, we need an algorithm to find the most appropriate
//! self-signature.  Obvious non-candidate self signature are self
//! signatures whose creation time is in the future.  We don't assume
//! that these self signatures are bad per se, but that they represent
//! policy that should go into effect some time in the future.
//!
//! We extend this idea of a self signature representing a policy for
//! a certain period of time to all self signatures.  In particular,
//! Sequoia takes the view that *a binding signature represents a
//! policy that is valid from its creation time until its expiry*.
//! Thus, when considering what self signature to use, we need a
//! reference time.  Given the reference time, we then use the self
//! signature that was in effect at that time, i.e., the most recent,
//! non-expired, non-revoked self signature that was created at or
//! prior to the reference time.  In other words, we ignore self
//! signatures created after the reference time.  We take the position
//! that if the certificate holder wants a new policy to apply to
//! existing signatures, then the new self signature should be
//! backdated, and existing self signatures revoked, if necessary.
//!
//! Consider evaluating signatures over a document.  Sequoia's
//! [streaming verifier] uses the signature's creation time as the
//! reference time.  Thus, if the signature was created on June 9th,
//! 2011, then, when evaluating that signature, the streaming verifier
//! uses a self-signature that was alive at that time, since that was
//! the self-signature that represented the signer's policy at the
//! time the signature was created.
//!
//! A consequence of this approach is that even if the self-signature
//! were considered expired at the time the signature was evaluated
//! (e.g., "now"), this fact doesn't invalidate the signature.  That
//! is, a self-siganture's lifetime does not impact a signature's
//! lifetime; a signature's lifetime is defined by its own creation
//! time and expiry.  Likewise, a key's lifetime is defined by its own
//! creation time and expiry.
//!
//! This interpretation of lifetimes removes a major disadvantage that
//! comes with fast rotation of subkeys: if an implementation binds
//! the lifetime of signatures to the signing key, and the key
//! expires, then old messages are considered invalid.  Consider a
//! user who generates a new signature subkey each week, and sets it
//! to expire after exactly one week.  If we use the policy that the
//! signature is only valid while the key and self signatures are
//! alive, then if someone checks the signature a week after receiving
//! it, the signature will be considered invalid, because the key has
//! expired.  The practical result is that all old messages from this
//! user will be considered invalid!  Unfortunately, this will result
//! in users becoming accustomed to seeing invalid signatures, and
//! cause them to be less suspcious of them.
//!
//! Note: the possibility of abuse of this interpretation is limited.
//! If the key has been compromised, then the right thing to do is to
//! revoked it.  Expiry doesn't help.  The attacker can simply create
//! self-signatures that say whatevery she wants.  Assuming the secret
//! key material has not been compromised, then an attacker could
//! reuse a message that might otherwise be considered expired.
//! However, the attacker will not be able to change the signature's
//! creation time, so, assuming a mail context and MUAs that check
//! that the time in the message's headers matches the signature's
//! creation time, the mails will appear old.  Further, this type of
//! attack will be mitigated by the proposed "[Intended Recipients]"
//! subpacket, which more tightly binds the message to its context.
//!
//! # [`ValidComponetAmalgamation`]
//!
//! Oftentimes, a `ComponentAmalgamation` isn't just used once for
//! some operation, but many times.  Passing around the same policy
//! and the same reference time to each invocation cluters the code
//! and can introduce subtle bugs.  In particular, when using the
//! current time as the reference time, the interfaces allow the
//! caller to pass in `None`.  But if the operation is long running,
//! then the current time changes, which can cause subtle
//! inconsistencies.  In these cases, the correct approach is to use
//! the current time at the start of the operation.
//!
//! Alternatively, the `ValidComponetAmalgamation` data structure
//! embeds a policy and a reference time, and automatically passes
//! them to methods on the wrapped `ComponetAmalgamation`.  When
//! passed `None` for the reference time, the
//! `ValidComponetAmalgamation` constructor stores the current time,
//! and uses that for all operations.
//!
//! # Lifetimes
//!
//! `ComponentAmalgamation` autoderefs to `ComponentBundle`.
//! Unfortunately, due to the definition of the [`Deref` trait],
//! `ComponentBundle` is assigned the same lifetime as
//! `ComponentAmalgamation`.  However, particularly when using
//! combinators like [`std::iter::map`], the `ComponentBundle`'s
//! lifetime is longer.  Consider the following code, which doesn't
//! compile:
//!
//! ```compile_fail
//! # extern crate sequoia_openpgp as openpgp;
//! use openpgp::cert::prelude::*;
//! use openpgp::packet::prelude::*;
//!
//! # let (cert, _) = CertBuilder::new()
//! #     .add_userid("Alice")
//! #     .add_signing_subkey()
//! #     .add_transport_encryption_subkey()
//! #     .generate().unwrap();
//! cert.userids()
//!     .map(|ua| {
//!         // Use auto deref to get the containing `&ComponentBundle`.
//!         let b : &ComponentBundle<_> = &ua;
//!         b
//!     })
//!     .collect::<Vec<&UserID>>();
//! ```
//!
//! Compiling it results in the following error:
//!
//! > `b` returns a value referencing data owned by the current
//! function
//!
//! This error occurs because the `Deref` trait says that the lifetime
//! of the target, i.e., `&ComponentBundle`, is bounded by `ua`'s
//! lifetime, whose lifetime is indeed limited to the closure.  But,
//! `&ComponentBundle` is independent of `ua`; it is a copy of the
//! `ComponentAmalgamation`'s reference to the `ComponentBundle` whose
//! lifetime is `'a`!  Unfortunately, this can't be expressed using
//! `Deref`, but it can be done using separate methods as shown below
//! for the [`ComponentAmalgamation::component`] method:
//!
//! ```
//! # extern crate sequoia_openpgp as openpgp;
//! use openpgp::cert::prelude::*;
//! use openpgp::packet::prelude::*;
//!
//! # let (cert, _) = CertBuilder::new()
//! #     .add_userid("Alice")
//! #     .add_signing_subkey()
//! #     .add_transport_encryption_subkey()
//! #     .generate().unwrap();
//! cert.userids()
//!     .map(|ua| {
//!         // ua's lifetime is this closure.  But `component()`
//!         // returns a reference whose lifetime is that of the
//!         // `cert`.
//!         ua.component()
//!     })
//!     .collect::<Vec<&UserID>>();
//! ```
//!
//! [`ComponentBundle`]: ../bundle/index.html
//! [`Signature`]: ../../packet/signature/index.html
//! [`ComponentAmalgamation`]: struct.ComponentAmalgamation.html
//! [`Cert`]: ../index.html
//! [`ValidComponetAmalgamation`]: struct.ValidComponentAmalgamation.html
//! [`std::iter::map`]: https://doc.rust-lang.org/std/iter/struct.Map.html
//! [MD5 collisions]: https://en.wikipedia.org/wiki/MD5
//! [Policy]: ../../policy/index.html
//! [streaming verifier]: ../../parse/stream.html
//! [Intended Recipients]: https://www.ietf.org/id/draft-ietf-openpgp-rfc4880bis-09.html#name-intended-recipient-fingerpr
//! [forward secrecy]: https://tools.ietf.org/html/draft-brown-pgp-pfs-03
//! [`Deref` trait]: https://doc.rust-lang.org/stable/std/ops/trait.Deref.html
use std::time;
use std::time::SystemTime;
use std::clone::Clone;

use crate::{
    cert::prelude::*,
    Error,
    packet::{
        Signature,
        Unknown,
        UserAttribute,
        UserID,
    },
    Result,
    policy::Policy,
    types::{
        AEADAlgorithm,
        CompressionAlgorithm,
        Features,
        HashAlgorithm,
        KeyServerPreferences,
        RevocationKey,
        RevocationStatus,
        SymmetricAlgorithm,
    },
};

mod iter;
pub use iter::{
    ComponentAmalgamationIter,
    UnknownComponentAmalgamationIter,
    UserAttributeAmalgamationIter,
    UserIDAmalgamationIter,
    ValidComponentAmalgamationIter,
    ValidUnknownComponentAmalgamationIter,
    ValidUserAttributeAmalgamationIter,
    ValidUserIDAmalgamationIter,
};

mod keyiter;
pub use keyiter::{
    KeyAmalgamationIter,
    ValidKeyAmalgamationIter,
};

mod key;
pub use key::{
    ErasedKeyAmalgamation,
    KeyAmalgamation,
    PrimaryKey,
    PrimaryKeyAmalgamation,
    SubordinateKeyAmalgamation,
    ValidErasedKeyAmalgamation,
    ValidKeyAmalgamation,
    ValidPrimaryKeyAmalgamation,
    ValidSubordinateKeyAmalgamation,
};

/// Applies a policy to an amalgamation.
///
/// Note: This trait is split off from the `ComponentAmalgamation`
/// trait, to reduce code duplication: it is often possible to provide
/// blanket implementations of `ComponentAmalgamation`, but the
/// `ValidateAmalgamation` trait can only be implemented on more
/// concrete types.
pub trait ValidateAmalgamation<'a, C: 'a> {
    /// The type returned by `with_policy`.
    type V;

    /// Uses the specified `Policy` and reference time with the amalgamation.
    ///
    /// If `time` is `None`, the current time is used.
    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized;
}

/// Applies a policy to an amalgamation.
///
/// This is an internal variant of `ValidateAmalgamation`, which
/// allows validating a component for an otherwise invalid
/// certificate.  See `ValidComponentAmalgamation::primary` for an
/// explanation.
trait ValidateAmalgamationRelaxed<'a, C: 'a> {
    /// The type returned by `with_policy`.
    type V;

    /// Changes the amalgamation's policy.
    ///
    /// If `time` is `None`, the current time is used.
    ///
    /// If `valid_cert` is `false`, then this does not also check
    /// whether the certificate is valid; it only checks whether the
    /// component is valid.  Normally, this should be `true`.  This
    /// option is only expose to allow breaking an infinite recursion:
    ///
    ///   - To check if a certificate is valid, we check if the
    ///     primary key is valid.
    ///
    ///   - To check if the primary key is valid, we need the primary
    ///     key's self signature
    ///
    ///   - To find the primary key's self signature, we need to find
    ///     the primary user id
    ///
    ///   - To find the primary user id, we need to check if the user
    ///     id is valid.
    ///
    ///   - To check if the user id is valid, we need to check that
    ///     the corresponding certificate is valid.
    fn with_policy_relaxed<T>(self, policy: &'a dyn Policy, time: T,
                              valid_cert: bool) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized;
}

/// Methods for valid amalgamations.
///
/// The methods exposed by a `ValidComponentAmalgamation` are similar
/// to those exposed by a `ComponentAmalgamation`, but the policy and
/// reference time are included in the `ValidComponentAmalgamation`.
/// This helps prevent using different policies or different reference
/// times when using a component, which can easily happen when the
/// checks span multiple functions.
pub trait ValidAmalgamation<'a, C: 'a>
{
    /// Maps the given function over binding and direct key signature.
    ///
    /// Makes `f` consider both the binding signature and the direct
    /// key signature.  Information in the binding signature takes
    /// precedence over the direct key signature.  See also [Section
    /// 5.2.3.3 of RFC 4880].
    ///
    ///   [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    fn map<F: Fn(&'a Signature) -> Option<T>, T>(&self, f: F) -> Option<T> {
        f(self.binding_signature())
            .or_else(|| self.direct_key_signature().ok().and_then(f))
    }

    /// Returns the valid amalgamation's associated certificate.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::StandardPolicy;
    /// #
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let cert = ua.cert();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let fpr = cert.fingerprint();
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     assert_eq!(ua.cert().fingerprint(), fpr);
    /// #     f(&ua.with_policy(p, None)?);
    /// #     Ok(())
    /// # }
    /// ```
    fn cert(&self) -> &ValidCert<'a>;

    /// Returns the amalgamation's reference time.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::time::{SystemTime, Duration, UNIX_EPOCH};
    /// #
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::StandardPolicy;
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let t = ua.time();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p = &StandardPolicy::new();
    /// #     let t = UNIX_EPOCH + Duration::from_secs(1554542220);
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .set_creation_time(t)
    /// #         .generate()?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     let ua = ua.with_policy(p, t)?;
    /// #     assert_eq!(t, ua.time());
    /// #     f(&ua);
    /// #     Ok(())
    /// # }
    /// ```
    fn time(&self) -> SystemTime;

    /// Returns the amalgamation's policy.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::{Policy, StandardPolicy};
    /// #
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let policy = ua.policy();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p : &dyn Policy = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     let ua = ua.with_policy(p, None)?;
    /// #     assert!(std::ptr::eq(p, ua.policy()));
    /// #     f(&ua);
    /// #     Ok(())
    /// # }
    /// ```
    fn policy(&self) -> &'a dyn Policy;

    /// Returns the component's binding signature as of the reference time.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::{Policy, StandardPolicy};
    /// #
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let sig = ua.binding_signature();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p : &dyn Policy = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     let ua = ua.with_policy(p, None)?;
    /// #     f(&ua);
    /// #     Ok(())
    /// # }
    /// ```
    fn binding_signature(&self) -> &'a Signature;

    /// Returns the certificate's direct key signature as of the
    /// reference time, if any.
    ///
    /// Subpackets on direct key signatures apply to all components of
    /// the certificate, cf. [Section 5.2.3.3 of RFC 4880].
    ///
    /// [Section 5.2.3.3 of RFC 4880]: https://tools.ietf.org/html/rfc4880#section-5.2.3.3
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::{Policy, StandardPolicy};
    /// #
    /// fn f(ua: &ValidUserIDAmalgamation) {
    ///     let sig = ua.direct_key_signature();
    ///     // ...
    /// }
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p : &dyn Policy = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let cert = cert.with_policy(p, None)?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// #     assert!(std::ptr::eq(ua.direct_key_signature().unwrap(),
    /// #                          cert.direct_key_signature().unwrap()));
    /// #     f(&ua);
    /// #     Ok(())
    /// # }
    /// ```
    fn direct_key_signature(&self) -> Result<&'a Signature> {
        self.cert().cert.primary.binding_signature(self.policy(), self.time())
    }

    /// Returns the component's revocation status as of the amalgamation's
    /// reference time.
    ///
    /// This does *not* check whether the certificate has been
    /// revoked.  For that, use `Cert::revoked()`.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// # use openpgp::policy::StandardPolicy;
    /// # use openpgp::types::RevocationStatus;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// #     let p = &StandardPolicy::new();
    /// #     let (cert, _) =
    /// #         CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #         .generate()?;
    /// #     let cert = cert.with_policy(p, None)?;
    /// #     let ua = cert.userids().nth(0).expect("User IDs");
    /// match ua.revoked() {
    ///     RevocationStatus::Revoked(revs) => {
    ///         // The certificate holder revoked the User ID.
    /// #       unreachable!();
    ///     }
    ///     RevocationStatus::CouldBe(revs) => {
    ///         // There are third-party revocations.  You still need
    ///         // to check that they are valid (this is necessary,
    ///         // because without the Certificates are not normally
    ///         // available to Sequoia).
    /// #       unreachable!();
    ///     }
    ///     RevocationStatus::NotAsFarAsWeKnow => {
    ///         // We have no evidence that the User ID is revoked.
    ///     }
    /// }
    /// #     Ok(())
    /// # }
    /// ```
    fn revoked(&self) -> RevocationStatus<'a>;

    /// Returns a list of any designated revokers for this component.
    ///
    /// This function returns the designated revokers listed on both
    /// this component's binding signature and the certificate's
    /// direct key signature.
    ///
    /// Note: the returned list has not been deduplicated.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::Result;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::policy::StandardPolicy;
    /// use openpgp::types::RevocationKey;
    ///
    /// # fn main() -> Result<()> {
    /// let p = &StandardPolicy::new();
    ///
    /// let (alice, _) =
    ///     CertBuilder::general_purpose(None, Some("alice@example.org"))
    ///     .generate()?;
    /// let (bob, _) =
    ///     CertBuilder::general_purpose(None, Some("bob@example.org"))
    ///     .set_revocation_keys(vec![ (&alice).into() ])
    ///     .generate()?;
    ///
    /// assert_eq!(bob.primary_userid(p, None)?.revocation_keys()
    ///                .collect::<Vec<&RevocationKey>>(),
    ///            vec![ &(&alice).into() ]);
    /// # Ok(()) }
    /// ```
    fn revocation_keys(&self)
                       -> Box<dyn Iterator<Item = &'a RevocationKey> + 'a>
    {
        if let Some(dk) = self.direct_key_signature().ok() {
            let bs = self.binding_signature();
            if std::ptr::eq(dk, bs) {
                // Avoid unnecessary duplicates.
                Box::new(bs.revocation_keys())
            } else {
                Box::new(bs.revocation_keys().chain(dk.revocation_keys()))
            }
        } else {
            Box::new(self.binding_signature().revocation_keys())
        }
    }
}

/// A certificate component, its associated signatures, and useful
/// methods.
#[derive(Debug, PartialEq)]
pub struct ComponentAmalgamation<'a, C> {
    cert: &'a Cert,
    bundle: &'a ComponentBundle<C>,
}

/// A User ID and its associated data.
///
/// This is just a specialized version of `ComponentAmalgamation`.
pub type UserIDAmalgamation<'a> = ComponentAmalgamation<'a, UserID>;

/// A User Attribute and its associated data.
///
/// This is just a specialized version of `ComponentAmalgamation`.
pub type UserAttributeAmalgamation<'a>
    = ComponentAmalgamation<'a, UserAttribute>;

/// An Unknown component and its associated data.
///
/// This is just a specialized version of `ComponentAmalgamation`.
pub type UnknownComponentAmalgamation<'a>
    = ComponentAmalgamation<'a, Unknown>;

// derive(Clone) doesn't work with generic parameters that don't
// implement clone.  But, we don't need to require that C implements
// Clone, because we're not cloning C, just the reference.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<'a, C> Clone for ComponentAmalgamation<'a, C> {
    fn clone(&self) -> Self {
        Self {
            cert: self.cert,
            bundle: self.bundle,
        }
    }
}

impl<'a, C> std::ops::Deref for ComponentAmalgamation<'a, C> {
    type Target = ComponentBundle<C>;

    fn deref(&self) -> &Self::Target {
        self.bundle
    }
}

impl<'a, C> ComponentAmalgamation<'a, C> {
    /// Creates a new amalgamation.
    pub(crate) fn new(cert: &'a Cert, bundle: &'a ComponentBundle<C>) -> Self
    {
        Self {
            cert,
            bundle,
        }
    }

    /// Returns the component's associated certificate.
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// # use openpgp::cert::prelude::*;
    /// #
    /// # fn main() -> openpgp::Result<()> {
    /// # let (cert, _) =
    /// #     CertBuilder::general_purpose(None, Some("alice@example.org"))
    /// #     .generate()?;
    /// for u in cert.userids() {
    ///     // It's not only an identical `Cert`, it's the same one.
    ///     assert!(std::ptr::eq(u.cert(), &cert));
    /// }
    /// # Ok(()) }
    /// ```
    pub fn cert(&self) -> &'a Cert {
        &self.cert
    }

    /// Selects a binding signature.
    ///
    /// Uses the provided policy and reference time to select an
    /// appropriate binding signature.
    ///
    /// Note: this function is not exported.  Users of this interface
    /// should do: ca.with_policy(policy, time)?.binding_signature().
    fn binding_signature<T>(&self, policy: &dyn Policy, time: T)
        -> Result<&'a Signature>
        where T: Into<Option<time::SystemTime>>
    {
        let time = time.into().unwrap_or_else(SystemTime::now);
        self.bundle.binding_signature(policy, time)
    }

    /// Returns this amalgamation's bundle.
    ///
    /// Note: although `ComponentAmalgamation` derefs to a
    /// `&ComponentBundle`, this method provides a more accurate
    /// lifetime, which is helpful when returning the reference from a
    /// function.  [See the module's documentation] for more details.
    ///
    /// [See the module's documentation]: index.html
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate sequoia_openpgp as openpgp;
    /// use openpgp::cert::prelude::*;
    /// use openpgp::packet::prelude::*;
    ///
    /// # let (cert, _) = CertBuilder::new()
    /// #     .add_userid("Alice")
    /// #     .add_signing_subkey()
    /// #     .add_transport_encryption_subkey()
    /// #     .generate().unwrap();
    /// cert.userids()
    ///     .map(|ua| {
    ///         // The following doesn't work:
    ///         //
    ///         //   let b : &ComponentBundle<_> = &ua; b
    ///         //
    ///         // Because ua's lifetime is this closure and autoderef
    ///         // assigns `b` the same lifetime as `ua`.  `bundle()`,
    ///         // however, returns a reference whose lifetime is that
    ///         // of the `cert`.
    ///         ua.bundle()
    ///     })
    ///     .collect::<Vec<&ComponentBundle<_>>>();
    /// ```
    pub fn bundle(&self) -> &'a ComponentBundle<C> {
        &self.bundle
    }

    /// Returns this amalgamation's component.
    ///
    /// Note: although `ComponentAmalgamation` derefs to a
    /// `&Component` (via `&ComponentBundle`), this method provides a
    /// more accurate lifetime, which is helpful when returning the
    /// reference from a function.  [See the module's documentation]
    /// for more details.
    ///
    /// [See the module's documentation]: index.html
    pub fn component(&self) -> &'a C {
        self.bundle().component()
    }

    /// The component's self-signatures.
    ///
    /// This method is a forwarder for
    /// [`ComponentBundle::self_signatures`].  Although
    /// `ComponentAmalgamation` derefs to a `&ComponentBundle`, this
    /// method provides a more accurate lifetime, which is helpful
    /// when returning the reference from a function.  [See the
    /// module's documentation] for more details.
    ///
    /// [`ComponentBundle::self_signatures`]: ../bundle/struct.ComponentBundle.html#method.self_signatures
    /// [See the module's documentation]: index.html
    pub fn self_signatures(&self) -> &'a [Signature] {
        self.bundle().self_signatures()
    }

    /// The component's third-party certifications.
    ///
    /// This method is a forwarder for
    /// [`ComponentBundle::certifications`].  Although
    /// `ComponentAmalgamation` derefs to a `&ComponentBundle`, this
    /// method provides a more accurate lifetime, which is helpful
    /// when returning the reference from a function.  [See the
    /// module's documentation] for more details.
    ///
    /// [`ComponentBundle::certifications`]: ../bundle/struct.ComponentBundle.html#method.certifications
    /// [See the module's documentation]: index.html
    pub fn certifications(&self) -> &'a [Signature] {
        self.bundle().certifications()
    }

    /// The component's revocations that were issued by the
    /// certificate holder.
    ///
    /// This method is a forwarder for
    /// [`ComponentBundle::self_revocations`].  Although
    /// `ComponentAmalgamation` derefs to a `&ComponentBundle`, this
    /// method provides a more accurate lifetime, which is helpful
    /// when returning the reference from a function.  [See the
    /// module's documentation] for more details.
    ///
    /// [`ComponentBundle::self_revocations`]: ../bundle/struct.ComponentBundle.html#method.self_revocations
    /// [See the module's documentation]: index.html
    pub fn self_revocations(&self) -> &'a [Signature] {
        self.bundle().self_revocations()
    }

    /// The component's revocations that were issued by other
    /// certificates.
    ///
    /// This method is a forwarder for
    /// [`ComponentBundle::other_revocations`].  Although
    /// `ComponentAmalgamation` derefs to a `&ComponentBundle`, this
    /// method provides a more accurate lifetime, which is helpful
    /// when returning the reference from a function.  [See the
    /// module's documentation] for more details.
    ///
    /// [`ComponentBundle::other_revocations`]: ../bundle/struct.ComponentBundle.html#method.other_revocations
    /// [See the module's documentation]: index.html
    pub fn other_revocations(&self) -> &'a [Signature] {
        self.bundle().other_revocations()
    }
}

macro_rules! impl_with_policy {
    ($func:ident, $value:ident $(, $arg:ident: $type:ty )*) => {
        fn $func<T>(self, policy: &'a dyn Policy, time: T, $($arg: $type, )*)
            -> Result<Self::V>
            where T: Into<Option<time::SystemTime>>,
                  Self: Sized
        {
            let time = time.into().unwrap_or_else(SystemTime::now);

            if $value {
                self.cert.with_policy(policy, time)?;
            }

            let binding_signature = self.binding_signature(policy, time)?;
            let cert = self.cert;
            // We can't do `Cert::with_policy` as that would
            // result in infinite recursion.  But at this point,
            // we know the certificate is valid (unless the caller
            // doesn't care).
            Ok(ValidComponentAmalgamation {
                ca: self,
                cert: ValidCert {
                    cert: cert,
                    policy: policy,
                    time: time,
                },
                binding_signature: binding_signature,
            })
        }
    }
}

impl<'a, C> ValidateAmalgamation<'a, C> for ComponentAmalgamation<'a, C> {
    type V = ValidComponentAmalgamation<'a, C>;

    impl_with_policy!(with_policy, true);
}

impl<'a, C> ValidateAmalgamationRelaxed<'a, C> for ComponentAmalgamation<'a, C> {
    type V = ValidComponentAmalgamation<'a, C>;

    impl_with_policy!(with_policy_relaxed, valid_cert, valid_cert: bool);
}

/// A `ComponentAmalgamation` specialized for `UserID`s.
pub type UserIDAmalgamation<'a> = ComponentAmalgamation<'a, crate::packet::UserID>;

impl<'a> ComponentAmalgamation<'a, crate::packet::UserID> {
    /// Returns a reference to the User ID.
    ///
    /// Note: although `ComponentAmalgamation<UserID>` derefs to a
    /// `&UserID` (via `&ComponentBundle`), this method provides a
    /// more accurate lifetime, which is helpful when returning the
    /// reference from a function.  [See the module's documentation]
    /// for more details.
    ///
    /// [See the module's documentation]: index.html
    pub fn userid(&self) -> &'a crate::packet::UserID {
        self.component()
    }
}

/// A `ComponentAmalgamation` specialized for `UserAttributes`s.
pub type UserAttributeAmalgamation<'a> = ComponentAmalgamation<'a, crate::packet::UserAttribute>;

impl<'a> ComponentAmalgamation<'a, crate::packet::UserAttribute> {
    /// Returns a reference to the User Attribute.
    ///
    /// Note: although `ComponentAmalgamation<UserAttribute>` derefs
    /// to a `&UserAttribute` (via `&ComponentBundle`), this method
    /// provides a more accurate lifetime, which is helpful when
    /// returning the reference from a function.  [See the module's
    /// documentation] for more details.
    ///
    /// [See the module's documentation]: index.html
    pub fn user_attribute(&self) -> &'a crate::packet::UserAttribute {
        self.component()
    }
}

/// A `ComponentAmalgamation` plus a `Policy` and a reference time.
///
/// A `ValidComponentAmalgamation` combines a
/// [`ComponentAmalgamation`] with a [`Policy`] and a reference time.
/// This makes it easy to call methods that require this information,
/// and it helps ensure that the same policy and reference time are
/// used for multipart operations.
///
/// A `ComponentAmalgamation` is normally turned into a
/// `ValidComponentAmalgamation` using
/// [`ComponentAmalgamation::with_policy`]
///
/// # Example
///
/// ```
/// # extern crate sequoia_openpgp as openpgp;
/// use openpgp::cert::prelude::*;
/// use openpgp::packet::prelude::*;
/// use openpgp::policy::StandardPolicy;
/// use openpgp::types::RevocationStatus;
///
/// # fn main() -> openpgp::Result<()> {
/// let p = &StandardPolicy::new();
/// # let (cert, _) = CertBuilder::new()
/// #     .add_userid("Alice")
/// #     .add_signing_subkey()
/// #     .add_transport_encryption_subkey()
/// #     .generate().unwrap();
/// for u in cert.userids() {
///     // Create a `ValidComponentAmalgamation`.  This may fail if
///     // there are no binding signatures that are accepted by the
///     // policy and live right now.
///     let u = u.with_policy(p, None)?;
///
///     // Before using the User ID, we still need to check that it is
///     // alive and not revoked; `ComponentAmalgamation::with_policy`
///     // ensures that there is a valid *binding signature*, not that
///     // the `Component` is valid.
///     //
///     // Note: `ValidComponentAmalgamation::revoked` and
///     // `Preferences::preferred_symmetric_algorithms` uses th
///     // embeded policy and timestamp.  Even though we used `None` for
///     // the timestamp, which means the current time, they are
///     // guaranteed to use the same timestamp, because `with_policy`
///     // eagerly transforms it into the current time.
///     //
///     // Note: we only check whether the User ID is not revoked.  If
///     // we were using a key, we'd also want to check that it is alive.
///     // (Keys can expire, but User IDs do not.)
///     if let RevocationStatus::Revoked(_revs) = u.revoked() {
///         // Revoked by the key owner.  (If we care about
///         // designated revokers, then we need to check those
///         // ourselves.)
///     } else {
///         eprintln!("{}: preferred symmetric algorithms: {:?}",
///                   String::from_utf8_lossy(u.value()),
///                   u.preferred_symmetric_algorithms());
///     }
/// }
/// # Ok(()) }
/// ```
///
/// [`ComponentAmalgamation`]: struct.ComponentAmalgamation.html
/// [`Policy`]: ../../policy/index.html
/// [`ComponentAmalgamation::with_policy`]: trait.ValidateAmalgamation.html#tymethod.with_policy
#[derive(Debug)]
pub struct ValidComponentAmalgamation<'a, C> {
    ca: ComponentAmalgamation<'a, C>,
    cert: ValidCert<'a>,
    // The binding signature at time `time`.  (This is just a cache.)
    binding_signature: &'a Signature,
}

<<<<<<< Updated upstream
/// A User ID and its associated data.
///
/// This is just a specialized version of `ValidComponentAmalgamation`.
pub type ValidUserIDAmalgamation<'a> = ValidComponentAmalgamation<'a, UserID>;

/// A User Attribute and its associated data.
///
/// This is just a specialized version of `ValidComponentAmalgamation`.
pub type ValidUserAttributeAmalgamation<'a>
    = ValidComponentAmalgamation<'a, UserAttribute>;

/// An Unknown component and its associated data.
///
/// This is just a specialized version of `ValidComponentAmalgamation`.
pub type ValidUnknownComponentAmalgamation<'a>
    = ValidComponentAmalgamation<'a, Unknown>;
=======
/// A `ValidComponentAmalgamation` specialized for `UserID`s.
pub type ValidUserIDAmalgamation<'a>
    = ValidComponentAmalgamation<'a, crate::packet::UserID>;

/// A `ValidComponentAmalgamation` specialized for `UserAttributes`s.
pub type ValidUserAttributeAmalgamation<'a>
    = ValidComponentAmalgamation<'a, crate::packet::UserAttribute>;
>>>>>>> Stashed changes

// derive(Clone) doesn't work with generic parameters that don't
// implement clone.  But, we don't need to require that C implements
// Clone, because we're not cloning C, just the reference.
//
// See: https://github.com/rust-lang/rust/issues/26925
impl<'a, C> Clone for ValidComponentAmalgamation<'a, C> {
    fn clone(&self) -> Self {
        Self {
            ca: self.ca.clone(),
            cert: self.cert.clone(),
            binding_signature: self.binding_signature,
        }
    }
}

impl<'a, C> std::ops::Deref for ValidComponentAmalgamation<'a, C> {
    type Target = ComponentAmalgamation<'a, C>;

    fn deref(&self) -> &Self::Target {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        &self.ca
    }
}

impl<'a, C: 'a> From<ValidComponentAmalgamation<'a, C>>
    for ComponentAmalgamation<'a, C>
{
    fn from(vca: ValidComponentAmalgamation<'a, C>) -> Self {
        assert!(std::ptr::eq(vca.ca.cert(), vca.cert.cert()));
        vca.ca
    }
}

impl<'a, C> ValidComponentAmalgamation<'a, C>
    where C: Ord
{
    /// Returns the amalgamated primary component at time `time`
    ///
    /// If `time` is None, then the current time is used.
    /// `ValidComponentAmalgamationIter` for the definition of a valid component.
    ///
    /// The primary component is determined by taking the components that
    /// are alive at time `t`, and sorting them as follows:
    ///
    ///   - non-revoked first
    ///   - primary first
    ///   - signature creation first
    ///
    /// If there is more than one, than one is selected in a
    /// deterministic, but undefined manner.
    ///
    /// If `valid_cert` is `false`, then this does not also check
    /// whether the certificate is valid; it only checks whether the
    /// component is valid.  Normally, this should be `true`.  This
    /// option is only expose to allow breaking an infinite recursion:
    ///
    ///   - To check if a certificate is valid, we check if the
    ///     primary key is valid.
    ///
    ///   - To check if the primary key is valid, we need the primary
    ///     key's self signature
    ///
    ///   - To find the primary key's self signature, we need to find
    ///     the primary user id
    ///
    ///   - To find the primary user id, we need to check if the user
    ///     id is valid.
    ///
    ///   - To check if the user id is valid, we need to check that
    ///     the corresponding certificate is valid.
    pub(super) fn primary(cert: &'a Cert,
                          iter: std::slice::Iter<'a, ComponentBundle<C>>,
                          policy: &'a dyn Policy, t: SystemTime,
                          valid_cert: bool)
        -> Result<ValidComponentAmalgamation<'a, C>>
    {
        use std::cmp::Ordering;

        let mut error = None;

        // Filter out components that are not alive at time `t`.
        //
        // While we have the binding signature, extract a few
        // properties to avoid recomputing the same thing multiple
        // times.
        iter.filter_map(|c| {
            // No binding signature at time `t` => not alive.
            let sig = match c.binding_signature(policy, t) {
                Ok(sig) => Some(sig),
                Err(e) => {
                    error = Some(e);
                    None
                },
            }?;

            let revoked = c._revoked(policy, t, false, Some(sig));
            let primary = sig.primary_userid().unwrap_or(false);
            let signature_creation_time = match sig.signature_creation_time() {
                Some(time) => Some(time),
                None => {
                    error = Some(Error::MalformedPacket(
                        "Signature has no creation time".into()).into());
                    None
                },
            }?;

            Some(((c, sig, revoked), primary, signature_creation_time))
        })
            .max_by(|(a, a_primary, a_signature_creation_time),
                    (b, b_primary, b_signature_creation_time)| {
                match (destructures_to!(RevocationStatus::Revoked(_) = &a.2),
                       destructures_to!(RevocationStatus::Revoked(_) = &b.2)) {
                    (true, false) => return Ordering::Less,
                    (false, true) => return Ordering::Greater,
                    _ => (),
                }
                match (a_primary, b_primary) {
                    (true, false) => return Ordering::Greater,
                    (false, true) => return Ordering::Less,
                    _ => (),
                }
                match a_signature_creation_time.cmp(&b_signature_creation_time)
                {
                    Ordering::Less => return Ordering::Less,
                    Ordering::Greater => return Ordering::Greater,
                    Ordering::Equal => (),
                }

                // Fallback to a lexographical comparison.  Prefer
                // the "smaller" one.
                match a.0.component().cmp(&b.0.component()) {
                    Ordering::Less => return Ordering::Greater,
                    Ordering::Greater => return Ordering::Less,
                    Ordering::Equal =>
                        panic!("non-canonicalized Cert (duplicate components)"),
                }
            })
            .ok_or_else(|| {
                error.map(|e| e.context(format!(
                    "No binding signature at time {}", crate::fmt::time(&t))))
                    .unwrap_or(Error::NoBindingSignature(t).into())
            })
            .and_then(|c| ComponentAmalgamation::new(cert, (c.0).0)
                      .with_policy_relaxed(policy, t, valid_cert))
    }
}

impl<'a, C> ValidateAmalgamation<'a, C> for ValidComponentAmalgamation<'a, C> {
    type V = Self;

    fn with_policy<T>(self, policy: &'a dyn Policy, time: T) -> Result<Self::V>
        where T: Into<Option<time::SystemTime>>,
              Self: Sized,
    {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));

        let time = time.into().unwrap_or_else(SystemTime::now);
        self.ca.with_policy(policy, time)
    }
}

impl<'a, C> ValidAmalgamation<'a, C> for ValidComponentAmalgamation<'a, C> {
    fn cert(&self) -> &ValidCert<'a> {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        &self.cert
    }

    fn time(&self) -> SystemTime {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        self.cert.time
    }

    fn policy(&self) -> &'a dyn Policy
    {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        self.cert.policy
    }

    fn binding_signature(&self) -> &'a Signature {
        assert!(std::ptr::eq(self.ca.cert(), self.cert.cert()));
        self.binding_signature
    }

    fn revoked(&self) -> RevocationStatus<'a> {
        self.bundle._revoked(self.policy(), self.cert.time,
                              false, Some(self.binding_signature))
    }
}

impl<'a, C> crate::cert::Preferences<'a>
    for ValidComponentAmalgamation<'a, C>
{
    fn preferred_symmetric_algorithms(&self)
                                      -> Option<&'a [SymmetricAlgorithm]> {
        self.map(|s| s.preferred_symmetric_algorithms())
    }

    fn preferred_hash_algorithms(&self) -> Option<&'a [HashAlgorithm]> {
        self.map(|s| s.preferred_hash_algorithms())
    }

    fn preferred_compression_algorithms(&self)
                                        -> Option<&'a [CompressionAlgorithm]> {
        self.map(|s| s.preferred_compression_algorithms())
    }

    fn preferred_aead_algorithms(&self) -> Option<&'a [AEADAlgorithm]> {
        self.map(|s| s.preferred_aead_algorithms())
    }

    fn key_server_preferences(&self) -> Option<KeyServerPreferences> {
        self.map(|s| s.key_server_preferences())
    }

    fn preferred_key_server(&self) -> Option<&'a [u8]> {
        self.map(|s| s.preferred_key_server())
    }

    fn features(&self) -> Option<Features> {
        self.map(|s| s.features())
    }
}

#[cfg(test)]
mod test {
    use crate::policy::StandardPolicy as P;
    use crate::cert::prelude::*;
    use crate::packet::UserID;

    // derive(Clone) doesn't work with generic parameters that don't
    // implement clone.  Make sure that our custom implementations
    // work.
    //
    // See: https://github.com/rust-lang/rust/issues/26925
    #[test]
    fn clone() {
        let p = &P::new();

        let (cert, _) = CertBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();

        let userid : ComponentAmalgamation<UserID>
            = cert.userids().nth(0).unwrap();
        assert_eq!(userid.userid(), userid.clone().userid());

        let userid : ValidComponentAmalgamation<UserID>
            = userid.with_policy(p, None).unwrap();
        let c = userid.clone();
        assert_eq!(userid.userid(), c.userid());
        assert_eq!(userid.time(), c.time());
    }

    #[test]
    fn map() {
        // The reference returned by `ComponentAmalgamation::userid`
        // and `ComponentAmalgamation::user_attribute` is bound by the
        // reference to the `Component` in the
        // `ComponentAmalgamation`, not the `ComponentAmalgamation`
        // itself.
        let (cert, _) = CertBuilder::new()
            .add_userid("test@example.example")
            .generate()
            .unwrap();

        let _ = cert.userids().map(|ua| ua.userid())
            .collect::<Vec<_>>();

        let _ = cert.user_attributes().map(|ua| ua.user_attribute())
            .collect::<Vec<_>>();
    }
}
