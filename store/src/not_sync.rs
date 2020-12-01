//! Async variant of the Store interface.

use capnp;
use capnp_rpc;

use std::fmt;
use std::time;

use futures::stream::{Stream, unfold};

use capnp_rpc::rpc_twoparty_capnp::Side;

use sequoia_openpgp as openpgp;
use sequoia_core as core;
#[allow(unused_imports)]
use sequoia_core;

use openpgp::Fingerprint;
use openpgp::KeyID;
use openpgp::Cert;
use openpgp::parse::Parse;
use openpgp::serialize::SerializeInto;
use sequoia_core::Context;
use crate::Result;

use crate::store_protocol_capnp::node;
use crate::{
    from_unix,
    Stamps,
    Stats,
};

/// The common key pool.
pub struct Store {
}

impl Store {
    /// Establishes a connection to the backend.
    fn connect(c: &Context) -> Result<node::Client> {
        let descriptor = crate::descriptor(c);
        let mut rpc_system =
            tokio::runtime::Handle::current().enter(|| descriptor.connect())?;
        let bootstrap_capability = rpc_system.bootstrap(Side::Server);
        tokio::task::spawn_local(Box::pin(rpc_system));
        Ok(bootstrap_capability)
    }

    /// Imports a key into the common key pool.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::not_sync::Store;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// let key = Store::import(&ctx, &cert).await?;
    /// assert_eq!(key.cert().await?.fingerprint(), cert.fingerprint());
    /// # Ok(()) }
    /// ```
    pub async fn import(c: &Context, cert: &Cert) -> Result<Key> {
        let client = Store::connect(c)?;
        let mut request = client.import_request();
        request.get().set_key(&cert.to_vec()?);
        invoke!(request).map(Key::new)
    }

    /// Looks up a key in the common key pool.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::not_sync::Store;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// Store::import(&ctx, &cert).await?;
    /// let key = Store::lookup(&ctx, &cert.fingerprint()).await?;
    /// assert_eq!(key.cert().await?.fingerprint(), cert.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn lookup(c: &Context, fp: &Fingerprint) -> Result<Key> {
        let client = Store::connect(c)?;
        let mut request = client.lookup_by_fingerprint_request();
        request.get().set_fingerprint(&fp.to_hex());
        invoke!(request).map(Key::new)
    }

    /// Looks up a key in the common key pool by KeyID.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::not_sync::Store;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// Store::import(&ctx, &cert).await?;
    /// let key = Store::lookup_by_keyid(&ctx, &cert.fingerprint().into()).await?;
    /// assert_eq!(key.cert().await?.fingerprint(), cert.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn lookup_by_keyid(c: &Context, keyid: &KeyID) -> Result<Key> {
        let client = Store::connect(c)?;
        let mut request = client.lookup_by_keyid_request();
        request.get().set_keyid(keyid.as_u64()?);
        invoke!(request).map(Key::new)
    }

    /// Looks up a key in the common key pool by (Sub)KeyID.
    ///
    /// The KeyID may also reference a subkey.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::{Cert, KeyID};
    /// # use openpgp::parse::Parse;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::not_sync::Store;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/neal.pgp")[..])
    /// #     .unwrap();
    /// Store::import(&ctx, &cert).await?;
    ///
    /// // Lookup by the primary key's KeyID.
    /// let key = Store::lookup_by_subkeyid(&ctx, &"AACB3243630052D9".parse()?).await?;
    /// assert_eq!(key.cert().await?.fingerprint(), cert.fingerprint());
    ///
    /// // Lookup by the signing subkey's KeyID.
    /// let key = Store::lookup_by_subkeyid(&ctx, &"7223B56678E02528".parse()?).await?;
    /// assert_eq!(key.cert().await?.fingerprint(), cert.fingerprint());
    ///
    /// // Lookup by the encryption subkey's KeyID.
    /// let key = Store::lookup_by_subkeyid(&ctx, &"C2B819056C652598".parse()?).await?;
    /// assert_eq!(key.cert().await?.fingerprint(), cert.fingerprint());
    ///
    /// // Lookup by the authentication subkey's KeyID.
    /// let key = Store::lookup_by_subkeyid(&ctx, &"A3506AFB820ABD08".parse()?).await?;
    /// assert_eq!(key.cert().await?.fingerprint(), cert.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn lookup_by_subkeyid(c: &Context, keyid: &KeyID) -> Result<Key> {
        let client = Store::connect(c)?;
        let mut request = client.lookup_by_subkeyid_request();
        request.get().set_keyid(keyid.as_u64()?);
        invoke!(request).map(Key::new)
    }

    /// Lists all keys in the common key pool.
    pub async fn list_keys(c: &Context) -> Result<impl Stream<Item = Key>> {
        let client = Store::connect(c)?;
        let iter = invoke!(client.iter_keys_request())?;
        Ok(unfold(iter, unfold_key_iter))
    }

    /// Lists all log entries.
    pub async fn server_log(c: &Context) -> Result<impl Stream<Item = Log>> {
        let client = Store::connect(c)?;
        let iter = invoke!(client.log_request())?;
        Ok(unfold(iter, unfold_log_iter))
    }
}

/// A public key store.
pub struct Mapping {
    name: String,
    mapping: node::mapping::Client,
}

impl fmt::Debug for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Mapping {{ name: {} }}", self.name)
    }
}

impl Mapping {
    /// Opens a mapping.
    ///
    /// Opens a mapping with the given name.  If the mapping does not
    /// exist, it is created.  Mappings are handles for objects
    /// maintained by a background service.  The background service
    /// associates state with this name.
    ///
    /// The store updates Certs in compliance with the network policy
    /// of the context that created the mapping in the first place.
    /// Opening the mapping with a different network policy is
    /// forbidden.
    pub async fn open(c: &Context, realm: &str, name: &str) -> Result<Self> {
        let client = Store::connect(c)?;

        let mut request = client.open_request();
        request.get().set_realm(realm);
        request.get().set_network_policy(c.network_policy().into());
        request.get().set_ephemeral(c.ephemeral());
        request.get().set_name(name);

        invoke!(request).map(|c| Mapping::new(name, c))
    }

    fn new(name: &str, mapping: node::mapping::Client) -> Self {
        Mapping { name: name.into(), mapping, }
    }

    /// Lists all mappings with the given prefix.
    pub async fn list(c: &Context, realm_prefix: &str)
                      -> Result<impl Stream<Item = (String, String,
                                                    core::NetworkPolicy,
                                                    Mapping)>>
    {
        let client = Store::connect(c)?;
        let mut request = client.iter_request();
        request.get().set_realm_prefix(realm_prefix);
        let iter = invoke!(request)?;
        Ok(unfold(iter, unfold_mapping_iter))
    }

    /// Adds a key identified by fingerprint to the mapping.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{REALM_CONTACTS};
    /// # use sequoia_store::not_sync::Mapping;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// mapping.add("Mister B.", &fp).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn add(&self, label: &str, fingerprint: &Fingerprint)
                     -> Result<Binding> {
        let mut request = self.mapping.add_request();
        request.get().set_label(label);
        request.get().set_fingerprint(&fingerprint.to_hex());
        let label = label.to_owned();
        invoke!(request).map(|b| Binding::new(Some(label), b))
    }

    /// Imports a key into the mapping.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{REALM_CONTACTS};
    /// # use sequoia_store::not_sync::Mapping;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// mapping.import("Testy McTestface", &cert).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn import(&self, label: &str, cert: &Cert) -> Result<Cert> {
        let fingerprint = cert.fingerprint();
        let mut request = self.mapping.add_request();
        request.get().set_label(label);
        request.get().set_fingerprint(format!("{:X}", fingerprint).as_ref());
        invoke!(request).map(|b| Binding::new(Some(label), b))?.import(cert).await
    }

    /// Returns the binding for the given label.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{REALM_CONTACTS};
    /// # use sequoia_store::not_sync::Mapping;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// mapping.add("Mister B.", &fp).await?;
    /// drop(mapping);
    /// // ...
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// let binding = mapping.lookup("Mister B.").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn lookup(&self, label: &str) -> Result<Binding> {
        let mut request = self.mapping.lookup_request();
        request.get().set_label(label);
        invoke!(request).map(|b| Binding::new(Some(label), b))
    }

    /// Looks up a key by (Sub)KeyID.
    ///
    /// The KeyID may also reference a subkey.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::{Cert, KeyID};
    /// # use openpgp::parse::Parse;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{REALM_CONTACTS};
    /// # use sequoia_store::not_sync::Mapping;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let cert = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/emmelie-dorothea-dina-samantha-awina-ed25519.pgp")[..])
    /// #     .unwrap();
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// mapping.import("Emmelie", &cert).await?;
    ///
    /// // Lookup by the primary key's KeyID.
    /// let cert_ = mapping.lookup_by_subkeyid(&"069C0C348DD82C19".parse()?).await?
    ///     .cert().await?;
    /// assert_eq!(cert, cert_);
    ///
    /// // Lookup by the subkey's KeyID.
    /// let cert_ = mapping.lookup_by_subkeyid(&"22E3FAFE96B56C32".parse()?).await?
    ///     .cert().await?;
    /// assert_eq!(cert, cert_);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn lookup_by_subkeyid(&self, keyid: &KeyID) -> Result<Binding> {
        let mut request = self.mapping.lookup_by_subkeyid_request();
        request.get().set_keyid(keyid.as_u64()?);
        invoke!(request).map(|b| Binding::new(Option::<&str>::None, b))
    }

    /// Deletes this mapping.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # #[macro_use] use sequoia_core;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{REALM_CONTACTS};
    /// # use sequoia_store::not_sync::Mapping;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// mapping.add("Mister B.", &fp).await?;
    /// mapping.delete().await?;
    /// // ...
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// let binding = mapping.lookup("Mister B.").await;
    /// assert!(binding.is_err()); // not found
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete(self) -> Result<()> {
        invoke!(self.mapping.delete_request()).map( |_| ())
    }

    /// Lists all bindings.
    pub async fn iter(&self) -> Result<impl Stream<Item = (String,
                                                           openpgp::Fingerprint,
                                                           Binding)>> {
        let iter = invoke!(self.mapping.iter_request())?;
        Ok(unfold(iter, unfold_binding_iter))
    }

    /// Lists all log entries related to this mapping.
    pub async fn log(&self) -> Result<impl Stream<Item = Log>> {
        let iter = invoke!(self.mapping.log_request())?;
        Ok(unfold(iter, unfold_log_iter))
    }
}

/// Represents an entry in a Mapping.
///
/// Mappings map labels to Certs.  A `Binding` represents a pair in this
/// relation.  We make this explicit because we associate metadata
/// with these pairs.
pub struct Binding {
    label: Option<String>,
    binding: node::binding::Client,
}

impl fmt::Debug for Binding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Binding {{ label: {:?} }}", self.label)
    }
}

impl Binding {
    fn new<L: AsRef<str>>(label: Option<L>,
           binding: node::binding::Client) -> Self {
        Binding{label: label.map(|l| l.as_ref().into()), binding,}
    }

    /// Returns stats for this binding.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{REALM_CONTACTS};
    /// # use sequoia_store::not_sync::Mapping;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    ///
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// let binding = mapping.add("Mister B.", &fp).await?;
    ///
    /// println!("Binding {:?}", binding.stats().await?);
    /// // prints:
    /// // Binding Stats {
    /// //     created: Some(Timespec { tv_sec: 1513704042, tv_nsec: 0 }),
    /// //     updated: None,
    /// //     encryption: Stamps { count: 0, first: None, last: None },
    /// //     verification: Stamps { count: 0, first: None, last: None }
    /// // }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn stats(&self) -> Result<Stats> {
        invoke!(self.binding.stats_request()).map(|s| {
            Stats {
                created: from_unix(s.get_created()),
                updated: from_unix(s.get_updated()),
                encryption: Stamps::new(
                    s.get_encryption_count(),
                    from_unix(s.get_encryption_first()),
                    from_unix(s.get_encryption_last())),
                verification: Stamps::new(
                    s.get_verification_count(),
                    from_unix(s.get_verification_first()),
                    from_unix(s.get_verification_last())),
            }
        })
    }

    /// Returns the `Key` of this binding.
    pub async fn key(&self) -> Result<Key> {
        invoke!(self.binding.key_request()).map(Key::new)
    }

    /// Returns the `Cert` of this binding.
    ///
    /// A shortcut for `self.key()?.cert()`.
    pub async fn cert(&self) -> Result<Cert> {
        self.key().await?.cert().await
    }

    /// Updates this binding with the given Cert.
    ///
    /// If the new key `cert` matches the current key, i.e. they have
    /// the same fingerprint, both keys are merged and normalized.
    /// The returned key contains all packets known to Sequoia, and
    /// should be used instead of `cert`.
    ///
    /// If the new key does not match the current key, and it does not
    /// carry a valid signature from the current key, an
    /// `Error::Conflict` is returned, and you have to resolve the
    /// conflict, either by ignoring the new key, or by using
    /// `Binding::rotate` to force a rotation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # #[macro_use] use sequoia_core;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{REALM_CONTACTS};
    /// # use sequoia_store::not_sync::Mapping;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let old = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// # let new = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")[..]).unwrap();
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// mapping.import("Testy McTestface", &old).await?;
    /// // later...
    /// let binding = mapping.lookup("Testy McTestface").await?;
    /// let r = binding.import(&new).await;
    /// assert!(r.is_err()); // Conflict!
    /// # Ok(())
    /// # }
    /// ```
    pub async fn import(&self, cert: &Cert) -> Result<Cert> {
        let mut request = self.binding.import_request();
        request.get().set_force(false);
        request.get().set_key(&cert.to_vec()?);
        invoke!(request).and_then(Cert::from_bytes)
    }

    /// Forces a keyrotation to the given Cert.
    ///
    /// The current key is replaced with the new key `cert`, even if
    /// they do not have the same fingerprint.  If a key with the same
    /// fingerprint as `cert` is already in the store, is merged with
    /// `cert` and normalized.  The returned key contains all packets
    /// known to Sequoia, and should be used instead of `cert`.
    ///
    /// Use this function to resolve conflicts returned from
    /// `Binding::import`.  Make sure that you have authenticated
    /// `cert` properly.  How to do that depends on your thread model.
    /// You could simply ask Alice to call her communication partner
    /// Bob and confirm that he rotated his keys.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # #[macro_use] use sequoia_core;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{REALM_CONTACTS};
    /// # use sequoia_store::not_sync::Mapping;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let old = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// # let new = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")[..]).unwrap();
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// mapping.import("Testy McTestface", &old).await?;
    /// // later...
    /// let binding = mapping.lookup("Testy McTestface").await?;
    /// let r = binding.import(&new).await;
    /// assert!(r.is_err()); // Conflict!
    /// let r = binding.rotate(&new).await?;
    /// assert_eq!(new.fingerprint(), r.fingerprint());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn rotate(&self, cert: &Cert) -> Result<Cert> {
        let mut request = self.binding.import_request();
        request.get().set_force(true);
        request.get().set_key(&cert.to_vec()?);
        invoke!(request).and_then(Cert::from_bytes)
    }

    /// Deletes this binding.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # #[macro_use] use sequoia_core;
    /// # use openpgp::Fingerprint;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::{REALM_CONTACTS};
    /// # use sequoia_store::not_sync::Mapping;
    /// # fn main() -> openpgp::Result<()> {
    /// #     let mut rt = tokio::runtime::Builder::new()
    /// #         .basic_scheduler().enable_io().enable_time()
    /// #         .build()?;
    /// #     tokio::task::LocalSet::new().block_on(&mut rt, f())
    /// # }
    /// # async fn f() -> openpgp::Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
    /// let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
    /// let binding = mapping.add("Mister B.", &fp).await?;
    /// binding.delete().await?;
    /// let binding = mapping.lookup("Mister B.").await;
    /// assert!(binding.is_err()); // not found
    /// # Ok(())
    /// # }
    /// ```
    pub async fn delete(self) -> Result<()> {
        let request = self.binding.delete_request();
        invoke!(request).map(|_| ())
    }

    /// Lists all log entries related to this binding.
    pub async fn log(&self) -> Result<impl Stream<Item = Log>> {
        let iter = invoke!(self.binding.log_request())?;
        Ok(unfold(iter, unfold_log_iter))
    }

    /// Gets this binding's label.
    pub async fn label(&self) -> Result<String> {
        if let Some(ref label) = self.label {
            return Ok(label.clone());
        }

        invoke!(self.binding.label_request()).map(Into::into)
    }
}

/// Represents a key in the store.
///
/// A `Key` is a handle to a stored Cert.  We make this explicit
/// because we associate metadata with Certs.
pub struct Key {
    key: node::key::Client,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key {{ }}")
    }
}

impl Key {
    fn new(key: node::key::Client) -> Self {
        Key { key, }
    }

    /// Returns the Cert.
    pub async fn cert(&self) -> Result<Cert> {
        invoke!(self.key.cert_request()).and_then(Cert::from_bytes)
    }

    /// Returns stats for this key.
    pub async fn stats(&self) -> Result<Stats> {
        invoke!(self.key.stats_request()).map(|s| {
            Stats {
                created: from_unix(s.get_created()),
                updated: from_unix(s.get_updated()),
                encryption: Stamps::new(
                    s.get_encryption_count(),
                    from_unix(s.get_encryption_first()),
                    from_unix(s.get_encryption_last())),
                verification: Stamps::new(
                    s.get_verification_count(),
                    from_unix(s.get_verification_first()),
                    from_unix(s.get_verification_last())),
            }
        })
    }

    /// Updates this stored key with the given Cert.
    ///
    /// If the new key `cert` matches the current key, i.e. they have
    /// the same fingerprint, both keys are merged and normalized.
    /// The returned key contains all packets known to Sequoia, and
    /// should be used instead of `cert`.
    ///
    /// If the new key does not match the current key,
    /// `Error::Conflict` is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use sequoia_openpgp as openpgp;
    /// # #[macro_use] use sequoia_core;
    /// # use openpgp::Fingerprint;
    /// # use openpgp::Cert;
    /// # use openpgp::parse::Parse;
    /// # use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
    /// # use sequoia_store::*;
    /// # fn main() { f().unwrap(); }
    /// # fn f() -> Result<()> {
    /// # let ctx = Context::configure()
    /// #     .network_policy(NetworkPolicy::Offline)
    /// #     .ipc_policy(IPCPolicy::Internal)
    /// #     .ephemeral().build()?;
    /// # let old = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    /// # let new = Cert::from_bytes(
    /// #     &include_bytes!("../../openpgp/tests/data/keys/testy-new.pgp")[..]).unwrap();
    /// let mapping = Mapping::open(&ctx, REALM_CONTACTS, "default")?;
    /// let fp = "3E8877C877274692975189F5D03F6F865226FE8B".parse().unwrap();
    /// let binding = mapping.add("Testy McTestface", &fp)?;
    /// let key = binding.key()?;
    /// let r = key.import(&old)?;
    /// assert_eq!(r.fingerprint(), old.fingerprint());
    /// let r = key.import(&new);
    /// assert!(r.is_err()); // conflict
    /// # Ok(())
    /// # }
    /// ```
    pub async fn import(&self, cert: &Cert) -> Result<Cert> {
        let mut request = self.key.import_request();
        request.get().set_key(&cert.to_vec()?);
        invoke!(request).and_then(Cert::from_bytes)
    }

    /// Lists all log entries related to this key.
    pub async fn log(&self) -> Result<impl Stream<Item = Log>> {
        let iter = invoke!(self.key.log_request())?;
        Ok(unfold(iter, unfold_log_iter))
    }
}

async fn unfold_key_iter(iter: node::key_iter::Client)
                         -> Option<(Key, node::key_iter::Client)> {
    let key =
        iter.next_request().send().promise.await.ok()?
        .get().ok()?.get_result().ok()?.which().ok()?.into_result().ok()?
        .get_key().ok()?;
    Some((Key::new(key), iter))
}

async fn unfold_log_iter(iter: node::log_iter::Client)
                         -> Option<(Log, node::log_iter::Client)> {
    let r_ =
        iter.next_request().send().promise.await.ok()?;
    let r =
        r_.get().ok()?.get_result().ok()?.which().ok()?.into_result().ok()?;
    Some((Log::new(r.get_timestamp(),
                   r.get_mapping().ok().map(
                       |cap| Mapping::new(&"", cap)),
                   r.get_binding().ok().map(
                       |cap| Binding::new(Option::<&str>::None, cap)),
                   r.get_key().ok().map(
                       |cap| Key::new(cap)),
                   r.get_slug().ok()?,
                   r.get_message().ok()?,
                   if r.has_error() {
                       r.get_error().ok()
                   } else {
                       None
                   })?, iter))
}

async fn unfold_mapping_iter(iter: node::mapping_iter::Client)
                             -> Option<((String, String,
                                         core::NetworkPolicy,
                                         Mapping), node::mapping_iter::Client)>
{
    let item_ =
        iter.next_request().send().promise.await.ok()?;
    let item =
        item_.get().ok()?.get_result().ok()?.which().ok()?.into_result().ok()?;
    let realm = item.get_realm().ok()?.to_owned();
    let name = item.get_name().ok()?.to_owned();
    let network_policy = item.get_network_policy().ok()?.into();
    let mapping = Mapping::new(&name, item.get_mapping().ok()?);
    Some(((realm, name, network_policy, mapping), iter))
}

async fn unfold_binding_iter(iter: node::binding_iter::Client)
                             -> Option<((String,
                                         openpgp::Fingerprint,
                                         Binding),
                                        node::binding_iter::Client)>
{
    let item_ =
        iter.next_request().send().promise.await.ok()?;
    let item =
        item_.get().ok()?.get_result().ok()?.which().ok()?.into_result().ok()?;
    let label = item.get_label().ok()?.to_owned();
    let fingerprint = item.get_fingerprint().ok()?.parse().ok()?;
    let binding = Binding::new(Some(&label), item.get_binding().ok()?);
    Some(((label, fingerprint, binding), iter))
}

/// Represents a log entry.
pub struct Log {
    /// Records the time of the entry.
    pub timestamp: time::SystemTime,

    /// Relates the entry to a mapping.
    pub mapping: Option<Mapping>,

    /// Relates the entry to a binding.
    pub binding: Option<Binding>,

    /// Relates the entry to a key.
    pub key: Option<Key>,

    /// Relates the entry to some object.
    ///
    /// This is a human-readable description of what this log entry is
    /// mainly concerned with.
    pub slug: String,

    /// Holds the result of the operation.
    ///
    /// This is either `Ok(Message)`, or `Err((Message, Error))`.
    pub status: ::std::result::Result<String, (String, String)>,
}

impl Log {
    fn new(timestamp: i64,
           mapping: Option<Mapping>, binding: Option<Binding>, key: Option<Key>,
           slug: &str, message: &str, error: Option<&str>)
           -> Option<Self> {
        let timestamp = from_unix(timestamp)?;

        Some(Log{
            timestamp: timestamp,
            mapping: mapping,
            binding: binding,
            key: key,
            slug: slug.into(),
            status: if let Some(error) = error {
                Err((message.into(), error.into()))
            } else {
                Ok(message.into())
            },
        })
    }

    /// Returns the message without context.
    pub fn short(&self) -> String {
        match self.status {
            Ok(ref m) => m.clone(),
            Err((ref m, ref e)) => format!("{}: {}", m, e),
        }
    }

    /// Returns the message with some context.
    pub fn string(&self) -> String {
        match self.status {
            Ok(ref m) => format!("{}: {}", self.slug, m),
            Err((ref m, ref e)) => format!("{}: {}: {}", self.slug, m, e),
        }
    }
}

trait ResultExt<T> {
    fn into_result(self) -> Result<T>;
}

impl<T> ResultExt<T> for crate::node::result::Which<std::result::Result<T, capnp::Error>>  {
    fn into_result(self) -> Result<T> {
        use crate::node::result::Which;
        match self {
            /* The Result.  */
            Which::Ok(Ok(x)) => Ok(x),
            Which::Err(Ok(e)) => Err(anyhow::Error::from(e)),
            /* Protocol violations.  */
            Which::Ok(Err(e)) => Err(anyhow::Error::from(e)),
            Which::Err(Err(e)) => Err(anyhow::Error::from(e)),
        }
    }
}
