//! Handling secret keys.

extern crate capnp;
#[macro_use]
extern crate capnp_rpc;
#[macro_use]
extern crate failure;
extern crate futures;
extern crate rusqlite;
extern crate time;
extern crate tokio_core;
extern crate tokio_io;

use capnp::capability::Promise;
use capnp_rpc::rpc_twoparty_capnp::Side;
use futures::Future;
use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use tokio_core::reactor::Core;

extern crate sequoia_openpgp as openpgp;
#[allow(unused_imports)]
#[macro_use]
extern crate sequoia_core;
use sequoia_core as core;
extern crate sequoia_ipc as ipc;
extern crate sequoia_store_rusqlite as store_rusqlite;

/// Macros managing requests and responses.
#[macro_use] mod macros;

use openpgp::Fingerprint;
use openpgp::TPK;
use openpgp::parse::Parse;
use openpgp::serialize::Serialize;
use core::Context;

#[allow(dead_code)] pub /*XXX*/ mod secret_protocol_capnp;
use secret_protocol_capnp::store;

trait SecretKeyObject {
    fn fingerprint(&self) -> &Fingerprint;
    fn tpk(&self) -> Result<TPK>;
    fn unlock(&self, passphrase: &str) -> Result<()>;
    fn lock(&self) -> Result<()>;
    fn decrypt(&self, sk: &[u8]) -> Result<Vec<u8>>;
}

/// Storage backend.
mod backend;

/// Returns the service descriptor.
#[doc(hidden)]
pub fn descriptor(c: &Context) -> ipc::Descriptor {
    ipc::Descriptor::new(
        c,
        c.home().join("secret-key-store.cookie"),
        c.lib().join("sequoia-secret-key-store"),
        backend::factory,
    )
}

/// A secret key object.
pub struct Key {
    core: Rc<RefCell<Core>>,
    fp: Fingerprint,
    key: store::key::Client,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key {{ {} }}", self.fp)
    }
}

impl Key {
    fn connect(c: &Context, ipc_policy: Option<core::IPCPolicy>)
               -> Result<(Core, store::Client)> {
        let descriptor = descriptor(c);
        let core = Core::new()?;
        let handle = core.handle();

        let mut rpc_system
            = match descriptor.connect_with_policy(
                &handle, ipc_policy.unwrap_or(core::IPCPolicy::External)) {
                Ok(r) => r,
                Err(e) => return Err(e.into()),
            };

        let client: store::Client = rpc_system.bootstrap(Side::Server);
        handle.spawn(rpc_system.map_err(|_e| ()));

        Ok((core, client))
    }

    pub fn open(c: &Context, fp: &Fingerprint,
                ipc_policy: Option<core::IPCPolicy>) -> Result<Self> {
        let (mut core, client) = Self::connect(c, ipc_policy)?;

        let mut request = client.open_request();
        request.get().set_fingerprint(&fp.to_hex());

        let key = make_request!(&mut core, request)?;
        Ok(Self::new(Rc::new(RefCell::new(core)), fp, key))
    }

    fn new(core: Rc<RefCell<Core>>, fp: &Fingerprint,
           key: store::key::Client) -> Self {
        Key{core: core, fp: fp.clone(), key: key}
    }

    pub fn import(c: &Context, tpk: &openpgp::TPK,
                  ipc_policy: Option<core::IPCPolicy>)
                  -> Result<Key> {
        let mut blob = vec![];
        tpk.as_tsk().serialize(&mut blob)?;
        let (mut core, client) = Self::connect(c, ipc_policy)?;
        let mut request = client.import_request();
        request.get().set_key(&blob);
        let key = make_request!(core, request)?;
        Ok(Self::new(Rc::new(RefCell::new(core)), &tpk.fingerprint(), key))
    }

    /// Lists all keys.
    pub fn list(c: &Context, ipc_policy: Option<core::IPCPolicy>) -> Result<KeyIter> {
        let (mut core, client) = Self::connect(c, ipc_policy)?;
        let request = client.iter_request();
        let iter = make_request!(&mut core, request)?;
        Ok(KeyIter{core: Rc::new(RefCell::new(core)), iter: iter})
    }
}

impl SecretKeyObject for Key {
    /// Returns the fingerprint.
    fn fingerprint(&self) -> &Fingerprint {
        &self.fp
    }

    /// Returns the TPK.
    fn tpk(&self) -> Result<TPK> {
        make_request_map!(self.core.borrow_mut(),
                          self.key.tpk_request(),
                          |tpk| TPK::from_bytes(tpk).map_err(|e| e.into()))
    }

    /// Unlocks this secret key.
    fn unlock(&self, passphrase: &str) -> Result<()> {
        let mut request = self.key.unlock_request();
        request.get().set_passphrase(passphrase.into());
        make_request_map!(self.core.borrow_mut(), request,
                          |_| Ok(()))
    }

    /// Locks this secret key.
    fn lock(&self) -> Result<()> {
        make_request_map!(self.core.borrow_mut(),
                          self.key.lock_request(),
                          |_| Ok(()))
    }

    /// Decrypts the given session key
    fn decrypt(&self, sk: &[u8]) -> Result<Vec<u8>> {
        let mut request = self.key.decrypt_request();
        request.get().set_sk(sk);
        make_request_map!(self.core.borrow_mut(), request,
                          |x| Ok(Vec::from(x)))
    }
}

/// Iterates over keys in the common key pool.
pub struct KeyIter {
    core: Rc<RefCell<Core>>,
    iter: store::key_iter::Client,
}

impl Iterator for KeyIter {
    type Item = Key;

    fn next(&mut self) -> Option<Self::Item> {
        let request = self.iter.next_request();
        let doit = || {
            make_request_map!(
                self.core.borrow_mut(), request,
                |r: store::key_iter::item::Reader| {
                    let fp =
                        Fingerprint::from_hex(r.get_fingerprint()?)
                        .map_err(|_| Error::NotFound)?;
                    Ok(Key::new(self.core.clone(), &fp, r.get_key()?))
                })
        };
        doit().ok()
    }
}

/* Error handling.  */

/// Results for sequoia-secret.
pub type Result<T> = ::std::result::Result<T, failure::Error>;

#[derive(Fail, Debug)]
/// Errors returned from the store.
pub enum Error {
    /// A requested key was not found.
    #[fail(display = "Key not found")]
    NotFound,
    /// The key already exists.
    #[fail(display = "Key already exists")]
    KeyExists,
    /// The store is locked.
    #[fail(display = "Store is locked")]
    StoreLocked,
    /// The key is locked.
    #[fail(display = "Key is locked")]
    KeyLocked,
    /// Bad unlock passphrase.
    #[fail(display = "Bad passphrase")]
    BadPassphrase,
    /// Internal inconsistency.
    #[fail(display = "Internal inconsistency")]
    InternalInconsistency,
}

/// Converts from backend errors.
impl From<store::Error> for failure::Error {
    fn from(error: store::Error) -> Self {
        match error {
            store::Error::NotFound => Error::NotFound,
            store::Error::KeyExists => Error::KeyExists,
            store::Error::StoreLocked => Error::StoreLocked,
            store::Error::KeyLocked => Error::KeyLocked,
            store::Error::BadPassphrase => Error::BadPassphrase,
            _ => unimplemented!(),
        }.into()
    }
}

#[cfg(test)]
mod store_test {
    use super::*;

    macro_rules! bytes {
        ( $x:expr ) => { include_bytes!(concat!("../../openpgp/tests/data/keys/", $x)) };
    }

    use std::path::PathBuf;
    /// Returns the path to the binaries.
    fn libpath() -> PathBuf {
        use std::env::current_exe;
        let mut path = current_exe().unwrap();
        path.pop();
        path.pop();
        path
    }

    #[test]
    fn import_key() {
        let ctx = core::Context::configure()
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .lib(libpath())
            .build().unwrap();
        let tpk = openpgp::TPK::from_bytes(bytes!("testy-new-private.pgp"))
            .unwrap();
        let key = Key::import(&ctx, &tpk, Some(core::IPCPolicy::Internal))
            .unwrap();
        assert_eq!(key.tpk().unwrap().fingerprint(), tpk.fingerprint());
    }

    #[test]
    fn key_not_found() {
        let ctx = core::Context::configure()
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .lib(libpath())
            .build().unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let r = Key::open(&ctx, &fp, Some(core::IPCPolicy::Internal));
        assert_match!(Error::NotFound
                      = r.err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn decryption() {
        let ctx = core::Context::configure()
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .lib(libpath())
            .build().unwrap();
        let tpk = openpgp::TPK::from_bytes(bytes!("testy-new-private.pgp"))
            .unwrap();
        let key = Key::import(&ctx, &tpk, Some(core::IPCPolicy::Internal))
            .unwrap();
        if false {
            let sk = Vec::from(&b"abc"[..]);

            let r = key.decrypt(&sk);
            assert_match!(Error::KeyLocked
                          = r.err().unwrap().downcast::<Error>().unwrap());

            let r = key.unlock("nicht geheim");
            assert_match!(Error::BadPassphrase
                          = r.err().unwrap().downcast::<Error>().unwrap());

            key.unlock("streng geheim").unwrap();
            assert_eq!(key.decrypt(&sk).unwrap(), sk);

            key.lock().unwrap();
            let r = key.decrypt(&sk);
            assert_match!(Error::KeyLocked
                          = r.err().unwrap().downcast::<Error>().unwrap());
        }
    }
}
