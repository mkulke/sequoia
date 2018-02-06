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
use std::io;
use std::rc::Rc;
use tokio_core::reactor::Core;

extern crate openpgp;
#[allow(unused_imports)]
#[macro_use]
extern crate sequoia_core;
use sequoia_core as core;
extern crate sequoia_net;
use sequoia_net as net;

/// Macros managing requests and responses.
#[macro_use] mod macros;

use openpgp::Fingerprint;
use openpgp::tpk::TPK;
use core::Context;
use net::ipc;

#[allow(dead_code)] pub /*XXX*/ mod secret_protocol_capnp;
use secret_protocol_capnp::node;

/// Dummy TSK implementation.
pub struct TSK(TPK);

impl TSK {
    pub fn new(tpk: TPK) -> TSK {
        TSK(tpk)
    }

    pub fn from_bytes(b: &[u8]) -> Result<TSK> {
        TPK::from_bytes(b).map(|x| TSK(x))
    }

    pub fn serialize<W: io::Write>(&self, o: &mut W) -> Result<()> {
        self.0.serialize(o)
    }

    pub fn tpk(&self) -> TPK {
        self.0.clone()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.0.fingerprint()
    }
}

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
        c.home().join("S.secret"),
        c.lib().join("secret-store"),
        backend::factory,
    )
}

/// A secret key object.
pub struct Key {
    core: Rc<RefCell<Core>>,
    fp: Fingerprint,
    key: node::key::Client,
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key {{ {} }}", self.fp)
    }
}

impl Key {
    fn connect(c: &Context) -> Result<(Core, node::Client)> {
        let descriptor = descriptor(c);
        let core = Core::new()?;
        let handle = core.handle();

        let mut rpc_system
            = match descriptor.connect_with_policy(&handle,
                                                   core::IPCPolicy::External) {
                Ok(r) => r,
                Err(e) => return Err(e.into()),
            };

        let client: node::Client = rpc_system.bootstrap(Side::Server);
        handle.spawn(rpc_system.map_err(|_e| ()));

        Ok((core, client))
    }

    pub fn open(c: &Context, fp: &Fingerprint) -> Result<Self> {
        let (mut core, client) = Self::connect(c)?;

        let mut request = client.open_request();
        request.get().set_fingerprint(&fp.to_hex());

        let key = make_request!(&mut core, request)?;
        Ok(Self::new(Rc::new(RefCell::new(core)), fp, key))
    }

    fn new(core: Rc<RefCell<Core>>, fp: &Fingerprint,
           key: node::key::Client) -> Self {
        Key{core: core, fp: fp.clone(), key: key}
    }

    pub fn import(c: &Context, tsk: &TSK) -> Result<Key> {
        let mut blob = vec![];
        tsk.serialize(&mut blob)?;
        let (mut core, client) = Self::connect(c)?;
        let mut request = client.import_request();
        request.get().set_key(&blob);
        let key = make_request!(core, request)?;
        Ok(Self::new(Rc::new(RefCell::new(core)), &tsk.fingerprint(), key))
    }

    /// Lists all keys.
    pub fn list(c: &Context) -> Result<KeyIter> {
        let (mut core, client) = Self::connect(c)?;
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
    iter: node::key_iter::Client,
}

impl Iterator for KeyIter {
    type Item = Key;

    fn next(&mut self) -> Option<Self::Item> {
        let request = self.iter.next_request();
        let doit = || {
            make_request_map!(
                self.core.borrow_mut(), request,
                |r: node::key_iter::item::Reader| {
                    let fp =
                        Fingerprint::from_hex(r.get_fingerprint()?)
                        .ok_or(Error::NotFound)?;
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
    /// The key is locked.
    #[fail(display = "Key is locked")]
    KeyLocked,
    /// Bad unlock passphrase.
    #[fail(display = "Bad passphrase")]
    BadPassphrase,
}

/// Converts from backend errors.
impl From<node::Error> for failure::Error {
    fn from(error: node::Error) -> Self {
        match error {
            node::Error::NotFound => Error::NotFound,
            node::Error::KeyExists => Error::KeyExists,
            node::Error::KeyLocked => Error::KeyLocked,
            node::Error::BadPassphrase => Error::BadPassphrase,
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
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .lib(libpath())
            .build().unwrap();
        let tsk = TSK::from_bytes(bytes!("testy.pgp")).unwrap();
        let key = Key::import(&ctx, &tsk).unwrap();
        let tpk = key.tpk().unwrap();
        assert_eq!(tsk.fingerprint(), tpk.fingerprint());
    }

    #[test]
    fn key_not_found() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .lib(libpath())
            .build().unwrap();
        let fp = Fingerprint::from_bytes(b"bbbbbbbbbbbbbbbbbbbb");
        let r = Key::open(&ctx, &fp);
        assert_match!(Error::NotFound
                      = r.err().unwrap().downcast::<Error>().unwrap());
    }

    #[test]
    fn decryption() {
        let ctx = core::Context::configure("org.sequoia-pgp.tests")
            .ephemeral()
            .network_policy(core::NetworkPolicy::Offline)
            .ipc_policy(core::IPCPolicy::Internal)
            .lib(libpath())
            .build().unwrap();
        let tsk = TSK::from_bytes(bytes!("testy.pgp")).unwrap();
        let key = Key::import(&ctx, &tsk).unwrap();
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
