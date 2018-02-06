//! Secret key backend.

use capnp::capability::Promise;
use capnp;
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::{self, RpcSystem, twoparty};
use failure;
use rusqlite::Connection;
use rusqlite;
use std::cell::{Ref, RefCell};
use std::fmt;
use std::rc::Rc;
use tokio_core::reactor::Handle;
use tokio_core;
use tokio_io::io::ReadHalf;

use openpgp::{
    self,
    Fingerprint,
    KeyID,
    TPK,
    constants::{DataFormat, PublicKeyAlgorithm, SymmetricAlgorithm},
    crypto::{mpis, Password, SessionKey},
    packet::{Key, key::SecretKey, PKESK, SKESK},
    parse::Parse,
    serialize::{Serialize, SerializeInto},
};
use ipc;

use store_rusqlite::{ID, Timestamp};

use secret_protocol_capnp::store;

use super::{Error, Result};

/* Entry point.  */

/// Makes backends.
#[doc(hidden)]
pub fn factory(descriptor: ipc::Descriptor, handle: Handle)
               -> Result<Box<ipc::Handler>> {
    Backend::new(descriptor, handle)
        .map(|b| -> Box<ipc::Handler> { Box::new(b) })
}

struct Backend {
    secret: store::Client,
}

impl Backend {
    fn new(descriptor: ipc::Descriptor, handle: Handle) -> Result<Self> {
        Ok(Backend {
            secret: store::ToClient::new(StoreServer::new(descriptor, handle)?)
                .into_client::<capnp_rpc::Server>(),
        })
    }
}

impl ipc::Handler for Backend {
    fn handle(&self,
              network: twoparty::VatNetwork<ReadHalf<tokio_core::net::TcpStream>>)
              -> RpcSystem<Side> {
        RpcSystem::new(Box::new(network), Some(self.secret.clone().client))
    }
}

/* Server implementation.  */

struct DBKey {
    tpk: openpgp::TPK,
    secret: RefCell<Option<mpis::SecretKey>>,
}

impl DBKey {
    fn new(tpk: openpgp::TPK) -> Result<DBKey> {
        // The key has one encryption subkey with a secret key.
        let secret = {
            let key =
                tpk.subkeys().nth(0).ok_or(failure::Error::from(Error::InternalInconsistency))?
                .subkey();
            let secret =
                key.secret().ok_or(failure::Error::from(Error::InternalInconsistency))?;
            match secret {
                SecretKey::Unencrypted { ref mpis } => Some(mpis.clone()),
                SecretKey::Encrypted { .. } => None,
            }
        };
        Ok(DBKey {
            tpk: tpk,
            secret: RefCell::new(secret),
        })
    }

    fn public(&self) -> &openpgp::packet::Key {
        self.tpk.subkeys().nth(0).unwrap().subkey()
    }

    fn secret(&self) -> Ref<Option<mpis::SecretKey>> {
        self.secret.borrow()
    }

    fn is_locked(&self) -> bool {
        self.secret.borrow().is_none()
    }

    fn lock(&self) {
        *self.secret.borrow_mut() = None;
    }

    fn unlock(&self, password: &Password) -> Result<()> {
        let secret =
            self.public().secret().expect("established in new()").clone();
        *self.secret.borrow_mut() = match secret {
            SecretKey::Unencrypted { ref mpis } => Some(mpis.clone()),
            SecretKey::Encrypted { .. } =>
                Some(secret.decrypt(PublicKeyAlgorithm::ECDH, password)?),
        };
        Ok(())
    }

    fn encrypt(&self, tpk: TPK) -> Result<Vec<u8>> {
        use openpgp::serialize::stream::{Message, Encryptor, EncryptionMode,
                                         LiteralWriter};
        let mut buf = Vec::new();
        {
            let msg = Message::new(&mut buf);
            let msg = Encryptor::new(msg, &[], &[&self.tpk],
                                     EncryptionMode::AtRest, None)?;
            let mut msg = LiteralWriter::new(msg, DataFormat::Binary,
                                             None, None)?;
            tpk.as_tsk().serialize(&mut msg)?;
            msg.finalize()?;
        }
        Ok(buf)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<TPK> {
        use openpgp::parse::stream::*;

        if self.is_locked() {
            return Err(Error::StoreLocked.into());
        }

        struct Helper(Key, mpis::SecretKey);
        impl VerificationHelper for Helper {
            fn get_public_keys(&mut self, _ids: &[KeyID])
                               -> openpgp::Result<Vec<TPK>> {
                Ok(Vec::new())
            }
            fn check(&mut self, _structure: &MessageStructure)
                     -> openpgp::Result<()> {
                Ok(())
            }
        }
        impl DecryptionHelper for Helper {
            fn decrypt<D>(&mut self, pkesks: &[PKESK], _: &[SKESK],
                          mut decrypt: D)
                          -> openpgp::Result<Option<openpgp::Fingerprint>>
                where D: FnMut(SymmetricAlgorithm, &SessionKey)
                               -> openpgp::Result<()>
            {
                pkesks.get(0).ok_or(Error::InternalInconsistency.into())
                    .and_then(|pkesk| pkesk.decrypt(&self.0, &self.1))
                    .and_then(|(algo, session_key)| decrypt(algo, &session_key))
                    .map(|_| None)
            }
        }

        let h = Helper(self.public().clone(), self.secret().as_ref().unwrap().clone());
        let decryptor = Decryptor::from_bytes(ciphertext, h, None)?;

        let tpk = TPK::from_reader(decryptor)?;
        Ok(tpk)
    }
}

/// Shared server state.
struct State {
    key: DBKey,
    c: Connection,
}

struct StoreServer {
    _descriptor: ipc::Descriptor,
    state: Rc<State>,
}

impl StoreServer {
    fn new(descriptor: ipc::Descriptor, _handle: Handle) -> Result<Self> {
        let mut db_path = descriptor.context().home().to_path_buf();
        db_path.push("secret-key-store.sqlite");

        let c = Connection::open(db_path)?;
        c.execute_batch("PRAGMA secure_delete = true;")?;
        c.execute_batch("PRAGMA foreign_keys = true;")?;
        let key = Self::init(&c)?;
        let server = StoreServer {
            _descriptor: descriptor,
            state: Rc::new(State {
                key: DBKey::new(key)?,
                c: c,
            }),
        };

        Ok(server)
    }

    /// Initializes or migrates the database.
    fn init(c: &Connection) -> Result<openpgp::TPK> {
        let v = c.query_row(
            "SELECT version FROM version WHERE id=1",
            &[], |row| row.get(0));

        if let Ok(v) = v {
            match v {
                1 => return Self::read_local_key(c),
                _ => unimplemented!(),
            }
        }

        c.execute_batch(DB_SCHEMA_1)?;

        Self::generate_local_key(c)
    }

    /// Generates a local key.
    fn generate_local_key(c: &Connection) -> Result<openpgp::TPK> {
        let (tpk, _) = openpgp::tpk::TPKBuilder::new()
            .set_cipher_suite(openpgp::tpk::CipherSuite::Cv25519)
            .add_encryption_subkey()
            .generate()?;

        c.execute("INSERT INTO local_key (id, key) VALUES (1, ?)",
                  &[&tpk.to_vec()?])?;
        Ok(tpk)
    }

    /// Reads the local key.
    fn read_local_key(c: &Connection) -> Result<openpgp::TPK> {
        let key: Vec<u8> =
            c.query_row(
                "SELECT key FROM keys WHERE id = 1",
                &[],
                |row| row.get_checked(0).unwrap_or(vec![]))?;

        Ok(openpgp::TPK::from_bytes(&key)?)
    }
}

impl store::Server for StoreServer {
    fn open(&mut self,
            params: store::OpenParams,
            mut results: store::OpenResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let params = pry!(params.get());
        let fp = pry!(params.get_fingerprint());
        let fp = sry!(Fingerprint::from_hex(fp)
                      .map_err(|_| store::Error::MalformedFingerprint));

        let key = sry!(KeyServer::open(self.state.clone(), &fp));
        pry!(pry!(results.get().get_result()).set_ok(
            store::key::ToClient::new(key).into_client::<capnp_rpc::Server>()));
        Promise::ok(())
    }

    fn import(&mut self,
              params: store::ImportParams,
              mut results: store::ImportResults)
              -> Promise<(), capnp::Error> {
        bind_results!(results);

        // This is the key to import.
        let new = sry!(TPK::from_bytes(&pry!(pry!(params.get()).get_key())));
        let fp = new.fingerprint();

        let id: Option<ID>
            = sry!(match self.state.c.query_row(
                "SELECT id FROM keys WHERE fingerprint = ?1",
                &[&fp.to_hex()],
                |row| row.get(0)) {
                Ok(x) => Ok(Some(x)),
                Err(e) => match e {
                    rusqlite::Error::QueryReturnedNoRows =>
                        Ok(None),
                    _ => Err(e),
                },
            });

        if id.is_some() {
            fail!(store::Error::KeyExists);
        }

        // Write key back to the database.
        let mut blob = vec![];
        sry!(new.serialize(&mut blob));

        sry!(self.state.c.execute("INSERT INTO keys (fingerprint, key, created)
                             VALUES (?, ?, ?)",
                            &[&fp.to_hex(), &blob, &Timestamp::now()]));

        let key = KeyServer::new(self.state.clone(),
                                 self.state.c.last_insert_rowid().into());
        pry!(pry!(results.get().get_result()).set_ok(
            store::key::ToClient::new(key).into_client::<capnp_rpc::Server>()));
        Promise::ok(())
    }

    fn iter(&mut self,
            _: store::IterParams,
            mut results: store::IterResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let iter = KeyIterServer::new(self.state.clone());
        pry!(pry!(results.get().get_result()).set_ok(
            store::key_iter::ToClient::new(iter).into_client::<capnp_rpc::Server>()));
        Promise::ok(())
    }
}

struct KeyServer {
    state: Rc<State>,
    id: ID,
}

impl KeyServer {
    fn new(state: Rc<State>, id: ID) -> Self {
        KeyServer {
            state: state,
            id: id,
        }
    }

    fn open(state: Rc<State>, fp: &Fingerprint) -> Result<Self> {
        let fp = fp.to_hex();
        let id = state.c.query_row(
            "SELECT id FROM keys WHERE fingerprint = ?1",
            &[&fp], |row| row.get(0))
            .map_err(|_| Error::NotFound)?;

        Ok(Self::new(state, id))
    }

}

impl store::key::Server for KeyServer {
    fn tpk(&mut self,
           _: store::key::TpkParams,
           mut results: store::key::TpkResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        let key: Vec<u8> = sry!(
            self.state.c.query_row(
                "SELECT key FROM keys WHERE id = ?1",
                &[&self.id],
                |row| row.get_checked(0).unwrap_or(vec![])));
        // XXX tpkify key
        pry!(pry!(results.get().get_result()).set_ok(key.as_slice()));
        Promise::ok(())
    }

    fn unlock(&mut self,
              params: store::key::UnlockParams,
              mut results: store::key::UnlockResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        let passphrase = pry!(pry!(params.get()).get_passphrase());
        if passphrase != "streng geheim" {
            fail!(store::Error::BadPassphrase);
        }
        Promise::ok(())
    }

    fn lock(&mut self,
            _: store::key::LockParams,
            _: store::key::LockResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        Promise::ok(())
    }

    fn decrypt(&mut self,
              params: store::key::DecryptParams,
              mut results: store::key::DecryptResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        if false {
            fail!(store::Error::KeyLocked);
        }

        let sk = pry!(pry!(params.get()).get_sk());
        pry!(pry!(results.get().get_result()).set_ok(sk));
        Promise::ok(())
    }

    fn sign(&mut self,
            params: store::key::SignParams,
            mut results: store::key::SignResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);

        let subkey: openpgp::KeyID =
            pry!(params.get()).get_subkey_id().into();
        //pry!(pry!(results.get().get_result()).set_ok(sk));
        Promise::ok(())
    }
}

struct KeyIterServer {
    state: Rc<State>,
    n: ID,
}

impl KeyIterServer {
    fn new(state: Rc<State>) -> Self {
        KeyIterServer{state: state, n: ID::null()}
    }
}

impl store::key_iter::Server for KeyIterServer {
    fn next(&mut self,
            _: store::key_iter::NextParams,
            mut results: store::key_iter::NextResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let (id, fingerprint): (ID, String) =
            sry!(self.state.c.query_row(
                 "SELECT id, fingerprint FROM keys
                      WHERE keys.id > ?1
                      ORDER BY id LIMIT 1",
                &[&self.n],
                |row| (row.get(0), row.get(1))));

        let mut entry = pry!(results.get().get_result()).init_ok();
        entry.set_fingerprint(&fingerprint);
        entry.set_key(store::key::ToClient::new(
            KeyServer::new(self.state.clone(), id)).into_client::<capnp_rpc::Server>());
        self.n = id;
        Promise::ok(())
    }
}

/* Database schemata and migrations.  */

/* Version 1.  */
const DB_SCHEMA_1: &'static str = "
CREATE TABLE version (
    id INTEGER PRIMARY KEY,
    version INTEGER);

INSERT INTO version (id, version) VALUES (1, 1);

CREATE TABLE local_key (
    id INTEGER PRIMARY KEY,
    key BLOB);

CREATE TABLE keys (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    key BLOB,

    created INTEGER NOT NULL,
    updated INTEGER NULL,

    UNIQUE (fingerprint));
";

impl fmt::Debug for store::Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "store::Error::{}",
               match self {
                   &store::Error::NotFound => "NotFound",
                   &store::Error::KeyExists => "KeyExists",
                   &store::Error::MalformedKey => "MalformedKey",
                   &store::Error::MalformedFingerprint => "MalformedFingerprint",
                   &store::Error::StoreLocked => "StoreLocked",
                   &store::Error::KeyLocked => "KeyLocked",
                   &store::Error::BadPassphrase => "BadPassphrase",
               })
    }
}

impl From<failure::Error> for store::Error {
    fn from(e: failure::Error) -> Self {
        if e.downcast_ref::<openpgp::Error>().is_some() {
            // XXX differentiate
            return store::Error::MalformedKey;
        }

        if let Some(e) = e.downcast_ref::<Error>() {
            return match e {
                &Error::NotFound => store::Error::NotFound,
                _ => unimplemented!(),
            }
        }

        // XXX: Currently, this does not happen, hence rustc warns
        // if let Some(e) = e.downcast_ref::<core::Error>() {
        //     return match e {
        //         _ => unimplemented!(),
        //     }
        // }

        if let Some(e) = e.downcast_ref::<rusqlite::Error>() {
            return match e {
                &rusqlite::Error::SqliteFailure(f, _) => match f.code {
                    rusqlite::ErrorCode::ConstraintViolation =>
                        store::Error::NotFound,
                    _ => unimplemented!(),
                },
                &rusqlite::Error::QueryReturnedNoRows =>
                    store::Error::NotFound,
                _ => unimplemented!(),
            }
        }

        eprintln!("Error not converted: {:?}", e);
        unimplemented!()
    }
}

impl From<rusqlite::Error> for store::Error {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(f, _) => match f.code {
                rusqlite::ErrorCode::ConstraintViolation =>
                    store::Error::NotFound,
                _ => unimplemented!(),
            },
            rusqlite::Error::QueryReturnedNoRows =>
                store::Error::NotFound,
                _ => unimplemented!(),
        }
    }
}
