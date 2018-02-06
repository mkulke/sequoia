//! Secret key backend.

use capnp::capability::Promise;
use capnp;
use capnp_rpc::rpc_twoparty_capnp::Side;
use capnp_rpc::{self, RpcSystem, twoparty};
use failure;
use rusqlite::Connection;
use rusqlite::types::{ToSql, ToSqlOutput, FromSql, FromSqlResult, ValueRef};
use rusqlite;
use std::fmt;
use std::ops::{Add, Sub};
use std::rc::Rc;
use tokio_core::reactor::Handle;
use tokio_core;
use tokio_io::io::ReadHalf;
use time::{Timespec, Duration, now_utc};

use openpgp::Fingerprint;
use openpgp::tpk;
use sequoia_core as core;
use sequoia_net::ipc;

use secret_protocol_capnp::node;

use super::{TSK, Error, Result};

/* Entry point.  */

/// Makes backends.
#[doc(hidden)]
pub fn factory(descriptor: ipc::Descriptor, handle: Handle) -> Option<Box<ipc::Handler>> {
    match Backend::new(descriptor, handle) {
        Ok(backend) => Some(Box::new(backend)),
        Err(_) => None,
    }
}

struct Backend {
    secret: node::Client,
}

impl Backend {
    fn new(descriptor: ipc::Descriptor, handle: Handle) -> Result<Self> {
        Ok(Backend {
            secret: node::ToClient::new(NodeServer::new(descriptor, handle)?)
                .from_server::<capnp_rpc::Server>(),
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

struct NodeServer {
    _descriptor: ipc::Descriptor,
    c: Rc<Connection>,
}

impl NodeServer {
    fn new(descriptor: ipc::Descriptor, handle: Handle) -> Result<Self> {
        let mut db_path = descriptor.context().home().to_path_buf();
        db_path.push("secrets.sqlite");

        let c = Connection::open(db_path)?;
        c.execute_batch("PRAGMA secure_delete = true;")?;
        c.execute_batch("PRAGMA foreign_keys = true;")?;
        let server = NodeServer {
            _descriptor: descriptor,
            c: Rc::new(c),
        };
        server.init()?;

        Ok(server)
    }

    /// Initializes or migrates the database.
    fn init(&self) -> Result<()> {
        let v = self.c.query_row(
            "SELECT version FROM version WHERE id=1",
            &[], |row| row.get(0));

        if let Ok(v) = v {
            match v {
                1 => return Ok(()),
                _ => unimplemented!(),
            }
        }

        self.c.execute_batch(DB_SCHEMA_1)?;
        Ok(())
    }
}

impl node::Server for NodeServer {
    fn open(&mut self,
            params: node::OpenParams,
            mut results: node::OpenResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let params = pry!(params.get());
        let fp = pry!(params.get_fingerprint());
        let fp = sry!(Fingerprint::from_hex(fp)
                      .ok_or(node::Error::MalformedFingerprint));

        let key = sry!(KeyServer::open(self.c.clone(), &fp));
        pry!(pry!(results.get().get_result()).set_ok(
            node::key::ToClient::new(key).from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }

    fn import(&mut self,
              params: node::ImportParams,
              mut results: node::ImportResults)
              -> Promise<(), capnp::Error> {
        bind_results!(results);

        // This is the key to import.
        let new = sry!(TSK::from_bytes(&pry!(pry!(params.get()).get_key())));
        let fp = new.fingerprint();

        let id: Option<ID>
            = sry!(match self.c.query_row(
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
            fail!(node::Error::KeyExists);
        }

        // Write key back to the database.
        let mut blob = vec![];
        sry!(new.serialize(&mut blob));

        sry!(self.c.execute("INSERT INTO keys (fingerprint, key, created)
                             VALUES (?, ?, ?)",
                            &[&fp.to_hex(), &blob, &Timestamp::now()]));

        let key = KeyServer::new(self.c.clone(),
                                 self.c.last_insert_rowid().into());
        pry!(pry!(results.get().get_result()).set_ok(
            node::key::ToClient::new(key).from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }

    fn iter(&mut self,
            params: node::IterParams,
            mut results: node::IterResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let iter = KeyIterServer::new(self.c.clone());
        pry!(pry!(results.get().get_result()).set_ok(
            node::key_iter::ToClient::new(iter).from_server::<capnp_rpc::Server>()));
        Promise::ok(())
    }
}

struct KeyServer {
    c: Rc<Connection>,
    id: ID,
    locked: bool,
}

impl KeyServer {
    fn new(c: Rc<Connection>, id: ID) -> Self {
        KeyServer {
            c: c,
            id: id,
            locked: true,
        }
    }

    fn open(c: Rc<Connection>, fp: &Fingerprint) -> Result<Self> {
        let fp = fp.to_hex();
        let id = c.query_row(
            "SELECT id FROM keys WHERE fingerprint = ?1",
            &[&fp], |row| row.get(0))
            .map_err(|_| Error::NotFound)?;

        Ok(Self::new(c, id))
    }

}

impl node::key::Server for KeyServer {
    fn tpk(&mut self,
           _: node::key::TpkParams,
           mut results: node::key::TpkResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        let key: Vec<u8> = sry!(
            self.c.query_row(
                "SELECT key FROM keys WHERE id = ?1",
                &[&self.id],
                |row| row.get_checked(0).unwrap_or(vec![])));
        // XXX tpkify key
        pry!(pry!(results.get().get_result()).set_ok(key.as_slice()));
        Promise::ok(())
    }

    fn unlock(&mut self,
              params: node::key::UnlockParams,
              mut results: node::key::UnlockResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        let passphrase = pry!(pry!(params.get()).get_passphrase());
        if passphrase != "streng geheim" {
            fail!(node::Error::BadPassphrase);
        }
        self.locked = false;
        Promise::ok(())
    }

    fn lock(&mut self,
            _: node::key::LockParams,
            mut results: node::key::LockResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        self.locked = true;
        Promise::ok(())
    }

    fn decrypt(&mut self,
              params: node::key::DecryptParams,
              mut results: node::key::DecryptResults)
           -> Promise<(), capnp::Error> {
        bind_results!(results);
        if self.locked {
            fail!(node::Error::KeyLocked);
        }

        let sk = pry!(pry!(params.get()).get_sk());
        pry!(pry!(results.get().get_result()).set_ok(sk));
        Promise::ok(())
    }
}

struct KeyIterServer {
    c: Rc<Connection>,
    n: ID,
}

impl KeyIterServer {
    fn new(c: Rc<Connection>) -> Self {
        KeyIterServer{c: c, n: ID::null()}
    }
}

impl node::key_iter::Server for KeyIterServer {
    fn next(&mut self,
            _: node::key_iter::NextParams,
            mut results: node::key_iter::NextResults)
            -> Promise<(), capnp::Error> {
        bind_results!(results);
        let (id, fingerprint): (ID, String) =
            sry!(self.c.query_row(
                 "SELECT id, fingerprint FROM keys
                      WHERE keys.id > ?1
                      ORDER BY id LIMIT 1",
                &[&self.n],
                |row| (row.get(0), row.get(1))));

        let mut entry = pry!(results.get().get_result()).init_ok();
        entry.set_fingerprint(&fingerprint);
        entry.set_key(node::key::ToClient::new(
            KeyServer::new(self.c.clone(), id)).from_server::<capnp_rpc::Server>());
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

CREATE TABLE keys (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    key BLOB,

    created INTEGER NOT NULL,
    updated INTEGER NULL,

    UNIQUE (fingerprint));
";

/// Represents a row id.
///
/// This is used to represent handles to stored objects.
#[derive(Copy, Clone, PartialEq)]
pub struct ID(i64);

impl ID {
    /// Returns ID(0).
    ///
    /// This is smaller than all valid ids.
    fn null() -> Self {
        ID(0)
    }

    /// Returns the largest id.
    fn max() -> Self {
        ID(::std::i64::MAX)
    }
}

impl From<i64> for ID {
    fn from(id: i64) -> Self {
        ID(id)
    }
}

impl ToSql for ID {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        Ok(ToSqlOutput::from(self.0))
    }
}

impl FromSql for ID {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        value.as_i64().map(|id| id.into())
    }
}

impl fmt::Debug for node::Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "node::Error::{}",
               match self {
                   &node::Error::NotFound => "NotFound",
                   &node::Error::KeyExists => "KeyExists",
                   &node::Error::MalformedKey => "MalformedKey",
                   &node::Error::MalformedFingerprint => "MalformedFingerprint",
                   &node::Error::KeyLocked => "KeyLocked",
                   &node::Error::BadPassphrase => "BadPassphrase",
               })
    }
}

impl From<failure::Error> for node::Error {
    fn from(e: failure::Error) -> Self {
        if e.downcast_ref::<tpk::Error>().is_some() {
            return node::Error::MalformedKey;
        }

        if let Some(e) = e.downcast_ref::<Error>() {
            return match e {
                &Error::NotFound => node::Error::NotFound,
                _ => unreachable!(),
            }
        }

        if let Some(e) = e.downcast_ref::<core::Error>() {
            return match e {
                _ => unreachable!(),
            }
        }

        if let Some(e) = e.downcast_ref::<rusqlite::Error>() {
            return match e {
                &rusqlite::Error::SqliteFailure(f, _) => match f.code {
                    rusqlite::ErrorCode::ConstraintViolation =>
                        node::Error::NotFound,
                    _ => unimplemented!(),
                },
                &rusqlite::Error::QueryReturnedNoRows =>
                    node::Error::NotFound,
                _ => unimplemented!(),
            }
        }

        eprintln!("Error not converted: {:?}", e);
        unimplemented!()
    }
}

impl From<rusqlite::Error> for node::Error {
    fn from(error: rusqlite::Error) -> Self {
        match error {
            rusqlite::Error::SqliteFailure(f, _) => match f.code {
                rusqlite::ErrorCode::ConstraintViolation =>
                    node::Error::NotFound,
                _ => unimplemented!(),
            },
            rusqlite::Error::QueryReturnedNoRows =>
                node::Error::NotFound,
                _ => unimplemented!(),
        }
    }
}

/* Timestamps.  */

/// A serializable system time.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
struct Timestamp(Timespec);

impl Timestamp {
    fn now() -> Self {
        Timestamp(now_utc().to_timespec())
    }

    /// Converts to unix time.
    fn unix(&self) -> i64 {
        self.0.sec
    }
}

impl ToSql for Timestamp {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput> {
        Ok(ToSqlOutput::from(self.0.sec))
    }
}

impl FromSql for Timestamp {
    fn column_result(value: ValueRef) -> FromSqlResult<Self> {
        value.as_i64().map(|t| Timestamp(Timespec::new(t, 0)))
    }
}

impl Add<Duration> for Timestamp {
    type Output = Timestamp;

    fn add(self, other: Duration) -> Timestamp {
        Timestamp(self.0 + other)
    }
}

impl Sub<Timestamp> for Timestamp {
    type Output = Duration;

    fn sub(self, other: Self) -> Self::Output {
        self.0 - other.0
    }
}
