use std::path::PathBuf;

use crate::sq_cli::store;
use sequoia_public_store::{Result, Store};

use openpgp::crypto::Password;
use openpgp::Fingerprint;
use sequoia_openpgp as openpgp;

pub fn store(c: store::Command) -> Result<()> {
    match c.subcommand {
        store::Subcommands::Get(c) => get(c.store, c.fingerprint),
        store::Subcommands::Insert(c) => insert(c.store),
        store::Subcommands::Import(c) => import(c.store),
        store::Subcommands::Export(c) => export(c.store),
        store::Subcommands::Search(c) => search(c),
        store::Subcommands::Setup(c) => {
            if c.import_from_stdin {
                setup_import_stdin(c.store)
            } else {
                setup_create(c.store, c.with_password)
            }
        }
    }
}

fn get(store: Option<PathBuf>, fingerprint: String) -> Result<()> {
    let certd = Store::new(store)?;

    let fingerprint = Fingerprint::from_hex(&fingerprint)?;

    certd.get_raw(&fingerprint, &mut std::io::stdout())
}

fn insert(store: Option<PathBuf>) -> Result<()> {
    let certd = Store::new(store)?;

    certd.insert(std::io::stdin())
}

fn import(store: Option<PathBuf>) -> Result<()> {
    let certd = Store::new(store)?;

    certd.import(std::io::stdin())
}

fn export(store: Option<PathBuf>) -> Result<()> {
    let certd = Store::new(store)?;

    certd.export(&mut std::io::stdout())
}

// Setup a new certificate directory and create a trust-root.
//
// The created trust-root
// - has a userid "trust-root", for compatibility
// - optionally a password
// - certification capable primary key
// - no subkeys
// - the direct key signature and the primary userid's binding signature are
//   marked non-exportable.
//
// See 3.5.1 for the trust-root's specification.
fn setup_create(store: Option<PathBuf>, with_password: bool) -> Result<()> {
    let certd = Store::new(store)?;

    let password = if with_password {
        Some(read_new_password()?)
    } else {
        None
    };

    certd.setup_create(password)
}

// Read a new password from stdin and double check.
fn read_new_password() -> anyhow::Result<Password> {
    let p0 = {
        rpassword::prompt_password("Enter password to protect the key: ")?
            .into()
    };
    let p1: Password = {
        rpassword::prompt_password("Repeat the password once more: ")?.into()
    };

    if p0 == p1 {
        Ok(p0)
    } else {
        Err(anyhow::anyhow!("Passwords do not match."))
    }
}

// Import the trust-root from stdin.
fn setup_import_stdin(store: Option<PathBuf>) -> Result<()> {
    let certd = Store::new(store)?;

    certd.setup_import_stdin(std::io::stdin())
}

fn search(c: store::SearchCommand) -> Result<()> {
    let certd = Store::new(c.store)?;

    if let Some(fp) = c.fingerprint {
        let certs = certd.search_by_fp(&fp)?;
        for cert in certs {
            println!("{}", cert.fingerprint())
        }
    } else {
        if let Some(userid) = c.userid {
            let certs = certd.search_by_userid(&userid)?;
            for cert in certs {
                println!("{}", cert.fingerprint())
            }
        }
    }

    Ok(())
}
