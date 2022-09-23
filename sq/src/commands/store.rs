use std::path::PathBuf;

use crate::sq_cli::store;
use sequoia_public_store::{Result, Store};

use openpgp::crypto::Password;
use openpgp::Fingerprint;
use openpgp::serialize::Serialize;
use sequoia_openpgp as openpgp;

pub fn store(c: store::Command) -> Result<()> {
    match c.subcommand {
        store::Subcommands::Get(c) => get(c.store, c.fingerprint),
        store::Subcommands::Insert(c) => insert(c.store),
        store::Subcommands::Export(c) => export(c.store),
        store::Subcommands::Search(c) => search(c),
    }
}

// TODO: use common IO arguments
// TODO: use Fingerprint type for cli parsing
fn get(store: Option<PathBuf>, fingerprint: String) -> Result<()> {
    let certd = Store::new(store)?;

    let fp = Fingerprint::from_hex(&fingerprint)?;

    let cert = certd.get(&fp.into())?;
    cert.export(&mut std::io::stdout())?;
    Ok(())
}

// TODO: use common IO arguments
fn insert(store: Option<PathBuf>) -> Result<()> {
    let certd = Store::new(store)?;

    certd.insert(std::io::stdin())
}

// TODO: use common IO arguments
fn export(store: Option<PathBuf>) -> Result<()> {
    let certd = Store::new(store)?;

    certd.export(&mut std::io::stdout())
}

// TODO: use common IO arguments
// TODO: allos keyhandles on cli
fn search(c: store::SearchCommand) -> Result<()> {
    let certd = Store::new(c.store)?;

    if let Some(fp) = c.fingerprint {
        let certs = certd.search_by_kh(&fp.into())?;
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
