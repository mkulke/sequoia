use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
};
use openpgp::Fingerprint;
use openpgp::packet::prelude::*;
use openpgp::wot::Network;
use openpgp::wot::RootedNetwork;
use openpgp::policy::StandardPolicy;
use openpgp::cert::CertParser;
use openpgp::parse::Parse;

pub fn authenticate(m: &clap::ArgMatches, force: bool) -> Result<()> {
    let p = &StandardPolicy::new();

    let target_fpr: Fingerprint = m.value_of("certificate").unwrap()
        .parse()
        .context("Expected a Fingerprint or a Key ID")?;
    let target_userid: UserID = m.value_of("userid").unwrap().into();

    let mut roots: Vec<Fingerprint> = Vec::new();
    if let Some(values) = m.values_of("trust-root") {
        for r in values {
            roots.push(r.parse()?);
        }
    }

    let mut certs = Vec::new();
    if let Some(values) = m.values_of("certring") {
        for f in values {
            certs.extend(CertParser::from_file(f)?
                         .map(|c| c.expect("Valid certificate")));
        }
    }

    let n = Network::new(
        certs
            .iter()
            .filter_map(|c| c.with_policy(p, None).ok())
            .collect()
    )?;

    let r = RootedNetwork::new(&n, &roots[..]);

    let got = r.authenticate(target_userid.clone(),
                             target_fpr.clone(),
                             120);

    eprintln!("{:?}", got);
    Ok(())
}
