use sequoia_openpgp as openpgp;
use openpgp::Cert;
use openpgp::parse::Parse;
use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
use sequoia_store::not_sync::Store;

fn main() -> openpgp::Result<()> {
    let mut rt = tokio::runtime::Builder::new()
        .basic_scheduler().enable_io().enable_time()
        .build()?;
    tokio::task::LocalSet::new().block_on(&mut rt, real_main())
}

async fn real_main() -> openpgp::Result<()> {
    let ctx = Context::configure()
        .network_policy(NetworkPolicy::Offline)
        .ipc_policy(IPCPolicy::Internal)
        .ephemeral().build()?;
    let cert = Cert::from_bytes(
        &include_bytes!("../../openpgp/tests/data/keys/testy.pgp")[..]).unwrap();
    let key = Store::import(&ctx, &cert).await?;
    assert_eq!(key.cert().await?.fingerprint(), cert.fingerprint());
    Ok(())
}
