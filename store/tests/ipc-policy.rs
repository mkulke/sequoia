use sequoia_core;
use sequoia_store;

use std::env::current_exe;
use std::path::PathBuf;

use sequoia_core::{Context, NetworkPolicy, IPCPolicy};
use sequoia_store::{Result, not_sync::Mapping, REALM_CONTACTS};

#[test]
fn ipc_policy_external() -> Result<()> {
    async fn f() -> Result<()> {
        let ctx = Context::configure()
            .ephemeral()
            .lib(current_exe().unwrap().parent().unwrap().parent().unwrap())
            .network_policy(NetworkPolicy::Offline)
            .ipc_policy(IPCPolicy::External)
            .build()?;
        Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
        Ok(())
    }

    let mut rt = tokio::runtime::Builder::new()
        .basic_scheduler().enable_io().enable_time()
        .build()?;
    tokio::task::LocalSet::new().block_on(&mut rt, f())
}

#[test]
fn ipc_policy_internal() -> Result<()> {
    async fn f() -> Result<()> {
        let ctx = Context::configure()
            .ephemeral()
            .lib(PathBuf::from("/i/do/not/exist"))
            .network_policy(NetworkPolicy::Offline)
            .ipc_policy(IPCPolicy::Internal)
            .build()?;
        Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
        Ok(())
    }

    let mut rt = tokio::runtime::Builder::new()
        .basic_scheduler().enable_io().enable_time()
        .build()?;
    tokio::task::LocalSet::new().block_on(&mut rt, f())
}

#[test]
fn ipc_policy_robust() -> Result<()> {
    async fn f() -> Result<()> {
        let ctx = Context::configure()
            .ephemeral()
            .lib(current_exe().unwrap().parent().unwrap().parent().unwrap())
            .network_policy(NetworkPolicy::Offline)
            .ipc_policy(IPCPolicy::Robust)
            .build()?;
        Mapping::open(&ctx, REALM_CONTACTS, "default").await?;

        let ctx = Context::configure()
            .ephemeral()
            .lib(PathBuf::from("/i/do/not/exist"))
            .network_policy(NetworkPolicy::Offline)
            .ipc_policy(IPCPolicy::Robust)
            .build()?;
        Mapping::open(&ctx, REALM_CONTACTS, "default").await?;
        Ok(())
    }

    let mut rt = tokio::runtime::Builder::new()
        .basic_scheduler().enable_io().enable_time()
        .build()?;
    tokio::task::LocalSet::new().block_on(&mut rt, f())
}
