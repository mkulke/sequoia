use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(
    about = "Access sequoia's public certificate store.",
    long_about = "Access sequoia's public certificate store.",
    name = "store",
    subcommand_required = true,
    arg_required_else_help = true,
    setting(clap::AppSettings::DeriveDisplayOrder)
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}

#[derive(Debug, Subcommand)]
pub enum Subcommands {
    Get(GetCommand),
    Insert(InsertCommand),
    Export(ExportCommand),
    Setup(SetupCommand),
    Search(SearchCommand),
}

// TODO replace doc-comments with clap(about = "") attribute

#[derive(Debug, Args)]
#[clap(
    about = "Look up a certificate by its fingerprint",
    long_about = "Look up a certificate by its fingerprint. \
        If found, write the cert to stdout.",
    name = get,
    )]
pub struct GetCommand {
    /// The path of the store
    #[clap(short, long)]
    pub store: Option<PathBuf>,
    /// The fingerprint
    // TODO: Use a Fingerprint type
    pub fingerprint: String,
}

#[derive(Debug, Args)]
#[clap(
    about = "Insert or update a certificate",
    long_about = "Insert or update a certificate. \
        Read the cert from stdin",
    name = insert,
    )]
pub struct InsertCommand {
    /// The path of the store
    #[clap(short, long)]
    pub store: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[clap(
    about = "Import certificates into the store",
    long_about = "Import certificates into the store from stdin.",
    name = import,
    )]
pub struct ImportCommand {
    /// The path of the store
    #[clap(short, long)]
    pub store: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[clap(
    about = "Export all certificates in the store",
    long_about = "Export all certificates in the store to stdout.",
    name = export,
    )]
pub struct ExportCommand {
    /// The path of the store
    #[clap(short, long)]
    pub store: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[clap(
    about = "Setup a new store",
    long_about = "Setup a new store. \
        Import the trust-root or create a new one.",
    name = setup,
    )]
pub struct SetupCommand {
    /// The path of the store
    #[clap(short, long, global(true))]
    pub store: Option<PathBuf>,
    /// Ask for a password
    #[clap(long = "with-password", conflicts_with("import-from-stdin"))]
    pub with_password: bool,
    /// Import from stdin
    #[clap(long = "import-from-stdin", conflicts_with("with-password"))]
    pub import_from_stdin: bool,
}

#[derive(Debug, Args)]
#[clap(
    about = "Look for a certificates in the store",
    long_about = "Look for a certificates in the store and output their fingerprints. \
        Use sq store get to get the full certificates.",
    name = search,
    )]
pub struct SearchCommand {
    /// The path of the store
    #[clap(short, long)]
    pub store: Option<PathBuf>,
    /// Search by (subkey) fingerprint
    #[clap(
        short,
        long,
        conflicts_with("userid")
    )]
    pub fingerprint: Option<sequoia_openpgp::Fingerprint>,
    /// Search by userid
    #[clap(
        short,
        long,
        conflicts_with("fingerprint")
    )]
    pub userid: Option<String>,
}

