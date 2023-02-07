use clap::Parser;

use crate::sq_cli::types::IoArgs;

#[derive(Parser, Debug)]
#[clap(
    name = "import",
    about = "Imports certificates into the local certificate store",
    long_about =
"Imports certificates into the local certificate store
",
    after_help =
"EXAMPLES:

# Inspects a certificate
$ sq import < juliet.pgp
",
)]
pub struct Command {
    #[clap(flatten)]
    pub io: IoArgs,
}
