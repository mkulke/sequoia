use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(
    name = "keystore",
    about = "Interact with the keystore",
    long_about =
"Interact with the keystore
",
    after_help =
"EXAMPLES:

# List the keys.
$ sq keystore list
",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Command {
    #[clap(subcommand)]
    pub subcommand: Subcommands,
}


#[derive(Debug, Subcommand)]
pub enum Subcommands {
    List(ListCommand),
}

#[derive(Debug, Args)]
#[clap(
    about = "Lists resources on the keystore",
    long_about = "Lists resources on the keystore
",
    after_help = "EXAMPLES:

# List the keys on the keystore
$ sq keystore list
"
)]
pub struct ListCommand {
}
