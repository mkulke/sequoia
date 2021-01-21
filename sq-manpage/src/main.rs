use man::prelude::*;
use std::fs::File;
use std::io::Write;

fn main() -> std::io::Result<()> {
    let _page = Manual::new("basic")
        .about("A basic example")
        .author(Author::new("Alice Person").email("alice@person.com"))
        .author(Author::new("Bob Human").email("bob@human.com"))
        .flag(
            Flag::new()
                .short("-d")
                .long("--debug")
                .help("Enable debug mode"),
        )
        .flag(
            Flag::new()
                .short("-v")
                .long("--verbose")
                .help("Enable verbose mode"),
        )
        .option(
            Opt::new("output")
                .short("-o")
                .long("--output")
                .help("The file path to write output to"),
        )
        .example(
            Example::new()
                .text("run basic in debug mode")
                .command("basic -d")
                .output("Debug Mode: basic will print errors to the console")
            )
        .custom(
            Section::new("usage note")
                .paragraph("This program will overwrite any file currently stored at the output path")
        )
        .render();


    //TODO: get rid of = for Options
    let sq_manpage = Manual::new("sq")
        .about("Sequoia is an implementation of OpenPGP.  This is a command-line frontend.")
        .header_title("sequoia") //TODO decide what goes here
        .flag(Flag::new()
             .short("-f").long("--force")
             .help("Overwrite existing files"))
        .flag(Flag::new()
             .short("-h").long("--help")
             .help("Prints help information"))
        .flag(Flag::new()
             .short("-V").long("--version")
             .help("Prints version information"))
        .option(Opt::new(" NOTATION ")
             .long("--known-notation")
             .help("The notation name is considered known. \
               This is used when validating signatures. \
               Signatures that have unknown notations with the \
               critical bit set are considered invalid."))
             //TODO .value_name("NOTATION")
        .subcommand(
            Subcommand::new()
            .name("encrypt")
            .help("Encrypts a message"));

    let mut file = File::create("sq_manpage")?;
    file.write_all(sq_manpage.render().as_bytes())?;
    Ok(())
}
