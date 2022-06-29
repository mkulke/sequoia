use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use clap_complete::Shell;

pub mod sq_cli {
    include!("src/sq_cli.rs");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // XXX: Revisit once
    // https://github.com/rust-lang/rust/issues/44732 is stabilized.

    subplot_build::codegen(Path::new("sq-subplot.md"))
        .expect("failed to generate code with Subplot");

    let mut sq = sq_cli::configure(
        clap::Command::new("sq").term_width(80),
    );
    let mut main = fs::File::create("src/sq-usage.rs").unwrap();
    dump_help(&mut main,
              &mut sq,
              vec![],
              "#").unwrap();
    writeln!(main, "\n#![doc(html_favicon_url = \"https://docs.sequoia-pgp.org/favicon.png\")]")
        .unwrap();
    writeln!(main, "#![doc(html_logo_url = \"https://docs.sequoia-pgp.org/logo.svg\")]")
        .unwrap();
    writeln!(main, "\ninclude!(\"sq.rs\");").unwrap();

    let outdir = match env::var_os("CARGO_TARGET_DIR") {
        None => return,
        Some(outdir) => outdir,
    };
    fs::create_dir_all(&outdir).unwrap();
    let mut sq = sq_cli::build();

    for shell in &[Shell::Bash, Shell::Fish, Shell::Zsh, Shell::PowerShell,
                   Shell::Elvish] {
        let path = clap_complete::generate_to(*shell, &mut sq, "sq", &outdir).unwrap();
        println!("cargo:warning=completion file is generated: {:?}", path);
    };
}

fn dump_help(sink: &mut dyn io::Write,
             sq: &mut clap::Command,
             cmd: Vec<String>,
             heading: &str)
             -> io::Result<()>
{

    if cmd.is_empty() {
        writeln!(sink, "//! A command-line frontend for Sequoia.")?;
        writeln!(sink, "//!")?;
        writeln!(sink, "//! # Usage")?;
    } else {
        writeln!(sink, "//!")?;
        writeln!(sink, "//! {} Subcommand {}", heading, cmd.join(" "))?;
    }

    writeln!(sink, "//!")?;

    let args = std::iter::once("sq")
        .chain(cmd.iter().map(|s| s.as_str()))
        .chain(std::iter::once("--help"))
        .collect::<Vec<_>>();

    let help = sq.try_get_matches_from_mut(&args)
        .unwrap_err().to_string();

    writeln!(sink, "//! ```text")?;
    for line in help.trim_end().split('\n').skip(1) {
        if line.is_empty() {
            writeln!(sink, "//!")?;
        } else {
            writeln!(sink, "//! {}", line.trim_end())?;
        }
    }
    writeln!(sink, "//! ```")?;

    // Recurse.
    let mut found_subcommands = false;
    for subcmd in help.split('\n').filter_map(move |line| {
        if line == "SUBCOMMANDS:" {
            found_subcommands = true;
            None
        } else if found_subcommands {
            if line.chars().nth(4).map(|c| ! c.is_ascii_whitespace())
                .unwrap_or(false)
            {
                line.trim_start().split(' ').next()
            } else {
                None
            }
        } else {
            None
        }
    }).filter(|subcmd| *subcmd != "help") {
        let mut c = cmd.clone();
        c.push(subcmd.into());
        dump_help(sink, sq, c, &format!("{}#", heading))?;
    }

    Ok(())
}
