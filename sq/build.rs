use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use clap_complete::Shell;
use anyhow::Result;
use clap_mangen::Man;

pub mod sq_cli {
    include!("src/sq_cli.rs");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // XXX: Revisit once
    // https://github.com/rust-lang/rust/issues/44732 is stabilized.

    subplot_build::codegen(Path::new("sq-subplot.md"))
        .expect("failed to generate code with Subplot");

    let mut sq = sq_cli::build().term_width(80);
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

    fs::create_dir_all("manpages").unwrap();
    let _ = dump_manpage(
        &sq,
        std::ffi::OsStr::new("manpages"),
        Vec::from([sq.get_name().to_owned()]),
    );

    // TODO: CARGO_TARGET_DIR is not always set, I think currently only by Makefile. So this is
    // janky
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

fn dump_manpage(
    cmd: &clap::Command,
    outdir: &OsStr,
    up_to_same_level: Vec<String>,
) -> Result<()> {
    //let command_name = match prefix {
    //    Some(p) => p.to_owned() + "-" + cmd.get_name(),
    //    None => cmd.get_name().to_owned(),
    //};

    // add subcommands to see_also
    let mut see_also = up_to_same_level.clone();
    see_also.extend(
        cmd.get_subcommands()
            .map(|sc| sc.get_display_name().unwrap_or_else(|| sc.get_name()))
            .map(|s| s.to_owned())
    );

    let mut man = clap_mangen::Man::new(cmd.clone())
        // Add build date in the form "Month Year" to the bottom of the manpage
        .date(chrono::Utc::today().format("%B %Y").to_string())
        // The manual's title, akin to git's "Git Manual"
        .manual("Sequoia Manual")
        // The source for all (sub)commands is sq, with version
        .source(&format!("sq {}", env!("CARGO_PKG_VERSION")));

    man = add_relevant_see_also(
        man,
        see_also.clone(),
        cmd.get_display_name().unwrap_or_else(|| cmd.get_name()),
    );
    let mut buffer: Vec<u8> = Default::default();
    man.render(&mut buffer)?;

    let mut path = PathBuf::from(outdir);
    path.push(cmd.get_display_name().unwrap_or_else(|| cmd.get_name()));
    path.set_extension("1");

    println!("cargo:warning=generated manpages: {:?}", path);
    std::fs::write(path, buffer)?;

    for subcmd in cmd.get_subcommands().filter(|s| !s.get_name().contains("help")) {
        dump_manpage(subcmd, outdir, see_also.clone())?
    }
    Ok(())
}

fn add_relevant_see_also<'a>(
    mut man: Man<'a>,
    subcommands: Vec<String>,
    own_name: &str,
) -> Man<'a> {
    for s in subcommands
        .into_iter()
        .filter(|sc| sc != &own_name)
        .filter(|sc| !sc.contains("help"))
    {
        man = man.see_also(format!("{}(1)", s));
    }
    man
}
