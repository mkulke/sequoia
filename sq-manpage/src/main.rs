use man::prelude::*;
use std::fs::File;
use std::io::Write;

use clap::{AnyArg, ArgSettings};

mod sq_cli;

fn main() -> std::io::Result<()> {
    let app = sq_cli::build();

    let main_manpage = create_manpage(app.clone(), None);

    let main_manpage = add_help_flag(main_manpage);
    let main_manpage = add_version_flag(main_manpage);

    let mut file = File::create(format!("{}.1", app.p.meta.name))?;
    file.write_all(main_manpage.render().as_bytes())?;

    for subcommand in app.p.subcommands {
        let sc_full_name =
            format!("{} {}", app.p.meta.name, subcommand.p.meta.name);
        let sc_manpage =
            create_manpage(subcommand.clone(), Some(&sc_full_name));
        let sc_manpage = add_help_flag(sc_manpage);

        let mut file = File::create(format!(
            "{}-{}.1",
            app.p.meta.name, subcommand.p.meta.name
        ))?;
        file.write_all(sc_manpage.render().as_bytes())?;
    }

    Ok(())
}

fn create_manpage(app: clap::App, name: Option<&str>) -> Manual {
    let name = name.unwrap_or(&app.p.meta.name);

    let mut manpage = Manual::new(&name);
    manpage = add_authors(manpage);
    manpage = manpage.date("January 2021");
    manpage  = add_help_flag(manpage);

    if let Some(about) = app.p.meta.long_about.filter(|la| !la.is_empty()).or(app.p.meta.about) {
        manpage = manpage.about(about);
    };
    for flag in app.p.flags {
        let mut man_flag = Flag::new();
        if let Some(short) = flag.short() {
            man_flag = man_flag.short(&format!("-{}", short));
        }
        if let Some(long) = flag.long() {
            man_flag = man_flag.long(&format!("--{}", long));
        }
        if let Some(help) = flag.long_help().or(flag.help()) {
            man_flag = man_flag.help(help);
        }
        manpage = manpage.flag(man_flag);
    }
    for option in app.p.opts {
        //TODO there may be more values
        let mut man_option = Opt::new(option.val_names().unwrap()[0]);
        if let Some(short) = option.short() {
            man_option = man_option.short(&format!("-{}", short));
        }
        if let Some(long) = option.long() {
            man_option = man_option.long(&format!("--{}", long));
        }
        if let Some(help) = option.long_help().or(option.help()) {
            man_option = man_option.help(help);
        }
        manpage = manpage.option(man_option);
    }
    for arg in app.p.positionals {
        //arg is a pair of (count, Arg)
        let arg = arg.1;
        let val_name = arg.val_names().unwrap()[0];
        let required = arg.is_set(ArgSettings::Required);
        let mut man_arg = man::Arg::new(val_name, required);
        if let Some(help) = arg.long_help().or(arg.help()) {
            man_arg = man_arg.description(help);
        }
        manpage = manpage.arg(man_arg);
    }
    if !app.p.subcommands.is_empty() {
        manpage = add_help_subcommand(manpage);
    };
    for subcommand in app.p.subcommands {
        let sc_meta = subcommand.p.meta;
        let mut man_subcommand = Subcommand::new(&sc_meta.name);
        if let Some(about) = sc_meta.long_about.filter(|la| !la.is_empty()).or(sc_meta.about) {
            man_subcommand = man_subcommand.description(about);
        };
        manpage = manpage.subcommand(man_subcommand);
    }
    if let Some(more_help) = app.p.meta.more_help {
        // this is specific to sequoia
        manpage = add_examples(manpage, more_help);
    }
    if let Some(version) = app.p.meta.version {
        manpage = manpage.version(version);
    };

    manpage
}

fn add_authors(mut manpage: Manual) -> Manual {
    let authors = [
        "Justus Winter <justus@sequoia-pgp.org>",
        "Kai Michaelis <kai@sequoia-pgp.org>",
        "Neal H. Walfield <neal@sequoia-pgp.org>",
    ];
    for author in authors.iter() {
        let mut split = author.split(" <");
        let name = split.next().unwrap();
        let email = split.next().unwrap().replace(">", "");
        let author = Author::new(name).email(&email);
        manpage = manpage.author(author);
    }
    manpage
}

/// Parse examples from clap's after_help (called more_help internally)
fn add_examples(mut manpage: Manual, more_help: &str) -> Manual {
    let mut lines_iter = more_help.lines();
    while let Some(line) = lines_iter.next() {
        if line.is_empty() || line.contains("EXAMPLE") {
            continue
        } else {
            let text = line.replace("# ", "");
            let command = lines_iter.next().expect("command example expected");
            let command = command.replace("$ ", "");
            let example = Example::new()
                .text(&text)
                .command(&command);
            manpage = manpage.example(example);
        }
    }
    manpage
}

fn add_help_subcommand(manpage: Manual) -> Manual {
    let help = Subcommand::new("help").description(
        "Prints this message or the help of the given subcommand(s)",
    );
    manpage.subcommand(help)
}

fn add_help_flag(manpage: Manual) -> Manual {
    let help = Flag::new()
        .short("-h")
        .long("--help")
        .help("Prints help information");
    manpage.flag(help)
}

fn add_version_flag(manpage: Manual) -> Manual {
    let version = Flag::new()
        .short("-V")
        .long("--version")
        .help("Prints version information");
    manpage.flag(version)
}
