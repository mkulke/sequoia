use man::prelude::*;
use std::fs::File;
use std::io::Write;

use clap::AnyArg;

mod sq_cli;

fn main() -> std::io::Result<()> {
    let mut app = sq_cli::build();
    app = app.version("0.22.0");

    let sq_manpage = create_manpage(app.clone(), None);

    let sq_packet = app.p.subcommands.iter().find(|sc| sc.p.meta.name == "packet").unwrap();
    let sq_packet_manpage = create_manpage(sq_packet.clone(), Some("sq packet".to_string()));
    let mut file = File::create("sq_packet_manpage")?;
    file.write_all(sq_packet_manpage.render().as_bytes())?;

    let mut file = File::create("sq_manpage")?;
    file.write_all(sq_manpage.render().as_bytes())?;
    Ok(())
}

fn create_manpage(app: clap::App, name: Option<String>) -> Manual {
    let name = name.unwrap_or(app.p.meta.name);
    let mut manpage = Manual::new(&name);
    if let Some(about) = app.p.meta.about {
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
        if let Some(help) = flag.help() {
            man_flag = man_flag.help(help);
        }
        manpage = manpage.flag(man_flag);
    }
    for option in app.p.opts {
        let mut man_option = Opt::new(option.val_names().unwrap()[0]);
        if let Some(short) = option.short() {
            man_option = man_option.short(&format!("-{}", short));
        }
        if let Some(long) = option.long() {
            man_option = man_option.long(&format!("--{}", long));
        }
        if let Some(help) = option.help() {
            man_option = man_option.help(help);
        }
        manpage = manpage.option(man_option);
    }
    for subcommand in app.p.subcommands {
        let mut  man_subcommand = Subcommand::new(&subcommand.p.meta.name);
        if let Some(about) = subcommand.p.meta.about {
            man_subcommand = man_subcommand.description(about);
        };
        manpage = manpage.subcommand(man_subcommand);
    }
    if let Some(version) = app.p.meta.version {
        manpage = manpage.version(version);
    };

    manpage
}

