/// Command-line parser for sqv.

use clap::{App, Arg, AppSettings};

// The argument parser.
pub fn build() -> App<'static, 'static> {
    configure(App::new("sqv"))
}

pub fn configure(app: App<'static, 'static>) -> App<'static, 'static> {
    app
        .version(env!("CARGO_PKG_VERSION"))
        .about("sqv is a command-line OpenPGP signature verification tool.")
        .setting(AppSettings::ArgRequiredElseHelp)
        .arg(Arg::with_name("keyring").value_name("FILE")
             .help("A keyring.  Can be given multiple times.")
             .long("keyring")
             .required(true)
             .number_of_values(1)
             .multiple(true))
        .arg(Arg::with_name("signatures").value_name("N")
             .help("The number of valid signatures to return success.  Default: 1")
             .long("signatures")
             .short("n"))
        .arg(Arg::with_name("not-before").value_name("TIMESTAMP")
             .help("Consider signatures created before TIMESTAMP as invalid.  \
                    If a date is given, 00:00:00 is used for the time. \
                    \n[default: no constraint]")
             .long("not-before"))
        .arg(Arg::with_name("not-after").value_name("TIMESTAMP")
             .help("Consider signatures created after TIMESTAMP as invalid.  \
                    If a date is given, 23:59:59 is used for the time. \
                    \n[default: now]")
             .long("not-after"))
        .arg(Arg::with_name("sig-file").value_name("SIG-FILE")
             .help("File containing the detached signature.")
             .required(true))
        .arg(Arg::with_name("file").value_name("FILE")
             .help("File to verify.")
             .required(true))
        .arg(Arg::with_name("verbose")
             .help("Be verbose.")
             .long("verbose")
             .short("v"))
        .after_help(
            "TIMESTAMPs must be given in ISO 8601 format \
             (e.g. '2017-03-04T13:25:35Z', '2017-03-04T13:25', \
             '20170304T1325+0830', '2017-03-04', '2017031', ...). \
             If no timezone is specified, UTC is assumed.")
}
