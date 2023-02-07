use clap::Parser;

use sequoia_openpgp as openpgp;

use openpgp::Fingerprint;

#[derive(Parser, Debug)]
#[clap(
    name = "export",
    about = "Exports certificates from the local certificate store",
    long_about =
"Exports certificates from the local certificate store

If multiple predicates are specified a certificate is returned if any
of them match.

This does not check the validity of the certificates or their
components (subkeys and User IDs) in anyway.  Before using the
certificates, be sure to validate and authenticate them.
",
    after_help =
"EXAMPLES:

# Exports all certificates
$ sq export > all.pgp

# Exports certificates with a matching User ID packet.  The
# binding signatures are checked, but the User IDs are not
# authenticated.
$ sq export --userid 'Alice <alice@example.org>'

# Exports certificates with a User ID containing the email
# address.  The binding signatures are checked, but the User IDs are
# not authenticated.
$ sq export --email 'alice@example.org'

# Exports certificates with the matching Key ID.
$ sq export --cert 1234567812345678

# Exports certificates that contain a key with the matching Key
# ID.
$ sq export --key 1234567812345678

# Exports certificates that contain a User ID with *either*
# (not both!) email address.
$ sq export --email alice@example.org --email bob@example.org
",
)]
pub struct Command {
    #[clap(
        short = 'B',
        long,
        help = "Emits binary data",
    )]
    pub binary: bool,

    #[clap(
        short,
        long,
        value_name = "FILE",
        help = "Writes to FILE or stdout if omitted"
    )]
    pub output: Option<String>,

    #[clap(
        long = "cert",
        value_name = "FINGERPRINT",
        multiple_occurrences = true,
        help = "Returns certificates with the specified fingerprint",
    )]
    pub cert: Vec<Fingerprint>,

    #[clap(
        long = "key",
        value_name = "FINGERPRINT",
        multiple_occurrences = true,
        help = "Returns certificates where a key has the specified fingerprint",
    )]
    pub key: Vec<Fingerprint>,

    #[clap(
        long = "userid",
        value_name = "USERID",
        multiple_occurrences = true,
        help = "Returns certificates where a UserID matches exactly",
    )]
    pub userid: Vec<String>,

    #[clap(
        long = "email",
        value_name = "EMAIL",
        multiple_occurrences = true,
        help = "Returns certificates where a UserID contains the email address",
    )]
    pub email: Vec<String>,
}
