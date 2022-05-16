use std::{
    collections::HashMap,
    collections::hash_map::Entry,
    fs::File,
    io,
    path::PathBuf,
};
use anyhow::Context;

use sequoia_openpgp as openpgp;
use openpgp::{
    Result,
    armor,
    cert::{
        Cert,
        CertParser,
    },
    Fingerprint,
    KeyHandle,
    packet::{
        UserID,
        UserAttribute,
        Key,
    },
    parse::Parse,
    serialize::Serialize,
};

use crate::{
    Config,
    open_or_stdin,
};

pub fn dispatch(config: Config, m: &clap::ArgMatches) -> Result<()> {
    match m.subcommand() {
        Some(("filter",  m)) => {
            let any_uid_predicates =
                m.is_present("userid")
                || m.is_present("name")
                || m.is_present("email")
                || m.is_present("domain");
            let uid_predicate = |uid: &UserID| {
                let mut keep = false;

                if let Some(userids) = m.values_of("userid") {
                    for userid in userids {
                        keep |= uid.value() == userid.as_bytes();
                    }
                }

                if let Some(names) = m.values_of("name") {
                    for name in names {
                        keep |= uid
                            .name().unwrap_or(None)
                            .map(|n| n == name)
                            .unwrap_or(false);
                    }
                }

                if let Some(emails) = m.values_of("email") {
                    for email in emails {
                        keep |= uid
                            .email().unwrap_or(None)
                            .map(|n| n == email)
                            .unwrap_or(false);
                    }
                }

                if let Some(domains) = m.values_of("domain") {
                    for domain in domains {
                        keep |= uid
                            .email().unwrap_or(None)
                            .map(|n| n.ends_with(&format!("@{}", domain)))
                            .unwrap_or(false);
                    }
                }

                keep
            };

            let any_ua_predicates = false;
            let ua_predicate = |_ua: &UserAttribute| false;

            let any_key_predicates = m.is_present("handle");
            let handles: Vec<KeyHandle> =
                if let Some(handles) = m.values_of("handle") {
                    use std::str::FromStr;
                    handles.into_iter().map(KeyHandle::from_str)
                        .collect::<Result<_>>()?
                } else {
                    Vec::with_capacity(0)
                };
            let key_predicate = |key: &Key<_, _>| {
                let mut keep = false;

                for handle in &handles {
                    keep |= handle.aliases(key.key_handle());
                }

                keep
            };

            let filter_fn = |c: Cert| -> Option<Cert> {
                if ! (any_uid_predicates
                      || any_ua_predicates
                      || any_key_predicates) {
                    // If there are no filters, pass it through.
                    Some(c)
                } else if ! (c.userids().any(|c| uid_predicate(&c))
                             || c.user_attributes().any(|c| ua_predicate(&c))
                             || c.keys().any(|c| key_predicate(c.key()))) {
                    None
                } else if m.is_present("prune-certs") {
                    let c = c
                        .retain_userids(|c| {
                            ! any_uid_predicates || uid_predicate(&c)
                        })
                        .retain_user_attributes(|c| {
                            ! any_ua_predicates || ua_predicate(&c)
                        })
                        .retain_subkeys(|c| {
                            ! any_key_predicates
                                || key_predicate(c.key().role_as_unspecified())
                        });
                    if c.userids().count() == 0
                        && c.user_attributes().count() == 0
                        && c.keys().subkeys().count() == 0
                    {
                        // We stripped all components, omit this cert.
                        None
                    } else {
                        Some(c)
                    }
                } else {
                    Some(c)
                }
            };

            let to_certificate = m.is_present("to-certificate");

            // XXX: Armor type selection is a bit problematic.  If any
            // of the certificates contain a secret key, it would be
            // better to use Kind::SecretKey here.  However, this
            // requires buffering all certs, which has its own
            // problems.
            let mut output =
                config.create_or_stdout_pgp(m.value_of("output"),
                                            m.is_present("binary"),
                                            armor::Kind::PublicKey)?;
            filter(m.values_of("input"), &mut output, filter_fn,
                   to_certificate)?;
            output.finalize()
        },
        Some(("join",  m)) => {
            // XXX: Armor type selection is a bit problematic.  If any
            // of the certificates contain a secret key, it would be
            // better to use Kind::SecretKey here.  However, this
            // requires buffering all certs, which has its own
            // problems.
            let mut output =
                config.create_or_stdout_pgp(m.value_of("output"),
                                            m.is_present("binary"),
                                            armor::Kind::PublicKey)?;
            filter(m.values_of("input"), &mut output, Some, false)?;
            output.finalize()
        },
        Some(("merge",  m)) => {
            let mut output =
                config.create_or_stdout_pgp(m.value_of("output"),
                                            m.is_present("binary"),
                                            armor::Kind::PublicKey)?;
            merge(m.values_of("input"), &mut output)?;
            output.finalize()
        },
        Some(("list",  m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            list(config, &mut input, m.is_present("all-userids"))
        },
        Some(("split",  m)) => {
            let mut input = open_or_stdin(m.value_of("input"))?;
            let prefix =
            // The prefix is either specified explicitly...
                m.value_of("prefix").map(|p| p.to_owned())
                .unwrap_or(
                    // ... or we derive it from the input file...
                    m.value_of("input").and_then(|i| {
                        let p = PathBuf::from(i);
                        // (but only use the filename)
                        p.file_name().map(|f| String::from(f.to_string_lossy()))
                    })
                    // ... or we use a generic prefix...
                        .unwrap_or_else(|| String::from("output"))
                    // ... finally, add a hyphen to the derived prefix.
                        + "-");
            split(&mut input, &prefix, m.is_present("binary"))
        },

        _ => unreachable!(),
    }
}

/// Joins certificates and keyrings into a keyring, applying a filter.
fn filter<F>(inputs: Option<clap::Values>, output: &mut dyn io::Write,
             mut filter: F, to_certificate: bool)
             -> Result<()>
    where F: FnMut(Cert) -> Option<Cert>,
{
    if let Some(inputs) = inputs {
        for name in inputs {
            for cert in CertParser::from_file(name)? {
                let cert = cert.context(
                    format!("Malformed certificate in keyring {:?}", name))?;
                if let Some(cert) = filter(cert) {
                    if to_certificate {
                        cert.serialize(output)?;
                    } else {
                        cert.as_tsk().serialize(output)?;
                    }
                }
            }
        }
    } else {
        for cert in CertParser::from_reader(io::stdin())? {
            let cert = cert.context("Malformed certificate in keyring")?;
            if let Some(cert) = filter(cert) {
                if to_certificate {
                    cert.serialize(output)?;
                } else {
                    cert.as_tsk().serialize(output)?;
                }
            }
        }
    }
    Ok(())
}

/// Lists certs in a keyring.
fn list(config: Config,
        input: &mut (dyn io::Read + Sync + Send),
        list_all_uids: bool)
        -> Result<()>
{
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let cert = cert.context("Malformed certificate in keyring")?;
        let line = format!("{}. {:X}", i, cert.fingerprint());
        let indent = line.chars().map(|_| ' ').collect::<String>();
        print!("{}", line);

        // Try to be more helpful by including a User ID in the
        // listing.  We'd like it to be the primary one.  Use
        // decreasingly strict policies.
        let mut primary_uid = None;

        // First, apply our policy.
        if let Ok(vcert) = cert.with_policy(&config.policy, None) {
            if let Ok(primary) = vcert.primary_userid() {
                println!(" {}", String::from_utf8_lossy(primary.value()));
                primary_uid = Some(primary.value().to_vec());
            }
        }

        // Second, apply the null policy.
        if primary_uid.is_none() {
            let null = openpgp::policy::NullPolicy::new();
            if let Ok(vcert) = cert.with_policy(&null, None) {
                if let Ok(primary) = vcert.primary_userid() {
                    println!(" {}", String::from_utf8_lossy(primary.value()));
                    primary_uid = Some(primary.value().to_vec());
                }
            }
        }

        // As a last resort, pick the first user id.
        if primary_uid.is_none() {
            if let Some(primary) = cert.userids().next() {
                println!(" {}", String::from_utf8_lossy(primary.value()));
                primary_uid = Some(primary.value().to_vec());
            }
        }

        if primary_uid.is_none() {
            // No dice.
            println!();
        }

        if list_all_uids {
            // List all user ids independently of their validity.
            for u in cert.userids() {
                if primary_uid.as_ref()
                    .map(|p| &p[..] == u.value()).unwrap_or(false)
                {
                    // Skip the user id we already printed.
                    continue;
                }

                println!("{} {}", indent,
                         String::from_utf8_lossy(u.value()));
            }
        }
    }
    Ok(())
}

/// Splits a keyring into individual certs.
fn split(input: &mut (dyn io::Read + Sync + Send), prefix: &str, binary: bool)
         -> Result<()> {
    for (i, cert) in CertParser::from_reader(input)?.enumerate() {
        let cert = cert.context("Malformed certificate in keyring")?;
        let filename = format!(
            "{}{}-{:X}",
            prefix,
            i,
            cert.fingerprint());

        // Try to be more helpful by including the first userid in the
        // filename.
        let mut sink = if let Some(f) = cert.userids().next()
            .and_then(|uid| uid.email().unwrap_or(None))
            .and_then(to_filename_fragment)
        {
            let filename_email = format!("{}-{}", filename, f);
            if let Ok(s) = File::create(filename_email) {
                s
            } else {
                // Degrade gracefully in case our sanitization
                // produced an invalid filename on this system.
                File::create(&filename)
                    .context(format!("Writing cert to {:?} failed", filename))?
            }
        } else {
            File::create(&filename)
                .context(format!("Writing cert to {:?} failed", filename))?
        };

        if binary {
            cert.as_tsk().serialize(&mut sink)?;
        } else {
            use sequoia_openpgp::serialize::stream::{Message, Armorer};
            let message = Message::new(sink);
            let mut message = Armorer::new(message)
            // XXX: should detect kind, see above
                .kind(sequoia_openpgp::armor::Kind::PublicKey)
                .build()?;
            cert.as_tsk().serialize(&mut message)?;
            message.finalize()?;
        }
    }
    Ok(())
}

/// Merge multiple keyrings.
fn merge(inputs: Option<clap::Values>, output: &mut dyn io::Write)
             -> Result<()>
{
    let mut certs: HashMap<Fingerprint, Option<Cert>> = HashMap::new();

    if let Some(inputs) = inputs {
        for name in inputs {
            for cert in CertParser::from_file(name)? {
                let cert = cert.context(
                    format!("Malformed certificate in keyring {:?}", name))?;
                match certs.entry(cert.fingerprint()) {
                    e @ Entry::Vacant(_) => {
                        e.or_insert(Some(cert));
                    }
                    Entry::Occupied(mut e) => {
                        let e = e.get_mut();
                        let curr = e.take().unwrap();
                        *e = Some(curr.merge_public_and_secret(cert)
                            .expect("Same certificate"));
                    }
                }
            }
        }
    } else {
        for cert in CertParser::from_reader(io::stdin())? {
            let cert = cert.context("Malformed certificate in keyring")?;
            match certs.entry(cert.fingerprint()) {
                e @ Entry::Vacant(_) => {
                    e.or_insert(Some(cert));
                }
                Entry::Occupied(mut e) => {
                    let e = e.get_mut();
                    let curr = e.take().unwrap();
                    *e = Some(curr.merge_public_and_secret(cert)
                              .expect("Same certificate"));
                }
            }
        }
    }

    let mut fingerprints: Vec<Fingerprint> = certs.keys().cloned().collect();
    fingerprints.sort();

    for fpr in fingerprints.iter() {
        if let Some(Some(cert)) = certs.get(fpr) {
            cert.as_tsk().serialize(output)?;
        }
    }

    Ok(())
}

/// Sanitizes a string to a safe filename fragment.
fn to_filename_fragment<S: AsRef<str>>(s: S) -> Option<String> {
    let mut r = String::with_capacity(s.as_ref().len());

    s.as_ref().chars().filter_map(|c| match c {
        '/' | ':' | '\\' => None,
        c if c.is_ascii_whitespace() => None,
        c if c.is_ascii() => Some(c),
        _ => None,
    }).for_each(|c| r.push(c));

    if !r.is_empty() {
        Some(r)
    } else {
        None
    }
}
