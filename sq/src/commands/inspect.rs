use std::convert::TryFrom;
use std::io::{self, Read};

use serde::Serialize;
use std::collections::HashMap;

use openpgp::types::{
    PublicKeyAlgorithm,
    ReasonForRevocation,
    SignatureType,
};
use sequoia_openpgp as openpgp;
use crate::openpgp::{KeyHandle, Packet, Result};
use crate::openpgp::cert::prelude::*;
use openpgp::packet::{
    Signature,
    key::PublicParts,
    UserID,
    UserAttribute,
};
use crate::openpgp::parse::{Parse, PacketParserResult};
use crate::openpgp::policy::Policy;
use crate::openpgp::packet::key::SecretKeyMaterial;

use super::dump::Convert;

pub fn inspect(m: &clap::ArgMatches, policy: &dyn Policy, output: &mut dyn io::Write)
               -> Result<()> {
    let mut buffer = Buffer::new();

    let print_certifications = m.is_present("certifications");

    let input = m.value_of("input");
    let input_name = input.unwrap_or("-");
    buffer.filename(input_name);

    let mut type_called = false;  // Did we print the type yet?
    let mut encrypted = false;    // Is it an encrypted message?
    let mut packets = Vec::new(); // Accumulator for packets.
    let mut pkesks = Vec::new();  // Accumulator for PKESKs.
    let mut n_skesks = 0;         // Number of SKESKs.
    let mut sigs = Vec::new();    // Accumulator for signatures.
    let mut literal_prefix = Vec::new();

    let mut ppr =
        openpgp::parse::PacketParser::from_reader(crate::open_or_stdin(input)?)?;
    while let PacketParserResult::Some(mut pp) = ppr {
        match pp.packet {
            Packet::PublicKey(_) | Packet::SecretKey(_) => {
                if pp.possible_cert().is_err()
                    && pp.possible_keyring().is_ok()
                {
                    if ! type_called {
                        buffer.openpgp_keyring();
                        buffer.separator();
                        type_called = true;
                    }
                    let pp = openpgp::PacketPile::from(
                        ::std::mem::replace(&mut packets, Vec::new()));
                    let cert = openpgp::Cert::try_from(pp)?;
                    inspect_cert(policy, &mut buffer, &cert,
                                 print_certifications)?;
                }
            },
            Packet::Literal(_) => {
                pp.by_ref().take(40).read_to_end(&mut literal_prefix)?;
            },
            Packet::SEIP(_) | Packet::AED(_) => {
                encrypted = true;
            },
            _ => (),
        }

        let possible_keyring = pp.possible_keyring().is_ok();
        let (packet, ppr_) = pp.recurse()?;
        ppr = ppr_;

        match packet {
            Packet::PKESK(p) => pkesks.push(p),
            Packet::SKESK(_) => n_skesks += 1,
            Packet::Signature(s) => if possible_keyring {
                packets.push(Packet::Signature(s))
            } else {
                sigs.push(s)
            },
            _ => packets.push(packet),
        }
    }

    if let PacketParserResult::EOF(eof) = ppr {
        let is_message = eof.is_message();
        let is_cert = eof.is_cert();
        let is_keyring = eof.is_keyring();

        if is_message.is_ok() {
            match (encrypted, ! sigs.is_empty()) {
                (false, false) => buffer.openpgp_message(),
                (false, true) => buffer.signed_openpgp_message(),
                (true, false) => buffer.encrypted_openpgp_message(),
                (true, true) => buffer.encrypted_signed_openpgp_msg(),
            }
            buffer.separator();
            if n_skesks > 0 {
                buffer.passwords(n_skesks);
            }
            for pkesk in pkesks.iter() {
                buffer.recipient(pkesk.recipient());
            }
            inspect_signatures(&mut buffer, &sigs)?;
            if ! literal_prefix.is_empty() {
                let data = String::from_utf8_lossy(&literal_prefix);
                let suffix = if literal_prefix.len() == 40 { "..." } else { "" };
                buffer.data(&data, suffix);
            }

        } else if is_cert.is_ok() || is_keyring.is_ok() {
            let pp = openpgp::PacketPile::from(packets);
            let cert = openpgp::Cert::try_from(pp)?;
            inspect_cert(policy, &mut buffer, &cert,
                         print_certifications)?;
        } else if packets.is_empty() && ! sigs.is_empty() {
            if sigs.len() == 1 {
                buffer.detached_signature();
            } else {
                buffer.detached_signatures();
            }
            buffer.separator();
            inspect_signatures(&mut buffer, &sigs)?;
        } else if packets.is_empty() {
            buffer.no_openpgp_data();
        } else {
            buffer.unknown_packet_sequence(is_message,
                                           is_cert,
                                           is_keyring,
                                           input_name);

        }
    } else {
        unreachable!()
    }

    if let Some("json") = m.value_of("output-format") {
        buffer.write_json(output)?;
    } else {
        buffer.write_human(output)?;
    }
    Ok(())
}

fn inspect_cert(policy: &dyn Policy,
                buffer: &mut Buffer,
                cert: &openpgp::Cert,
                print_certifications: bool) -> Result<()> {
    if cert.is_tsk() {
        buffer.transferable_secret_key();
    } else {
        buffer.openpgp_certificate();
    }
    buffer.separator();
    buffer.fingerprint(cert.fingerprint());
    inspect_revocation(buffer, cert.revocation_status(policy, None))?;
    inspect_key(policy, buffer, cert.keys().next().unwrap(),
                print_certifications)?;
    buffer.separator();

    for vka in cert.keys().subkeys().with_policy(policy, None) {
        buffer.subkey(vka.key().fingerprint());
        inspect_revocation(buffer, vka.revocation_status())?;
        inspect_key(policy, buffer, vka.into_key_amalgamation().into(),
                    print_certifications)?;
        buffer.separator();
    }

    fn print_error_chain(buffer: &mut Buffer, err: &anyhow::Error)
                         -> Result<()> {
        buffer.invalid_certificate(err);
        for cause in err.chain().skip(1) {
            buffer.invalid_certificate_cause(cause);
        }
        Ok(())
    }

    for uidb in cert.userids() {
        buffer.userid(uidb.userid());
        inspect_revocation(buffer, uidb.revocation_status(policy, None))?;
        match uidb.binding_signature(policy, None) {
            Ok(sig) => if let Err(e) =
                sig.signature_alive(None, std::time::Duration::new(0, 0))
            {
                print_error_chain(buffer, &e)?;
            }
            Err(e) => print_error_chain(buffer, &e)?,
        }
        inspect_certifications(buffer,
                               uidb.certifications(),
                               print_certifications)?;
        buffer.separator();
    }

    for uab in cert.user_attributes() {
        buffer.user_attribute(uab.user_attribute());
        inspect_revocation(buffer, uab.revocation_status(policy, None))?;
        match uab.binding_signature(policy, None) {
            Ok(sig) => if let Err(e) =
                sig.signature_alive(None, std::time::Duration::new(0, 0))
            {
                print_error_chain(buffer, &e)?;
            }
            Err(e) => print_error_chain(buffer, &e)?,
        }
        inspect_certifications(buffer,
                               uab.certifications(),
                               print_certifications)?;
        buffer.separator();
    }

    for ub in cert.unknowns() {
        buffer.unknown(ub.unknown());
        match ub.binding_signature(policy, None) {
            Ok(sig) => if let Err(e) =
                sig.signature_alive(None, std::time::Duration::new(0, 0))
            {
                print_error_chain(buffer, &e)?;
            }
            Err(e) => print_error_chain(buffer, &e)?,
        }
        inspect_certifications(buffer,
                               ub.certifications(),
                               print_certifications)?;
        buffer.separator();
    }

    for bad in cert.bad_signatures() {
        buffer.bad_signature(bad);
    }

    Ok(())
}

fn inspect_key(policy: &dyn Policy,
               buffer: &mut Buffer,
               ka: ErasedKeyAmalgamation<PublicParts>,
               print_certifications: bool)
        -> Result<()>
{
    let key = ka.key();
    let bundle = ka.bundle();
    let vka = match ka.with_policy(policy, None) {
        Ok(vka) => {
            if let Err(e) = vka.alive() {
                buffer.invalid_key(&e);
            }
            Some(vka)
        },
        Err(e) => {
            buffer.invalid_key(&e);
            None
        },
    };

    buffer.pk_algo(key.pk_algo());
    if let Some(bits) = key.mpis().bits() {
        buffer.pk_bits(bits);
    }
    if let Some(secret) = key.optional_secret() {
        if let SecretKeyMaterial::Unencrypted(_) = secret {
            buffer.unencrypted_secret_key();
        } else {
            buffer.encrypted_secret_key();
        }
    }
    buffer.creation_time(key.creation_time().convert().to_string());
    if let Some(vka) = vka {
        if let Some(expires) = vka.key_validity_period() {
            let expiration_time = key.creation_time() + expires;
            buffer.expiration_time(format!("{} (creation time + {})",
                                           expiration_time.convert(),
                                           expires.convert()));
        }

        if let Some(flags) = vka.key_flags().and_then(inspect_key_flags) {
            buffer.key_flags(flags);
        }
    }
    inspect_certifications(buffer, bundle.certifications().iter(),
                           print_certifications)?;

    Ok(())
}

fn inspect_revocation(buffer: &mut Buffer,
                      revoked: openpgp::types::RevocationStatus)
                      -> Result<()> {
    use crate::openpgp::types::RevocationStatus::*;
    fn print_reasons(buffer: &mut Buffer, sigs: &[&Signature])
                     -> Result<()> {
        for sig in sigs {
            if let Some((r, _)) = sig.reason_for_revocation() {
                buffer.revocation_reason(r);
            } else {
                buffer.unknown_revocation_reason();
            }
        }
        Ok(())
    }
    match revoked {
        Revoked(sigs) => {
            buffer.revoked();
            print_reasons(buffer, &sigs)?;
        },
        CouldBe(sigs) => {
            buffer.maybe_revoked();
            print_reasons(buffer, &sigs)?;
        },
        NotAsFarAsWeKnow => (),
    }

    Ok(())
}

fn inspect_key_flags(flags: openpgp::types::KeyFlags) -> Option<String> {
    let mut capabilities = Vec::new();
    if flags.for_certification() {
        capabilities.push("certification")
    }
    if flags.for_signing() {
        capabilities.push("signing")
    }
    if flags.for_authentication() {
        capabilities.push("authentication")
    }
    if flags.for_transport_encryption() {
        capabilities.push("transport encryption")
    }
    if flags.for_storage_encryption() {
        capabilities.push("data-at-rest encryption")
    }
    if flags.is_group_key() {
        capabilities.push("group key")
    }
    if flags.is_split_key() {
        capabilities.push("split key")
    }

    if !capabilities.is_empty() {
        Some(capabilities.join(", "))
    } else {
        None
    }
}

fn inspect_signatures(buffer: &mut Buffer,
                      sigs: &[openpgp::packet::Signature]) -> Result<()> {
    use crate::openpgp::types::SignatureType::*;
    for sig in sigs {
        match sig.typ() {
            Binary | Text => (),
            signature_type @ _ =>
                buffer.signature_type(signature_type),
        }

        let mut fps: Vec<_> = sig.issuer_fingerprints().collect();
        fps.sort();
        fps.dedup();
        let fps: Vec<KeyHandle> = fps.into_iter().map(|fp| fp.into()).collect();
        for fp in fps.iter() {
            buffer.alleged_signer_by_key_handle(fp);
        }
        let mut keyids: Vec<_> = sig.issuers().collect();
        keyids.sort();
        keyids.dedup();
        for keyid in keyids {
            if ! fps.iter().any(|fp| fp.aliases(&keyid.into())) {
                buffer.alleged_signer_by_key_id(keyid);
            }
        }
    }
    if ! sigs.is_empty() {
        buffer.unverified_signers();
    }

    Ok(())
}

fn inspect_certifications<'a, A>(buffer: &mut Buffer,
                          certs: A,
                          print_certifications: bool) -> Result<()> where
        A: std::iter::Iterator<Item=&'a openpgp::packet::Signature> {
    if print_certifications {
        let mut emit_warning = false;
        for sig in certs {
            emit_warning = true;
            let mut fps: Vec<_> = sig.issuer_fingerprints().collect();
            fps.sort();
            fps.dedup();
            let fps: Vec<KeyHandle> = fps.into_iter().map(|fp| fp.into()).collect();
            for fp in fps.iter() {
                buffer.alleged_certifier_by_key_handle(fp);
            }
            let mut keyids: Vec<_> = sig.issuers().collect();
            keyids.sort();
            keyids.dedup();
            for keyid in keyids {
                if ! fps.iter().any(|fp| fp.aliases(&keyid.into())) {
                    buffer.alleged_certifier_by_key_id(keyid);
                }
            }
        }
        if emit_warning {
            buffer.not_certified();
        }
    } else {
        let count = certs.count();
        if count > 0 {
            buffer.num_certification(count);
        }
    }

    Ok(())
}

// An atomic bit of information for output.
#[derive(Serialize)]
enum Atom {
    // A key/value pair.
    KeyValue(String, String),

    // A note.
    Note(String),

    // A separator between groups of atoms that belong together.
    Separator,
}

impl Atom {
    // Creates a key/value pair.
    fn pair(a: &str, b: String) -> Self {
        Self::KeyValue(a.to_string(), b)
    }

    // Creates a note: a value without a key.
    fn note(txt: &str) -> Self {
        Self::Note(txt.to_string())
    }

    // Creates a separator.
    fn separator() -> Self {
        Self::Separator
    }
}

// A sequence of output atoms.
//
// The sequence can be written out in different formats. The logic to
// parse a sequence of OpenPGP packets appends atoms to the output
// buffer and the buffer can then be formatted in various ways for
// output.
#[derive(Serialize)]
struct Buffer {
    atoms: Vec<Atom>,
}

impl Buffer {
    // Creates a new output buffer.
    fn new() -> Self {
        Self { atoms: vec![] }
    }

    // Writes output buffer as human-readable text.
    fn write_human(&self, output: &mut dyn io::Write) -> Result<()> {
        for atom in self.atoms.iter() {
            match atom {
                Atom::KeyValue(k, v) =>
                    write!(output, "{}: {}\n", k, v)?,
                Atom::Note(note) => write!(output, "{}\n", note)?,
                Atom::Separator => write!(output, "\n")?,
            }
        }
        Ok(())
    }

    // Writes output buffer as JSON.
    //
    // Splits the output buffer into groups, based on separators. Each
    // group results in an object (map), and the sequence of groups is
    // a list.
    fn write_json(&self, output: &mut dyn io::Write) -> Result<()> {
        let note = "Note".to_string();
        let mut maps = vec![];
        for v in self.split_groups() {
            let mut map = HashMap::new();
            for atom in v.iter() {
                match atom {
                    Atom::KeyValue(k, v) => {
                        map.insert(k, v);
                    },
                    Atom::Note(text) => {
                        map.insert(&note, text);
                    },
                    Atom::Separator => (),
                }
            }
            maps.push(map);
        }

        write!(output, "{}", serde_json::to_string(&maps)?)?;
        serde_json::to_writer(output, &maps)?;
        Ok(())
    }

    // Splits output buffer at separators into a groups of atoms that
    // belong together.
    fn split_groups(&self) -> Vec<Vec<&Atom>> {
        let mut vecs = vec![];
        let mut cur = vec![];

        for atom in self.atoms.iter() {
            if let Atom::Separator = atom {
                vecs.push(cur.clone());
                cur.clear();
            } else {
                cur.push(atom.clone());
            }
        }

        if ! cur.is_empty() {
            vecs.push(cur);
        }

        vecs
    }

    // The rest of the functions append atoms of different kinds to
    // the output buffer.

    fn alleged_certifier_by_key_handle(&mut self, who: &KeyHandle) {
        self.atoms.push(
            Atom::pair("Alleged certifier", format!("{}", who)));
    }

    fn alleged_certifier_by_key_id(&mut self, who: &openpgp::KeyID) {
        self.atoms.push(
            Atom::pair("Alleged certifier", format!("{}", who)));
    }

    fn alleged_signer_by_key_handle(&mut self, who: &KeyHandle) {
        self.atoms.push(
            Atom::pair("Alleged signer", format!("{}", who)));
    }

    fn alleged_signer_by_key_id(&mut self, who: &openpgp::KeyID) {
        self.atoms.push(
            Atom::pair("Alleged signer", format!("{}", who)));
    }

    fn bad_signature(&mut self, bad: &openpgp::packet::Signature) {
        self.atoms.push(
            Atom::pair("Bad signature", format!("{:?}", bad)));
    }

    fn creation_time(&mut self, time: String) {
        self.atoms.push(
            Atom::pair("Creation time", format!("{}", time)));
    }

    fn data(&mut self, data: &str, suffix: &str) {
        self.atoms.push(
            Atom::pair("Data", format!("{}{}", data, suffix)));
    }

    fn detached_signature(&mut self) {
        self.atoms.push(
            Atom::pair("File type", "Detached signature".to_string()));
    }

    fn detached_signatures(&mut self) {
        self.atoms.push(
            Atom::pair("File type", "Detached signatures".to_string()));
    }

    fn encrypted_openpgp_message(&mut self) {
        self.atoms.push(
            Atom::pair("File type",
                       "Encrypted OpenPGP Message".to_string()));
    }

    fn encrypted_secret_key(&mut self) {
        self.atoms.push(
            Atom::pair("Secret key", "Encrypted".to_string()));
    }

    fn encrypted_signed_openpgp_msg(&mut self) {
        let atom =Atom::pair(
            "File type",
            "Encrypted and signed OpenPGP Message"
                .to_string());
        self.atoms.push(atom);
    }

    fn expiration_time(&mut self, time: String) {
        self.atoms.push(
            Atom::pair("Expiration time", format!("{}", time)));
    }

    fn filename(&mut self, filename: &str) {
        self.atoms.push(Atom::pair("Filename", filename.to_string()));
    }

    fn fingerprint(&mut self, fp: openpgp::Fingerprint) {
        self.atoms.push(Atom::pair("Fingerprint", format!("{}", fp)));
    }

    fn invalid_certificate(&mut self, err: &anyhow::Error) {
        self.atoms.push(Atom::pair("Invalid", format!("{}", err)));
    }

    fn invalid_certificate_cause(&mut self,
                                 cause: &dyn std::error::Error) {
        self.atoms.push(Atom::pair("because", format!("{}", cause)));
    }

    fn invalid_key(&mut self, error: &anyhow::Error) {
        self.atoms.push(Atom::pair("Invalid", format!("{}", error)));
    }

    fn key_flags(&mut self, flags: String) {
        self.atoms.push(Atom::pair("Key flags", flags.clone()));
    }

    fn maybe_revoked(&mut self) {
        self.atoms.push(Atom::note("Possibly revoked"));
    }

    fn no_openpgp_data(&mut self) {
        self.atoms.push(Atom::note("No OpenPGP data"));
    }

    fn not_certified(&mut self) {
        self.atoms.push(
            Atom::note("Certifications have NOT been verified"));
    }

    fn num_certification(&mut self, count: usize) {
        self.atoms.push(
            Atom::pair("Certifications", format!("{}", count)));
    }

    fn openpgp_certificate(&mut self) {
        self.atoms.push(
            Atom::pair("File type", "OpenPGP Certificate".to_string()));
    }

    fn openpgp_keyring(&mut self) {
        self.atoms.push(
            Atom::pair("File type", "OpenPGP keyring".to_string()));
    }

    fn openpgp_message(&mut self) {
        self.atoms.push(
            Atom::pair("File type", "OpenPGP Message".to_string()));
    }

    fn passwords(&mut self, n: usize) {
        self.atoms.push(Atom::pair("Passwords", format!("{}", n)));
    }

    fn pk_algo(&mut self, algo: PublicKeyAlgorithm) {
        self.atoms.push(
            Atom::pair("Public key algorithm", format!("{}", algo)));
    }

    fn pk_bits(&mut self, bits: usize) {
        self.atoms.push(
            Atom::pair("Public key size", format!("{}", bits)));
    }

    fn recipient(&mut self, who: &openpgp::KeyID) {
        self.atoms.push(Atom::pair("Recipient", format!("{}", who)));
    }

    fn revocation_reason(&mut self, reason: ReasonForRevocation) {
        self.atoms.push(
            Atom::pair("Revocation reason", format!("{}", reason)));
    }

    fn revoked(&mut self) {
        self.atoms.push(Atom::note("Revoked"));
    }

    fn separator(&mut self) {
        self.atoms.push(Atom::separator());
    }

    fn signature_type(&mut self, typ: SignatureType) {
        self.atoms.push(Atom::pair("Kind", format!("{}", typ)));
    }

    fn signed_openpgp_message(&mut self) {
        self.atoms.push(
            Atom::pair("File type",
                       "Signed OpenPGP Message".to_string()));
    }

    fn subkey(&mut self, fp: openpgp::Fingerprint) {
        self.atoms.push(
            Atom::pair("Subkey fingerprint", format!("{}", fp)));
    }

    fn transferable_secret_key(&mut self) {
        self.atoms.push(
            Atom::pair("File type",
                       "Transferable Secret Key".to_string()));
    }

    fn unencrypted_secret_key(&mut self) {
        self.atoms.push(
            Atom::pair("Secret key", "Unencrypted".to_string()));
    }

    fn unknown_packet_sequence(
        &mut self,
        msg: std::result::Result<(), anyhow::Error>,
        cert: std::result::Result<(), anyhow::Error>,
        keyring: std::result::Result<(), anyhow::Error>,
        input_name: &str)
    {
        let msg = msg.unwrap_err();
        let cert = cert.unwrap_err();
        let keyring = keyring.unwrap_err();

        self.atoms.push(
            Atom::note("Unknown sequence of OpenPGP packets"));
        self.atoms.push(
            Atom::pair("Message", format!("{}", msg)));
        self.atoms.push(
            Atom::pair("Ceritifacte", format!("{}", cert)));
        self.atoms.push(
            Atom::pair("Keyring", format!("{}", keyring)));
        self.atoms.push(
            Atom::pair("Input name", format!("{}", input_name)));

    }

    fn unknown(&mut self, unknown: &openpgp::packet::Unknown) {
        self.atoms.push(
            Atom::pair("Unknown component", format!("{:?}", unknown)));
    }

    fn unknown_revocation_reason(&mut self) {
        self.atoms.push(Atom::note("No reason specified"));
    }

    fn unverified_signers(&mut self) {
        self.atoms.push(
            Atom::note("Signatures have NOT been verified"));
    }

    fn userid(&mut self, userid: &UserID) {
        self.atoms.push(
            Atom::pair("User ID", format!("{}", userid)));
    }

    fn user_attribute(&mut self, attr: &UserAttribute) {
        self.atoms.push(
            Atom::pair("User attribute", format!("{:?}", attr)));
    }
}
