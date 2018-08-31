use failure::{self, ResultExt};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read, Write};
use time;
use rpassword;

extern crate openpgp;
use openpgp::constants::DataFormat;
use openpgp::{Packet, Key, TPK, KeyID, SecretKey, Signature, Result};
use openpgp::parse::PacketParserResult;
use openpgp::subpacket::{Subpacket, SubpacketValue};
use openpgp::parse::stream::{
    Verifier, VerificationResult, VerificationHelper,
};
use openpgp::serialize::stream::{
    wrap, Signer, LiteralWriter, Encryptor, EncryptionMode,
};
extern crate sequoia_store as store;

// Indent packets according to their recursion level.
const INDENT: &'static str
    // 64 spaces = max recursion depth (16) * 4 spaces
    = "                                                                ";

const TIMEFMT: &'static str = "%Y-%m-%dT%H:%M";

pub fn decrypt(input: &mut io::Read, output: &mut io::Write,
               secrets: Vec<TPK>, dump: bool, map: bool)
           -> Result<()> {
    let mut keys: HashMap<KeyID, Key> = HashMap::new();
    for tsk in secrets {
        let can_encrypt = |key: &Key, sig: &Signature| -> bool {
            (sig.key_flags().can_encrypt_at_rest()
             || sig.key_flags().can_encrypt_for_transport())
            // Check expiry.
                && sig.signature_alive()
                && sig.key_alive(key)
        };

        if tsk.primary_key_signature()
            .map(|sig| can_encrypt(tsk.primary(), sig))
            .unwrap_or(false)
        {
            keys.insert(tsk.fingerprint().to_keyid(), tsk.primary().clone());
        }

        for skb in tsk.subkeys() {
            let key = skb.subkey();
            if can_encrypt(key, skb.binding_signature()) {
                keys.insert(key.fingerprint().to_keyid(), key.clone());
            }
        }
    }

    let mut pkesks: Vec<openpgp::PKESK> = Vec::new();
    let mut skesks: Vec<openpgp::SKESK> = Vec::new();
    let mut ppr
        = openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(map).finalize()?;

    while let PacketParserResult::Some(mut pp) = ppr {
        if ! pp.possible_message() {
            return Err(failure::err_msg("Malformed OpenPGP message"));
        }

        if dump || map {
            dump_packet(&mut io::stderr(),
                        &INDENT[0..4 * pp.recursion_depth as usize],
                        false,
                        &pp.packet)?;
            eprintln!();
        }

        if let Some(ref map) = pp.map {
            let mut hd = HexDumper::new();
            for (field, bytes) in map.iter() {
                hd.write(&mut io::stderr(), bytes, field)?;
            }
            eprintln!();
        }

        match pp.packet {
            Packet::SEIP(_) => {
                let mut decrypted = false;
                for pkesk in pkesks.iter() {
                    if let Some(tsk) = keys.get(pkesk.recipient()) {
                        // XXX: Deal with encrypted keys.
                        if let Some(SecretKey::Unencrypted{ref mpis}) =
                            tsk.secret()
                        {
                            if let Ok((algo, key)) = pkesk.decrypt(tsk, mpis) {
	                        let r = pp.decrypt(algo, &key[..]);
                                if r.is_ok() {
                                    decrypted = true;
                                    break;
                                }
                            }
                        }
                    }
                }
                if ! decrypted && ! skesks.is_empty() {
                    let pass = rpassword::prompt_password_stderr(
                        "Enter password to decrypt message: ")?
                    .into_bytes();

                    for skesk in skesks.iter() {
                        let (algo, key) = skesk.decrypt(&pass)?;

	                let r = pp.decrypt(algo, &key[..]);
                        if r.is_ok() {
                            break;
                        }
                    }
                }
            },
            Packet::Literal(_) => {
                io::copy(&mut pp, output)?;
            },
            _ => (),
        }

        let ((packet, _), (ppr_tmp, _)) = pp.recurse()?;
        ppr = ppr_tmp;

        match packet {
            Packet::PKESK(pkesk) => pkesks.push(pkesk),
            Packet::SKESK(skesk) => skesks.push(skesk),
            _ => (),
        }
    }
    if let PacketParserResult::EOF(eof) = ppr {
        if eof.is_message() {
            Ok(())
        } else {
            Err(failure::err_msg("Malformed OpenPGP message"))
        }
    } else {
        unreachable!()
    }
}

pub fn encrypt(store: &mut store::Store,
               input: &mut io::Read, output: &mut io::Write,
               npasswords: usize, recipients: Vec<&str>,
               mut tpks: Vec<openpgp::TPK>)
               -> Result<()> {
    for r in recipients {
        tpks.push(store.lookup(r).context("No such key found")?.tpk()?);
    }
    let mut passwords = Vec::with_capacity(npasswords);
    for n in 0..npasswords {
        let nprompt = format!("Enter password {}: ", n + 1);
        passwords.push(rpassword::prompt_password_stderr(
            if npasswords > 1 {
                &nprompt
            } else {
                "Enter password: "
            })?);
    }

    // Build a vector of references to hand to Encryptor.
    let recipients: Vec<&openpgp::TPK> = tpks.iter().collect();
    let passwords_: Vec<&[u8]> =
        passwords.iter().map(|p| p.as_bytes()).collect();

    // We want to encrypt a literal data packet.
    let encryptor = Encryptor::new(wrap(output),
                                   &passwords_,
                                   &recipients,
                                   EncryptionMode::AtRest)
        .context("Failed to create encryptor")?;
    let mut literal_writer = LiteralWriter::new(encryptor, DataFormat::Binary,
                                                None, None)
        .context("Failed to create literal writer")?;

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(input, &mut literal_writer)
        .context("Failed to encrypt")?;

    Ok(())
}

pub fn sign(input: &mut io::Read, output: &mut io::Write,
            secrets: Vec<openpgp::TPK>, detached: bool)
            -> Result<()> {
    let sink = wrap(output);
    // Build a vector of references to hand to Signer.
    let keys: Vec<&openpgp::TPK> = secrets.iter().collect();
    let signer = if detached {
        Signer::detached(sink, &keys)
    } else {
        Signer::new(sink, &keys)
    }.context("Failed to create signer")?;

    let mut writer = if detached {
        // Detached signatures do not need a literal data packet, just
        // hash the data as is.
        signer
    } else {
        // We want to wrap the data in a literal data packet.
        LiteralWriter::new(signer, DataFormat::Binary, None, None)
            .context("Failed to create literal writer")?
    };

    // Finally, copy stdin to our writer stack to encrypt the data.
    io::copy(input, &mut writer)
        .context("Failed to sign")?;

    writer.finalize()
        .context("Failed to sign")?;
    Ok(())
}

struct VHelper<'a> {
    store: &'a mut store::Store,
    tpks: Option<Vec<TPK>>,
    labels: HashMap<KeyID, String>,
    good: usize,
    unknown: usize,
    bad: usize,
    error: Option<failure::Error>,
}

impl<'a> VHelper<'a> {
    fn new(store: &'a mut store::Store, tpks: Vec<TPK>) -> Self {
        VHelper {
            store: store,
            tpks: Some(tpks),
            labels: HashMap::new(),
            good: 0,
            unknown: 0,
            bad: 0,
            error: None,
        }
    }

    fn get_error(&mut self) -> Result<()> {
        if let Some(e) = self.error.take() {
            Err(e)
        } else {
            Ok(())
        }
    }

    fn print_status(&self) {
        eprintln!("{} good signatures, {} bad signatures, {} not checked.",
                  self.good, self.bad, self.unknown);
    }

    fn success(&self) -> bool {
        self.good > 0 && self.bad == 0
    }
}

impl<'a> VerificationHelper for VHelper<'a> {
    fn get_public_keys(&mut self, ids: &[KeyID]) -> Result<Vec<TPK>> {
        let mut tpks = self.tpks.take().unwrap();
        let seen: HashSet<_> = tpks.iter()
            .map(|tpk| tpk.fingerprint().to_keyid()).collect();

        // Try to get missing TPKs from the store.
        for id in ids.iter().filter(|i| !seen.contains(i)) {
            let _ =
                self.store.lookup_by_keyid(id)
                .and_then(|binding| {
                    self.labels.insert(id.clone(), binding.label()?);
                    binding.tpk()
                })
                .and_then(|tpk| {
                    tpks.push(tpk);
                    Ok(())
                });
        }
        Ok(tpks)
    }

    fn result(&mut self, result: VerificationResult) -> Result<()> {
        use self::VerificationResult::*;
        match result {
            Good(sig) => {
                let issuer = sig.get_issuer().unwrap();
                let issuer_str = format!("{}", issuer);
                eprintln!("Good signature from {}",
                          self.labels.get(&issuer).unwrap_or(&issuer_str));
                self.good += 1;
            },
            Unknown(sig) => {
                eprintln!("No key to check signature from {}",
                          sig.get_issuer().unwrap());
                self.unknown += 1;
            },
            Bad(sig) => {
                if let Some(issuer) = sig.get_issuer() {
                    let issuer_str = format!("{}", issuer);
                    eprintln!("Bad signature from {}",
                              self.labels.get(&issuer).unwrap_or(&issuer_str));
                } else {
                    eprintln!("Bad signature without issuer information");
                }
                self.bad += 1;
            },
        }
        Ok(())
    }

    fn error(&mut self, error: failure::Error) {
        self.error = Some(error);
    }
}

pub fn verify(store: &mut store::Store,
              input: &mut io::Read, output: &mut io::Write,
              tpks: Vec<TPK>)
              -> Result<()> {
    let helper = VHelper::new(store, tpks);
    let mut verifier = Verifier::from_reader(input, helper)?;

    if verifier.helper_ref().success() {
        if let Err(e) = io::copy(&mut verifier, output) {
            verifier.helper_mut().get_error()?;
            Err(e)?;
        }
    }

    let helper = verifier.into_helper();
    helper.print_status();
    if helper.success() {
        Ok(())
    } else {
        Err(failure::err_msg("Verification failed"))
    }
}

pub fn dump(input: &mut io::Read, output: &mut io::Write, mpis: bool, hex: bool)
        -> Result<()> {
    let mut ppr
        = openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(hex).finalize()?;

    while let PacketParserResult::Some(mut pp) = ppr {
        let i = &INDENT[0..4 * pp.recursion_depth as usize];
        dump_packet(output, i, mpis, &pp.packet)?;
        writeln!(output)?;
        if let Some(ref map) = pp.map {
            let mut hd = HexDumper::new();
            for (field, bytes) in map.iter() {
                hd.write(output, bytes, field)?;
            }
            writeln!(output)?;
        } else {
            match pp.packet {
                Packet::Literal(_) => {
                    let mut prefix = vec![0; 40];
                    let n = pp.read(&mut prefix)?;
                    writeln!(output, "{}  Content: {:?}{}", i,
                             String::from_utf8_lossy(&prefix[..n]),
                             if n == prefix.len() { "..." } else { "" })?;
                },
                _ => (),
            }
        }

        let (_, (ppr_, _)) = pp.recurse()?;
        ppr = ppr_;
    }
    Ok(())
}

fn dump_packet(output: &mut io::Write, i: &str, mpis: bool, p: &Packet) -> Result<()> {
    use self::openpgp::Packet::*;
    match p {
        Unknown(ref u) => {
            writeln!(output, "{}Unknown Packet", i)?;
            writeln!(output, "{}  Tag: {}", i, u.tag())?;
        },

        Signature(ref s) => {
            writeln!(output, "{}Signature Packet", i)?;
            writeln!(output, "{}  Version: {}", i, s.version())?;
            writeln!(output, "{}  Type: {}", i, s.sigtype())?;
            writeln!(output, "{}  Pk algo: {}", i, s.pk_algo())?;
            writeln!(output, "{}  Hash algo: {}", i, s.hash_algo())?;
            if s.hashed_area().iter().count() > 0 {
                writeln!(output, "{}  Hashed area:", i)?;
                for (_, _, pkt) in s.hashed_area().iter() {
                    dump_subpacket(output, i, mpis, pkt)?;
                }
            }
            if s.unhashed_area().iter().count() > 0 {
                writeln!(output, "{}  Unhashed area:", i)?;
                for (_, _, pkt) in s.unhashed_area().iter() {
                    dump_subpacket(output, i, mpis, pkt)?;
                }
            }
            writeln!(output, "{}  Hash prefix: {}", i,
                     to_hex(s.hash_prefix(), false))?;
            if mpis {
                writeln!(output, "{}  MPIs: {:?}", i, s.mpis())?;
            }
        },

        OnePassSig(ref o) => {
            writeln!(output, "{}One-Pass Signature Packet", i)?;
            writeln!(output, "{}  Version: {}", i, o.version())?;
            writeln!(output, "{}  Type: {}", i, o.sigtype())?;
            writeln!(output, "{}  Pk algo: {}", i, o.pk_algo())?;
            writeln!(output, "{}  Hash algo: {}", i, o.hash_algo())?;
            writeln!(output, "{}  Issuer: {}", i, o.issuer())?;
            writeln!(output, "{}  Last: {}", i, o.last())?;
        },

        PublicKey(ref k) | PublicSubkey(ref k)
            | SecretKey(ref k) | SecretSubkey(ref k) =>
        {
            writeln!(output, "{}{}", i, p.tag())?;
            writeln!(output, "{}  Version: {}", i, k.version())?;
            writeln!(output, "{}  Creation time: {}", i,
                     time::strftime(TIMEFMT, k.creation_time()).unwrap())?;
            writeln!(output, "{}  Pk algo: {}", i, k.pk_algo())?;
            if mpis {
                writeln!(output, "{}  MPIs: {:?}", i, k.mpis())?;
                if let Some(secrets) = k.secret() {
                    writeln!(output, "{}  Secrets: {:?}", i, secrets)?;
                }
            }
        },

        UserID(ref u) => {
            writeln!(output, "{}User ID Packet", i)?;
            writeln!(output, "{}  Value: {}", i,
                     String::from_utf8_lossy(u.userid()))?;
        },

        UserAttribute(ref u) => {
            writeln!(output, "{}User Attribute Packet", i)?;
            writeln!(output, "{}  Value: {} bytes", i,
                     u.user_attribute().len())?;
        },

        Literal(ref l) => {
            writeln!(output, "{}Literal Data Packet", i)?;
            writeln!(output, "{}  Format: {}", i, l.format())?;
            if let Some(filename) = l.filename() {
                writeln!(output, "{}  Filename: {}", i,
                         String::from_utf8_lossy(filename))?;
            }
            if let Some(timestamp) = l.date() {
                writeln!(output, "{}  Timestamp: {}", i,
                         time::strftime(TIMEFMT, timestamp).unwrap())?;
            }
        },

        CompressedData(ref c) => {
            writeln!(output, "{}Compressed Data Packet", i)?;
            writeln!(output, "{}  Algorithm: {}", i, c.algorithm())?;
        },

        PKESK(ref p) => {
            writeln!(output,
                     "{}Public-key Encrypted Session Key Packet", i)?;
            writeln!(output, "{}  Version: {}", i, p.version())?;
            writeln!(output, "{}  Recipient: {}", i, p.recipient())?;
            writeln!(output, "{}  Pk algo: {}", i, p.pk_algo())?;
            if mpis {
                writeln!(output, "{}  ESK: {:?}", i, p.esk())?;
            }
        },

        SKESK(ref s) => {
            writeln!(output,
                     "{}Symmetric-key Encrypted Session Key Packet", i)?;
            writeln!(output, "{}  Version: {}", i, s.version())?;
            writeln!(output, "{}  Cipher: {}", i, s.symmetric_algo())?;
            writeln!(output, "{}  S2K: {:?}", i, s.s2k())?;
            writeln!(output, "{}  ESK: {:?}", i, s.esk())?;
        },

        SEIP(ref s) => {
            writeln!(output,
                     "{}Encrypted and Integrity Protected Data Packet", i)?;
            writeln!(output, "{}  Version: {}", i, s.version())?;
        },

        MDC(ref m) => {
            writeln!(output, "{}Modification Detection Code Packet", i)?;
            writeln!(output, "{}  Hash: {}", i, to_hex(m.hash(), false))?;
        },
    }

    Ok(())
}

fn dump_subpacket(output: &mut io::Write, i: &str, mpis: bool, s: Subpacket)
                  -> Result<()> {
    use self::SubpacketValue::*;
    match s.value {
        Unknown(ref b) =>
            write!(output, "{}    Unknown: {:?}", i, b)?,
        Invalid(ref b) =>
            write!(output, "{}    Invalid: {:?}", i, b)?,
        SignatureCreationTime(ref t) =>
            write!(output, "{}    Signature creation time: {}", i,
                   time::strftime(TIMEFMT, t).unwrap())?,
        SignatureExpirationTime(ref t) =>
            write!(output, "{}    Signature expiration time: {}", i, t)?,
        ExportableCertification(e) =>
            write!(output, "{}    Exportable certification: {}", i, e)?,
        TrustSignature{level, trust} =>
            write!(output, "{}    Trust signature: level {} trust {}", i,
                   level, trust)?,
        RegularExpression(ref r) =>
            write!(output, "{}    Regular expression: {}", i,
                   String::from_utf8_lossy(r))?,
        Revocable(r) =>
            write!(output, "{}    Revocable: {}", i, r)?,
        KeyExpirationTime(ref t) =>
            write!(output, "{}    Signature expiration time: {}", i, t)?,
        PreferredSymmetricAlgorithms(ref c) =>
            write!(output, "{}    Cipher preference: {}", i,
                   c.iter().map(|c| format!("{:?}", c))
                   .collect::<Vec<String>>().join(", "))?,
        RevocationKey{class, pk_algo, ref fp} =>
            write!(output,
                   "{}    Revocation key: class {} algo {} fingerprint {}", i,
                   class, pk_algo, fp)?,
        Issuer(ref is) =>
            write!(output, "{}    Issuer: {}", i, is)?,
        NotationData(ref n) =>
            write!(output, "{}    Notation: {:?}", i, n)?,
        PreferredHashAlgorithms(ref h) =>
            write!(output, "{}    Hash preference: {}", i,
                   h.iter().map(|h| format!("{:?}", h))
                   .collect::<Vec<String>>().join(", "))?,
        PreferredCompressionAlgorithms(ref c) =>
            write!(output, "{}    Compression preference: {}", i,
                   c.iter().map(|c| format!("{:?}", c))
                   .collect::<Vec<String>>().join(", "))?,
        KeyServerPreferences(ref p) =>
            write!(output, "{}    Keyserver preferences: {:?}", i, p)?,
        PreferredKeyServer(ref k) =>
            write!(output, "{}    Preferred keyserver: {}", i,
                   String::from_utf8_lossy(k))?,
        PrimaryUserID(p) =>
            write!(output, "{}    Primary User ID: {}", i, p)?,
        PolicyURI(ref p) =>
            write!(output, "{}    Policy URI: {}", i,
                   String::from_utf8_lossy(p))?,
        KeyFlags(ref k) =>
            write!(output, "{}    Key flags: {:?}", i, k)?,
        SignersUserID(ref u) =>
            write!(output, "{}    Signers User ID: {}", i,
                   String::from_utf8_lossy(u))?,
        ReasonForRevocation{code, ref reason} =>
            write!(output, "{}    Reason for revocation: {}, {}", i, code,
                   String::from_utf8_lossy(reason))?,
        Features(ref f) =>
            write!(output, "{}    Features: {:?}", i, f)?,
        SignatureTarget{pk_algo, hash_algo, ref digest} =>
            write!(output, "{}    Signature target: {}, {}, {}", i,
                   pk_algo, hash_algo, to_hex(digest, false))?,
        EmbeddedSignature(_) =>
        // Embedded signature is dumped below.
            write!(output, "{}    Embedded signature: ", i)?,
        IssuerFingerprint(ref fp) =>
            write!(output, "{}    Issuer Fingerprint: {}", i, fp)?,
        IntendedRecipient(ref fp) =>
            write!(output, "{}    Intended Recipient: {}", i, fp)?,
    }

    if s.critical {
        write!(output, " (critical)")?;
    }
    writeln!(output)?;

    match s.value {
        EmbeddedSignature(ref sig) => {
            let i_ = format!("{}      ", i);
            dump_packet(output, &i_, mpis, sig)?;
        },
        _ => (),
    }

    Ok(())
}

pub fn split(input: &mut io::Read, prefix: &str)
             -> Result<()> {
    // We (ab)use the mapping feature to create byte-accurate dumps of
    // nested packets.
    let mut ppr =
        openpgp::parse::PacketParserBuilder::from_reader(input)?
        .map(true).finalize()?;

    // This encodes our position in the tree.
    let mut pos = vec![0];

    while let PacketParserResult::Some(pp) = ppr {
        if let Some(ref map) = pp.map {
            let filename = format!(
                "{}{}--{:?}", prefix,
                pos.iter().map(|n| format!("{}", n))
                    .collect::<Vec<String>>().join("-"),
                pp.packet.tag());
            let mut sink = File::create(filename)
                .context("Failed to create output file")?;

            // Write all the bytes.
            for (_, buf) in map.iter() {
                sink.write_all(buf)?;
            }
        }

        let ((_, old_depth), (ppr_, new_depth)) = pp.recurse()?;
        ppr = ppr_;

        // Update pos.
        match old_depth.cmp(&new_depth) {
            Ordering::Less =>
                pos.push(0),
            Ordering::Equal =>
                *pos.last_mut().unwrap() += 1,
            Ordering::Greater => {
                pos.pop();
            },
        }
    }
    Ok(())
}

struct HexDumper {
    offset: usize,
}

impl HexDumper {
    fn new() -> Self {
        HexDumper {
            offset: 0,
        }
    }

    fn write(&mut self, sink: &mut io::Write, buf: &[u8], msg: &str)
             -> Result<()> {
        let mut msg_printed = false;
        write!(sink, "{:08x}  ", self.offset)?;
        for i in 0 .. self.offset % 16 {
            if i != 7 {
                write!(sink, "   ")?;
            } else {
                write!(sink, "    ")?;
            }
        }

        for c in buf {
            write!(sink, "{:02x} ", c)?;
            self.offset += 1;
            match self.offset % 16 {
                0 => {
                    if ! msg_printed {
                        write!(sink, "  {}", msg)?;
                        msg_printed = true;
                    }

                    write!(sink, "\n{:08x}  ", self.offset)?;
                },
                8 => write!(sink, " ")?,
                _ => (),
            }
        }

        for i in self.offset % 16 .. 16 {
            if i != 7 {
                write!(sink, "   ")?;
            } else {
                write!(sink, "    ")?;
            }
        }

        if ! msg_printed {
            write!(sink, "  {}", msg)?;
        }
        writeln!(sink)?;
        Ok(())
    }
}

fn to_hex(s: &[u8], pretty: bool) -> String {
    use std::fmt::Write;

    let mut result = String::new();
    for (i, b) in s.iter().enumerate() {
        // Add spaces every four digits to make the output more
        // readable.
        if pretty && i > 0 && i % 2 == 0 {
            write!(&mut result, " ").unwrap();
        }
        write!(&mut result, "{:02X}", b).unwrap();
    }
    result
}
