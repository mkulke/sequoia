use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;

use crate::Result;
use crate::cert::prelude::*;
use crate::Fingerprint;
use crate::KeyHandle;
use crate::KeyID;

use super::Certification;
use super::CertificationSet;

/// A certification network.
pub struct Network<'a> {
    // The list of Certificates.
    pub(super) nodes: HashMap<Fingerprint, ValidCert<'a>>,

    // Certifications that this certificate has made.
    //
    // Example:
    //
    // If certificate 0xA signed two User IDs, B and B', on 0xB, and
    // it signed one User ID, C, on 0xC, 0xA would map to a vector
    // containing two (not three!) CertificationSets: one for 0xA's
    // certifications of User IDs on 0xB and another for 0xA's
    // certifications on User IDs of 0xC.
    //
    // Note: if a certificate has not certified any other key, it will
    // NOT appear here.  But, it will appear in `nodes`.
    pub(super) edges: HashMap<Fingerprint, Vec<CertificationSet<'a>>>,

    // Certifications on this certificate.
    //
    // Example:
    //
    //   C = 0xA certifies <Bob, 0xB0B>.
    //
    // Whereas edges contains the entry 0xA with a CertificationSet
    // containing the certificate C, redges contains an entry for 0xB
    // with a CertificateSet containing C.
    pub(super) redges: HashMap<Fingerprint, Vec<CertificationSet<'a>>>,
}

impl<'a> fmt::Debug for Network<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Network {{\n")?;
        write!(f, "  Nodes:\n")?;

        let mut certs: Vec<_> = self.nodes.iter().map(|(fpr, vc)| {
            (
                vc.userids()
                    .map(|ua| {
                        String::from_utf8_lossy(ua.userid().value())
                            .into_owned()
                    })
                    .collect::<Vec<String>>()
                    .join(", "),
                fpr
            )
        }).collect();
        certs.sort();

        for (userid, fpr) in certs {
            write!(f, "    {}: {}\n", fpr, userid)?;
        }

        write!(f, "  Edges:\n")?;

        let mut edges: Vec<_> = self.edges.values().collect();
        edges.sort_by_key(|cs| {
            cs[0].issuer_cert.primary_userid()
                .map(|ua| String::from_utf8_lossy(ua.userid().value()))
                .unwrap_or("[no User ID]".into())
        });

        for cs in edges {
            let fpr = cs[0].issuer_cert.fingerprint();

            write!(f, "    {} ({}) certifies:\n",
                   fpr,
                   self.nodes.get(&fpr).unwrap()
                       .primary_userid()
                       .map(|ua| String::from_utf8_lossy(ua.userid().value()))
                       .unwrap_or("[no User ID]".into()))?;
            for (userid, c) in cs.iter().flat_map(|cs| cs.certifications.iter()) {
                write!(f, "      {}, {}: {}, {}, {}\n",
                       c.target_cert.fingerprint(),
                       String::from_utf8_lossy(userid),
                       c.depth, c.amount,
                       if c.re_set.matches_everything() { "*".into() }
                       else { format!("{:?}", c.re_set) })?;
            }
        }

        write!(f, "}}\n")?;

        Ok(())
    }
}

impl<'a> Network<'a> {
    /// Returns an empty network.
    pub fn empty() -> Self {
        Network {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            redges: HashMap::new(),
        }
    }

    /// Builds a WoT network from a set of keys.
    ///
    /// Note: if vcs contains multiple instances of the same
    /// certificate, only the first instance is used; the rest are
    /// silently ignored.
    pub fn new(vcs: Vec<ValidCert<'a>>)
        -> Result<Self>
    {
        tracer!(true, "Network::new", 0);

        let mut n = Network::empty();

        // Like n.nodes, but for Key IDs (needed when a certification
        // only includes an Issuer subpacket).
        let mut by_keyid: HashMap<KeyID, Vec<ValidCert<'a>>> = HashMap::new();

        // Build the hash from Fingerprint to Cert, and from KeyID to
        // Cert.
        for vc in vcs.iter() {
            n.nodes.entry(vc.fingerprint())
                .or_insert(vc.clone());
            by_keyid.entry(vc.keyid())
                .and_modify(|e| e.push(vc.clone()))
                .or_insert(vec![ vc.clone() ]);
        }

        // Iterate over each <Cert, UserID>.
        for ua in vcs.iter().flat_map(|vc| vc.userids()) {
            let vc = ua.cert();

            // Skip invalid User ID.
            if let Err(_) = std::str::from_utf8(ua.userid().value()) {
                t!("{}: Non-UTF-8 User ID ({:?}) skipped.",
                   vc.keyid(),
                   String::from_utf8_lossy(ua.userid().value()));
                continue;
            }

            // We iterate over all of the certifications.  We need to
            // be careful: we only want the newest certification for a
            // given <Issuer, <Cert, UserID>> tuple.

            let mut certifications: Vec<_> = ua.certifications().collect();
            t!("<{}, {}>: {} certifications",
               vc.fingerprint(), String::from_utf8_lossy(ua.userid().value()),
               certifications.len());

            // Sort the certifications so that the newest comes first.
            certifications.sort_by(|a, b| {
                a.signature_creation_time().cmp(&b.signature_creation_time())
                    .reverse()
            });

            // If we've already seen a valid certification from the
            // Issuer on the current <Cert, UserID> binding.
            let mut seen: HashMap<Fingerprint, ()> = HashMap::new();

            'cert: for certification in certifications {
                // Check that the certification is valid:
                //
                //   - Find the issuer.
                //   - Verify the signature.
                //
                // If we don't have a certificate for the alleged issuer,
                // then we ignore the certification.

                let verify = |possible_issuer: &ValidCert<'a>| -> Option<Certification> {
                    if certification
                        .clone()
                        .verify_userid_binding(
                            possible_issuer.primary_key().key(),
                            vc.primary_key().key(),
                            ua.userid())
                        .is_ok()
                    {
                        // Looks like the certification really came
                        // from the alleged issuer.
                        let c = Certification::from_signature(
                            possible_issuer.clone(),
                            ua.userid(),
                            vc.clone(),
                            certification);

                        t!("<{}, {:?}> {} <{}, {:?}> \
                            (depth: {}, amount: {}, scope: {:?})",
                           possible_issuer.keyid(),
                           possible_issuer
                               .primary_userid()
                               .map(|ua| {
                                   String::from_utf8_lossy(ua.value()).into_owned()
                               })
                               .unwrap_or("[no User ID]".into()),
                           if c.depth > 0 {
                               "tsigned"
                           } else {
                               "certified"
                           },
                           vc.keyid(),
                           String::from_utf8_lossy(ua.userid().value()),
                           c.depth,
                           c.amount,
                           if c.re_set.matches_everything() { "*".into() }
                           else { format!("{:?}", c.re_set) }
                        );

                        Some(c)
                    } else {
                        None
                    }
                };

                // Improve tracing: distinguish between we don't have
                // the issuer's certificate and we have it, but the
                // signature is invalid.
                let mut invalid_sig: Option<Fingerprint> = None;
                for alleged_issuer in certification.get_issuers() {
                    match alleged_issuer {
                        KeyHandle::Fingerprint(fpr) => {
                            if let Some(alleged_issuer) = n.nodes.get(&fpr) {
                                if let Some(edge) = verify(alleged_issuer) {
                                    if seen.get(&fpr).is_some() {
                                        // We already have a newer
                                        // certification from this
                                        // issuer.
                                        t!("Skipping certification {:02X}{:02X} \
                                            by {} for <{:?}, {}>: saw a newer one.",
                                           certification.digest_prefix()[0],
                                           certification.digest_prefix()[1],
                                           fpr,
                                           ua.userid(), vc.keyid());
                                        continue 'cert;
                                    }

                                    // Arg.  We can't simply do:
                                    //
                                    //   .and_modify(...).or_insert(...),
                                    //
                                    // because rustc doesn't know that
                                    // only one of them will run, and
                                    // concludes that c is used after
                                    // being moved.
                                    match n.edges.entry(fpr.clone()) {
                                        e @ Entry::Occupied(_) => {
                                            // We merge below.
                                            e.and_modify(|e| {
                                                e.push(CertificationSet
                                                       ::from_certification(
                                                           edge.clone()))
                                            });
                                        }
                                        e @ Entry::Vacant(_) => {
                                            e.or_insert(
                                                vec![
                                                    CertificationSet
                                                        ::from_certification(
                                                            edge.clone())
                                                ]);
                                        }
                                    }

                                    match n.redges.entry(vc.fingerprint()) {
                                        e @ Entry::Occupied(_) => {
                                            // We merge below.
                                            e.and_modify(|e| {
                                                e.push(CertificationSet
                                                       ::from_certification(
                                                           edge))
                                            });
                                        }
                                        e @ Entry::Vacant(_) => {
                                            e.or_insert(
                                                vec![
                                                    CertificationSet
                                                        ::from_certification(
                                                            edge.clone())
                                                ]);
                                        }
                                    }

                                    seen.insert(fpr, ());

                                    continue 'cert;
                                } else {
                                    invalid_sig = Some(fpr);
                                }
                            }
                        }
                        KeyHandle::KeyID(keyid) => {
                            if let Some(alleged_issuers) = by_keyid.get(&keyid) {
                                for alleged_issuer in alleged_issuers {
                                    let fpr = alleged_issuer.fingerprint();
                                    if let Some(edge) = verify(alleged_issuer) {
                                        if seen.get(&fpr).is_some() {
                                            // We already have a newer
                                            // certification from this
                                            // issuer.
                                            t!("Skipping certification {:02X}{:02X} \
                                                by {} for <{:?}, {}>: saw a newer one.",
                                               certification.digest_prefix()[0],
                                               certification.digest_prefix()[1],
                                               fpr,
                                               ua.userid(), vc.keyid());
                                            continue 'cert;
                                        }

                                        // Arg.  We can't simply do:
                                        // .and_modify(...).or_insert(...),
                                        // because rustc doesn't know that
                                        // only one of them will run, and
                                        // concludes that c is used after
                                        // being moved.
                                        match n.edges.entry(fpr.clone()) {
                                            e @ Entry::Occupied(_) => {
                                                // We merge below.
                                                e.and_modify(|e| {
                                                    e.push(CertificationSet
                                                           ::from_certification(
                                                               edge.clone()))
                                                });
                                            }
                                            e @ Entry::Vacant(_) => {
                                                e.or_insert(
                                                    vec![
                                                        CertificationSet
                                                            ::from_certification(
                                                                edge.clone())
                                                    ]);
                                            }
                                        }

                                        match n.redges.entry(vc.fingerprint()) {
                                            e @ Entry::Occupied(_) => {
                                                // We merge below.
                                                e.and_modify(|e| {
                                                    e.push(CertificationSet
                                                           ::from_certification(
                                                               edge))
                                                });
                                            }
                                            e @ Entry::Vacant(_) => {
                                                e.or_insert(
                                                    vec![
                                                        CertificationSet
                                                            ::from_certification(
                                                                edge.clone())
                                                    ]);
                                            }
                                        }

                                        seen.insert(fpr, ());

                                        continue 'cert;
                                    } else {
                                        invalid_sig = Some(fpr);
                                    }
                                }
                            }
                        }
                    };
                }

                if let Some(keyid) = invalid_sig {
                    t!("Invalid certification {:02X}{:02X} by {} for <{:?}, {}>.",
                       certification.digest_prefix()[0],
                       certification.digest_prefix()[1],
                       keyid,
                       ua.userid(), vc.keyid());
                } else {
                    t!("Certification {:02X}{:02X} for <{:?}, {}>: \
                        missing issuer's certificate ({}).",
                       certification.digest_prefix()[0],
                       certification.digest_prefix()[1],
                       ua.userid(), vc.keyid(),
                       certification.get_issuers()
                           .first()
                           .map(|h| h.to_string())
                           .unwrap_or("(no issuer subkeys)".into())
                    );
                }
            }
        }

        t!("Merging.");

        // Merge the CertificationSets.  A certification is from a
        // certificate and over a certification and User ID pair.  We
        // want one CertificateSet for each pair of certificates.
        for (_, cs) in n.edges.iter_mut() {
            cs.sort_by(|a, b| {
                a.target_cert.fingerprint().cmp(
                    &b.target_cert.fingerprint())
            });

            // Now merge certifications from the same certificate.
            *cs = cs.drain(..).fold(
                Vec::new(),
                |mut v: Vec<CertificationSet>, cs: CertificationSet|
                    -> Vec<CertificationSet>
                {
                    let len = v.len();
                    if len > 0 {
                        let l = &mut v[len-1];
                        if l.target_cert.fingerprint()
                            == cs.target_cert.fingerprint()
                        {
                            l.merge(cs);
                        } else {
                            v.push(cs);
                        }
                    } else {
                        v.push(cs);
                    }

                    v
                });
        }

        for (_, cs) in n.redges.iter_mut() {
            cs.sort_by(|a, b| {
                a.issuer_cert.fingerprint().cmp(
                    &b.issuer_cert.fingerprint())
            });

            // Now merge certifications from the same certificate.
            *cs = cs.drain(..).fold(
                Vec::new(),
                |mut v: Vec<CertificationSet>, cs: CertificationSet| -> Vec<CertificationSet> {
                    let len = v.len();
                    if len > 0 {
                        let l = &mut v[len-1];
                        if l.issuer_cert.fingerprint()
                            == cs.issuer_cert.fingerprint()
                        {
                            l.merge(cs);
                        } else {
                            v.push(cs);
                        }
                    } else {
                        v.push(cs);
                    }

                    v
                });
        }

        t!("Done.");

        Ok(n)
    }
}
