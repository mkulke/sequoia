//! Web of trust support.

use std::collections::HashMap;
use std::fmt;

use crate::cert::prelude::*;
use crate::packet::prelude::*;
use crate::Fingerprint;
use crate::regex::RegexSet;

mod network;
pub use network::Network;
mod forward_propagation;
mod backward_propagation;
use backward_propagation::SuppressCertificationFilter;
mod path;
pub use path::{Path, Paths};
mod priority_queue;
use priority_queue::PriorityQueue;

const TRACE: bool = true;

/// A single certification.
///
/// Encapsulates a certification over a binding, e.g., 0xA's
/// certification binding the User ID B and the certificate 0xB, which
/// we denote: <0xA, B:0xB>.
#[derive(Clone)]
pub struct Certification<'a> {
    issuer_cert: ValidCert<'a>,
    target_cert: ValidCert<'a>,
    target_userid: &'a UserID,

    /// 0: Normal certification.
    /// 1: Trusted introducer.
    /// 2: Meta-introducer.
    /// etc.
    depth: u8,
    /// 60: partial trust.
    /// 120: complete trust.
    amount: u8,
    /// Scope.
    re_set: RegexSet,
}

impl<'a> fmt::Debug for Certification<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Certification")
            .field("issuer",
                   &self.issuer_cert.fingerprint().to_string())
            .field("target_cert",
                   &self.target_cert.fingerprint().to_string())
            .field("target_userid",
                   &String::from_utf8_lossy(self.target_userid.value()))
            .field("depth", &self.depth)
            .field("amount", &self.amount)
            .field("regexs",
                   &if self.re_set.matches_everything() {
                       String::from("*")
                   } else {
                       format!("{:?}", &self.re_set)
                   })
            .finish()
    }
}


impl<'a> Certification<'a> {
    /// Creates a `Certification` from a signature.
    ///
    /// `target_userid` and `target_cert` are what are signed.
    ///
    /// The signature is not checked for validity.  The data structure
    /// does not contain a reference to the signer.
    pub fn from_signature(issuer_cert: ValidCert<'a>,
                          target_userid: &'a UserID,
                          target_cert: ValidCert<'a>,
                          sig: &Signature)
        -> Self
    {
        let (d, a, r) = if let Some((d, a)) = sig.trust_signature()
        {
            (d, a, RegexSet::from_signature(sig).expect("internal error"))
        } else {
            (0, 120, RegexSet::everything().expect("internal error"))
        };

        Certification {
            issuer_cert: issuer_cert,
            target_cert: target_cert,
            target_userid: target_userid,
            depth: d,
            amount: a,
            re_set: r,
        }
    }
}

/// All active certifications that one certificate made on another.
///
/// Encapsulates all active certifications that a certificate made on
/// another certificate.  For instance, if the certificate 0xB has two
/// User IDs: B and B' and 0xA signed both, then this contains the
/// latest certification for <0xA, B:0xB> and the latest certification
/// for <0xA, B':0xB>.
pub struct CertificationSet<'a> {
    // The certificate that issued the certifications.
    issuer_cert: ValidCert<'a>,
    // The certificate that was signed.
    target_cert: ValidCert<'a>,
    // The certifications, keyed by the certified (target) User ID.
    certifications: HashMap<&'a [u8], Certification<'a>>,
}

impl<'a> CertificationSet<'a> {
    /// Returns an empty CertificationSet.
    fn empty(issuer_cert: ValidCert<'a>, target_cert: ValidCert<'a>) -> Self {
        Self {
            issuer_cert: issuer_cert,
            target_cert: target_cert,
            certifications: HashMap::new(),
        }
    }

    /// Returns a new CertificationSet with the supplied
    /// certification.
    ///
    /// All certifications in a CertificationSet must be issued by the
    /// same certificate.  There can only be one certification per User
    /// ID.
    fn from_certification(certification: Certification<'a>) -> Self {
        let mut cs = CertificationSet::empty(certification.issuer_cert.clone(),
                                             certification.target_cert.clone());
        cs.add(certification);
        cs
    }

    /// Adds a certification to the CertificationSet.
    ///
    /// All certifications in a CertificationSet must be issued by the
    /// same certificate.  There can only be one certification per User
    /// ID.
    fn add(&mut self, certification: Certification<'a>) {
        // certification must be over the same certificate.
        if let Some((_, c)) = self.certifications.iter().next() {
            assert_eq!(certification.issuer_cert.fingerprint(),
                       c.issuer_cert.fingerprint());
            assert_eq!(certification.target_cert.fingerprint(),
                       c.target_cert.fingerprint());
        }

        self.certifications.entry(certification.target_userid.value())
            .and_modify(|_| {
                unreachable!("Have multiple certifications for {}, {}",
                             certification.target_cert.keyid(),
                             certification.target_userid);
            })
            .or_insert(certification);
    }

    fn merge(&mut self, other: Self) {
        assert_eq!(self.issuer_cert.fingerprint(),
                   other.issuer_cert.fingerprint());
        assert_eq!(self.target_cert.fingerprint(),
                   other.target_cert.fingerprint());

        for (_, c) in other.certifications.into_iter() {
            self.add(c);
        }
    }
}


/// A certification network.
pub struct RootedNetwork<'a> {
    // The underlying network.
    n: &'a Network<'a>,

    // The trust roots.  This is sorted and deduped.
    roots: Vec<Fingerprint>,

    // The result of n.forward_propagation(roots).
    auth_paths: HashMap<Fingerprint, Path<'a>>,
}

impl<'a> RootedNetwork<'a> {
    /// New.
    pub fn new(n: &'a Network<'a>, roots: &[Fingerprint]) -> Self {
        tracer!(TRACE, "RootedNetwork::new", 0);

        t!("Roots: {}.",
           roots.iter()
               .map(|fpr| fpr.to_string()).collect::<Vec<_>>()
               .join(", "));
        t!("Have {} nodes, {} have made at least one certification.",
           n.nodes.len(), n.edges.len());

        let mut roots = roots.to_vec();
        roots.sort();
        roots.dedup();

        let roots: Vec<Fingerprint> = roots.into_iter()
            .filter(|fpr| {
                if let Some(_) = n.nodes.get(fpr) {
                    true
                } else {
                    t!("  Ignoring root that does not occur in network: {}",
                       fpr);
                    false
                }
            })
            .collect();

        let auth_paths = n.forward_propagate(&roots[..]);

        RootedNetwork {
            n,
            roots,
            auth_paths,
        }
    }

    fn is_root(&self, fpr: &Fingerprint) -> bool {
        self.roots.binary_search(fpr).is_ok()
    }

    /// Attempts to authenticate the specified binding.
    ///
    /// Enough independent paths are gotten to satisfy
    /// `target_trust_amount`.  A fully trusted authentication is 120.
    /// If you require that a binding be double authenticated, you can
    /// specify 240.
    pub fn authenticate(&self, target_userid: UserID, target_fpr: Fingerprint,
                        target_trust_amount: usize)
        -> Paths<'a>
    {
        tracer!(TRACE, "RootedNetwork::authenticate", 0);

        t!("Authenticating <{}, {}>",
           target_fpr, String::from_utf8_lossy(target_userid.value()));
        t!("Roots:");
        for (i, fpr) in self.roots.iter().enumerate() {
            t!("  {}: {}", i, fpr);
        }

        let mut paths = Paths::new();

        // See if the path is cached.
        match self.auth_paths.get(&target_fpr) {
            Some(p) => {
                // Have a path.  We still need to check that the last
                // certification was for this User ID.
                if let Some(c) = p.certifications().last() {
                    if c.target_userid == &target_userid {
                        paths.push(p.clone(), p.amount());
                    } else {
                        if let Some(cs) = self.n.redges.get(&target_fpr).expect("have one")
                            .iter()
                            .find(|cs| {
                                cs.target_cert.fingerprint()
                                    == c.issuer_cert.fingerprint()
                            })
                        {
                            t!("  Found certification for binding: {:?}", c);
                            if let Some(c) = cs.certifications.get(&target_userid.value()) {
                                let mut p = p.clone();
                                p.replace_tail(c.clone());
                                let a = p.amount();
                                paths.push(p, a);
                            }
                        }
                    }
                }
            }
            None => {
                // Our cheap heuristic didn't find a path.  See if the
                // binding was even certified...
                //
                // Note: if target_fpr were a root, its self
                // signatures would have been added to auth_paths.
                if ! self.n.redges
                    .get(&target_fpr).iter()
                    .flat_map(|css| css.iter()).any(|cs| {
                        cs.certifications.values().any(|c| {
                            c.target_userid == &target_userid
                        })
                    })
                {
                    t!("{} was not certified for {}",
                       target_fpr, target_userid);
                    return paths;
                }
            }
        }

        t!("Doing a reverse search.");

        let mut filter = SuppressCertificationFilter::new();
        for (path, amount) in paths.iter() {
            filter.suppress_path(&path, *amount as u8);
        }

        while paths.amount() < target_trust_amount {
            let auth_rpaths: HashMap<Fingerprint, (Path, usize)>
                = self.n.backward_propagate(
                    &self.roots, target_fpr.clone(), target_userid.clone(),
                    &filter);

            if let Some((rpath, amount)) = self.roots.iter()
                .filter_map(|fpr| {
                    auth_rpaths.get(fpr)
                })
                .max_by_key(|(path, amount)| (amount, -(path.len() as isize)))
            {
                let path = rpath.clone();
                filter.suppress_path(&path, *amount as u8);

                paths.push(path, *amount);
            } else {
                t!("    backward propagation didn't find any more paths");
                break;
            }
        }

        paths
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use crate::Result;
    use crate::parse::Parse;
    use crate::policy::StandardPolicy;

    // Authenticates the target.
    fn sp(rn: &RootedNetwork,
          target_fpr: &Fingerprint, target_userid: &UserID,
          expected: &[ (usize, &[ &Fingerprint ]) ],
          min_trust_amount: Option<usize>)
    {
        eprintln!("\nauthenticating: {}, {}",
                  target_fpr,
                  String::from_utf8_lossy(target_userid.value()));
        let got = rn.authenticate(target_userid.clone(),
                                  target_fpr.clone(),
                                  min_trust_amount.unwrap_or(120));
        match (got.iter().count() > 0, expected.len() > 0 ) {
            (false, false) => {
                eprintln!("Can't authenticate == can't authenticate (good)");
            }
            (false, true) => {
                panic!("Couldn't authenticate.  Expected: paths:\n{}",
                       expected.iter()
                           .enumerate()
                       .flat_map(|(i, (_, p))| {
                               p.iter().enumerate().map(move |(j, f)| {
                                   format!("  {}.{}. {}", i, j, f.to_hex())
                               })
                           })
                           .collect::<Vec<_>>()
                           .join("\n  "));
            }
            (true, false) => {
                panic!("Unexpectedly authenticated binding.  Got:\n{}",
                       got.iter().enumerate().map(|(i, p)| {
                           format!("PATH #{}\n{:?}", i, p)
                       })
                       .collect::<Vec<_>>()
                       .join("\n"));
            }
            (true, true) => {
                eprintln!("Paths: {:?}", got);

                assert_eq!(got.iter().count(), expected.len(),
                           "Expected {:?} paths, got {:?}",
                           got, expected);
                for (i, ((got_amount, got_path), (expected_amount, expected_path)))
                    in got.iter().map(|(p, a)| {
                        (a,
                         p.certificates().map(|c| {
                             c.fingerprint()
                         })
                        .collect::<Vec<_>>())
                    })
                    .zip(expected.iter().map(|(a, fprs)| {
                        (a, fprs.iter().map(|&fpr| {
                            fpr.clone()
                        }).collect::<Vec<Fingerprint>>())
                    }))
                    .enumerate()
                {
                    assert_eq!(got_path, expected_path,
                               "got vs. expected path (#{})",
                               i);
                    assert_eq!(got_amount, expected_amount,
                               "got vs. expected trust amount (#{})",
                               i);
                }
                assert_eq!(got.amount(),
                           expected.iter().map(|(a, _)| a).sum());
            }
        }
    }

    #[test]
    #[allow(unused)]
    fn simple() -> Result<()> {
        let p = &StandardPolicy::new();

        let alice_fpr: Fingerprint =
            "76B4 1898 8CEF 5C87 89CE  4F01 12A6 22BC 137E ACC1"
           .parse().expect("valid fingerprint");
        let alice_uid
            = UserID::from("<alice@example.org>");

        let bob_fpr: Fingerprint =
            "BC65 F151 B2AE 3F92 74B2  21A6 86FC 52A0 DAC9 68FF"
           .parse().expect("valid fingerprint");
        let bob_uid
            = UserID::from("<bob@example.org>");
        // Certified by: 76B4 1898 8CEF 5C87 89CE  4F01 12A6 22BC 137E ACC1

        let carol_fpr: Fingerprint =
            "B76A 2C10 B70E 4EF3 0D44  D3AB DECB D640 CD19 749A"
           .parse().expect("valid fingerprint");
        let carol_uid
            = UserID::from("<carol@example.org>");
        // Certified by: BC65 F151 B2AE 3F92 74B2  21A6 86FC 52A0 DAC9 68FF

        let dave_fpr: Fingerprint =
            "38B4 D763 FD61 38E9 503A  2211 2C58 59B1 6CE5 97F7"
           .parse().expect("valid fingerprint");
        let dave_uid
            = UserID::from("<dave@example.org>");
        // Certified by: B76A 2C10 B70E 4EF3 0D44  D3AB DECB D640 CD19 749A

        let ellen_fpr: Fingerprint =
            "B4EF F302 0E14 E5A0 D978  D784 4362 FEA3 E9E7 4EFA"
           .parse().expect("valid fingerprint");
        let ellen_uid
            = UserID::from("<ellen@example.org>");
        // Certified by: 38B4 D763 FD61 38E9 503A  2211 2C58 59B1 6CE5 97F7

        let frank_fpr: Fingerprint =
            "7B3D 997B 80A8 09F9 B8C7  85AE 15EE 5AF2 E96B 0106"
           .parse().expect("valid fingerprint");
        let frank_uid
            = UserID::from("<frank@example.org>");


        let certs: Vec<Cert> = CertParser::from_bytes(
            &crate::tests::wot("simple.pgp"))?
            .map(|c| c.expect("Valid certificate"))
            .collect();
        let n = Network::new(
            certs
                .iter()
                .filter_map(|c| c.with_policy(p, None).ok())
                .collect()
        )?;

        eprintln!("{:?}", n);

        let r = RootedNetwork::new(&n, &[ alice_fpr.clone() ]);

        sp(&r, &alice_fpr, &alice_uid.clone(),
           &[ (120, &[ &alice_fpr ][..]) ][..],
           None);

        sp(&r, &bob_fpr, &bob_uid.clone(),
           &[ (100, &[ &alice_fpr, &bob_fpr ][..]) ][..],
           None);

        sp(&r, &carol_fpr, &carol_uid.clone(),
           &[ (100, &[ &alice_fpr, &bob_fpr, &carol_fpr ][..]) ][..],
           None);

        sp(&r, &dave_fpr, &dave_uid.clone(),
           &[ (100, &[ &alice_fpr, &bob_fpr, &carol_fpr, &dave_fpr ][..]) ][..],
           None);

        sp(&r, &ellen_fpr, &ellen_uid.clone(),
           &[][..],
           None);

        sp(&r, &frank_fpr, &frank_uid.clone(),
           &[][..],
           None);

        // No one authenticated Bob's User ID on Carol's key.
        sp(&r, &carol_fpr, &bob_uid.clone(),
           &[][..],
           None);

        let r = RootedNetwork::new(&n, &[ bob_fpr.clone() ]);

        sp(&r, &alice_fpr, &alice_uid.clone(),
           &[][..],
           None);

        sp(&r, &bob_fpr, &bob_uid.clone(),
           &[ (100, &[ &bob_fpr ][..]) ][..],
           None);

        sp(&r, &carol_fpr, &carol_uid.clone(),
           &[ (100, &[ &bob_fpr, &carol_fpr ][..]) ][..],
           None);

        sp(&r, &dave_fpr, &dave_uid.clone(),
           &[ (100, &[ &bob_fpr, &carol_fpr, &dave_fpr ][..]) ][..],
           None);

        sp(&r, &ellen_fpr, &ellen_uid.clone(),
           &[][..],
           None);

        sp(&r, &frank_fpr, &frank_uid.clone(),
           &[][..],
           None);

        // No one authenticated Bob's User ID on Carol's key.
        sp(&r, &carol_fpr, &bob_uid.clone(),
           &[][..],
           None);

        Ok(())
    }

    #[test]
    #[allow(unused)]
    fn cycle() -> Result<()> {
        let p = &StandardPolicy::new();

        let alice_fpr: Fingerprint =
            "B108 5496 9692 BE07 2F37  4D0D A914 FE6B 3879 7199"
           .parse().expect("valid fingerprint");
        let alice_uid
            = UserID::from("<alice@example.org>");

        let bob_fpr: Fingerprint =
            "8821 488D D4DD 0C01 8FF5  A4D2 E89F 6EE8 5AE0 98FB"
           .parse().expect("valid fingerprint");
        let bob_uid
            = UserID::from("<bob@example.org>");
        // Certified by: B108 5496 9692 BE07 2F37  4D0D A914 FE6B 3879 7199
        // Certified by: CBFB F6C4 9357 380F 633E  E785 F85C EC70 7AF8 A1FE

        let carol_fpr: Fingerprint =
            "3831 9E76 64BF 9180 ED41  2933 416D B660 67A7 74C3"
           .parse().expect("valid fingerprint");
        let carol_uid
            = UserID::from("<carol@example.org>");
        // Certified by: 8821 488D D4DD 0C01 8FF5  A4D2 E89F 6EE8 5AE0 98FB

        let dave_fpr: Fingerprint =
            "CBFB F6C4 9357 380F 633E  E785 F85C EC70 7AF8 A1FE"
           .parse().expect("valid fingerprint");
        let dave_uid
            = UserID::from("<dave@example.org>");
        // Certified by: 3831 9E76 64BF 9180 ED41  2933 416D B660 67A7 74C3

        let ed_fpr: Fingerprint =
            "6BFE 8673 D01E E032 D5B6  E9AC 6164 26A1 906D 67CE"
           .parse().expect("valid fingerprint");
        let ed_uid
            = UserID::from("<ed@example.org>");
        // Certified by: CBFB F6C4 9357 380F 633E  E785 F85C EC70 7AF8 A1FE

        let frank_fpr: Fingerprint =
            "F4AC E7B8 A36C B151 AC65  3EA6 6143 9493 CA15 9770"
           .parse().expect("valid fingerprint");
        let frank_uid
            = UserID::from("<frank@example.org>");
        // Certified by: 6BFE 8673 D01E E032 D5B6  E9AC 6164 26A1 906D 67CE


        let certs: Vec<Cert> = CertParser::from_bytes(
            &crate::tests::wot("cycle.pgp"))?
            .map(|c| c.expect("Valid certificate"))
            .collect();
        let n = Network::new(
            certs
                .iter()
                .filter_map(|c| c.with_policy(p, None).ok())
                .collect()
        )?;

        eprintln!("{:?}", n);

        let r = RootedNetwork::new(&n, &[ alice_fpr.clone() ]);

        sp(&r, &alice_fpr, &alice_uid.clone(),
           &[ (120, &[ &alice_fpr ][..]) ][..],
           None);

        sp(&r, &bob_fpr, &bob_uid.clone(),
           &[
               (120,
                &[ &alice_fpr, &bob_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &carol_fpr, &carol_uid.clone(),
           &[
               (90,
                &[ &alice_fpr, &bob_fpr, &carol_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &dave_fpr, &dave_uid.clone(),
           &[
               (60,
                &[ &alice_fpr, &bob_fpr, &carol_fpr, &dave_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &ed_fpr, &ed_uid.clone(),
           &[
               (30,
                &[ &alice_fpr, &bob_fpr, &carol_fpr, &dave_fpr, &ed_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &frank_fpr, &frank_uid.clone(),
           &[][..],
           None);

        let r = RootedNetwork::new(&n, &[ alice_fpr.clone(), dave_fpr.clone() ]);

        sp(&r, &alice_fpr, &alice_uid.clone(),
           &[ (120, &[ &alice_fpr ][..]) ][..],
           None);

        sp(&r, &bob_fpr, &bob_uid.clone(),
           &[
               (120, &[ &dave_fpr, &bob_fpr ][..]),
               (120, &[ &alice_fpr, &bob_fpr ][..]),
           ][..],
           Some(300));

        // Dave is preferred by the forward propagation, because the
        // path has more residual depth.
        sp(&r, &carol_fpr, &carol_uid.clone(),
           &[
               (90, &[ &dave_fpr, &bob_fpr, &carol_fpr ][..]),
           ][..],
           None);

        sp(&r, &ed_fpr, &ed_uid.clone(),
           &[
               (30,
                &[ &dave_fpr, &ed_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &frank_fpr, &frank_uid.clone(),
           &[
               (30,
                &[ &dave_fpr, &ed_fpr, &frank_fpr ][..]
               )
           ][..],
           None);

        Ok(())
    }

    #[test]
    #[allow(unused)]
    fn cliques() -> Result<()> {
        let p = &StandardPolicy::new();

        let root_fpr: Fingerprint =
            "D2B0 C383 5C01 B0C1 20BC  540D A4AA 8F88 0BA5 12B5"
           .parse().expect("valid fingerprint");
        let root_uid
            = UserID::from("<root@example.org>");

        let a_0_fpr: Fingerprint =
            "3630 82E9 EEB2 2E50 AD30  3D8B 1BFE 9BA3 F4AB D40E"
           .parse().expect("valid fingerprint");
        let a_0_uid
            = UserID::from("<a-0@example.org>");

        let a_1_fpr: Fingerprint =
            "7974 C04E 8D5B 540D 23CD  4E62 DDFA 779D 91C6 9894"
           .parse().expect("valid fingerprint");
        let a_1_uid
            = UserID::from("<a-1@example.org>");

        let b_0_fpr: Fingerprint =
            "25D8 EAAB 8947 05BB 64D4  A6A8 9649 EF81 AEFE 5162"
           .parse().expect("valid fingerprint");
        let b_0_uid
            = UserID::from("<b-0@example.org>");

        let b_1_fpr: Fingerprint =
            "46D2 F5CE D9BD 3D63 A11D  DFEE 1BA0 1950 6BE6 7FBB"
           .parse().expect("valid fingerprint");
        let b_1_uid
            = UserID::from("<b-1@example.org>");

        let c_0_fpr: Fingerprint =
            "A0CD 8758 2C21 743C 0E30  637F 7FAD B1C3 FEFB FE59"
           .parse().expect("valid fingerprint");
        let c_0_uid
            = UserID::from("<c-0@example.org>");

        let c_1_fpr: Fingerprint =
            "5277 C14F 9D37 A0F4 D615  DD9C CDCC 1AC8 464C 8FE5"
           .parse().expect("valid fingerprint");
        let c_1_uid
            = UserID::from("<c-1@example.org>");

        let d_0_fpr: Fingerprint =
            "C24C C091 02D2 2E38 E839  3C55 1669 8256 1E14 0C03"
           .parse().expect("valid fingerprint");
        let d_0_uid
            = UserID::from("<d-0@example.org>");

        let d_1_fpr: Fingerprint =
            "7A80 DB53 30B7 D900 D5BD  1F82 EAD7 2FF7 9140 78B2"
           .parse().expect("valid fingerprint");
        let d_1_uid
            = UserID::from("<d-1@example.org>");

        let e_0_fpr: Fingerprint =
            "D1E9 F85C EF62 7169 9FBD  E5AB 26EF E0E0 35AC 522E"
           .parse().expect("valid fingerprint");
        let e_0_uid
            = UserID::from("<e-0@example.org>");

        let f_0_fpr: Fingerprint =
            "C0FF AEDE F092 8B18 1265  775A 222B 480E B43E 0AFF"
           .parse().expect("valid fingerprint");
        let f_0_uid
            = UserID::from("<f-0@example.org>");

        let target_fpr: Fingerprint =
            "CE22 ECD2 82F2 19AA 9959  8BA3 B58A 7DA6 1CA9 7F55"
           .parse().expect("valid fingerprint");
        let target_uid
            = UserID::from("<target@example.org>");


        let certs: Vec<Cert> = CertParser::from_bytes(
            &crate::tests::wot("cliques.pgp"))?
            .map(|c| c.expect("Valid certificate"))
            .collect();
        let n = Network::new(
            certs
                .iter()
                .filter_map(|c| c.with_policy(p, None).ok())
                .collect()
        )?;

        eprintln!("{:?}", n);

        let r = RootedNetwork::new(&n, &[ root_fpr.clone() ]);

        // root -> a-0 -> a-1 -> b-0 -> ... -> f-0 -> target
        sp(&r, &target_fpr, &target_uid.clone(),
           &[
               (120, &[
                   &root_fpr,
                   &a_0_fpr,
                   &a_1_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_0_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..])
           ],
           None);

        let r = RootedNetwork::new(&n, &[ a_1_fpr.clone() ]);

        sp(&r, &target_fpr, &target_uid.clone(),
           &[
               (120, &[
                   &a_1_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_0_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..])
           ][..],
           None);

        let certs: Vec<Cert> = CertParser::from_bytes(
            &crate::tests::wot("cliques-local-optima.pgp"))?
            .map(|c| c.expect("Valid certificate"))
            .collect();
        let n = Network::new(
            certs
                .iter()
                .filter_map(|c| c.with_policy(p, None).ok())
                .collect()
        )?;

        eprintln!("{:?}", n);

        let r = RootedNetwork::new(&n, &[ root_fpr.clone() ]);

        // root -> b-0 -> ... -> f-0 -> target
        sp(&r, &target_fpr, &target_uid.clone(),
           &[
               (30, &[
                   &root_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_0_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..]),
               (30, &[
                   &root_fpr,
                   &a_1_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_0_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..]),
               (60, &[
                   &root_fpr,
                   &a_0_fpr,
                   &a_1_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_0_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..])
           ],
           None);

        let r = RootedNetwork::new(&n, &[ a_1_fpr.clone() ]);

        sp(&r, &target_fpr, &target_uid.clone(),
           &[
               (120, &[
                   &a_1_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_0_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..])
           ][..],
           None);


        let certs: Vec<Cert> = CertParser::from_bytes(
            &crate::tests::wot("cliques-local-optima-2.pgp"))?
            .map(|c| c.expect("Valid certificate"))
            .collect();
        let n = Network::new(
            certs
                .iter()
                .filter_map(|c| c.with_policy(p, None).ok())
                .collect()
        )?;

        eprintln!("{:?}", n);

        let r = RootedNetwork::new(&n, &[ root_fpr.clone() ]);

        // root -> b-0 -> ... -> f-0 -> target
        sp(&r, &target_fpr, &target_uid.clone(),
           &[
               (30, &[
                   &root_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..]),
               (30, &[
                   &root_fpr,
                   &a_1_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_0_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..]),
               (60, &[
                   &root_fpr,
                   &a_0_fpr,
                   &a_1_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_0_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..])
           ],
           None);

        let r = RootedNetwork::new(&n, &[ a_1_fpr.clone() ]);

        sp(&r, &target_fpr, &target_uid.clone(),
           &[
               (30, &[
                   &a_1_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..]),
               (90, &[
                   &a_1_fpr,
                   &b_0_fpr,
                   &b_1_fpr,
                   &c_0_fpr,
                   &c_1_fpr,
                   &d_0_fpr,
                   &d_1_fpr,
                   &e_0_fpr,
                   &f_0_fpr,
                   &target_fpr
               ][..])
           ][..],
           None);

        Ok(())
    }

    #[test]
    #[allow(unused)]
    fn roundabout() -> Result<()> {
        let p = &StandardPolicy::new();

        let alice_fpr: Fingerprint =
            "D8FA 1443 AE5A EAEB ACA3  0758 F697 6825 601D F253"
           .parse().expect("valid fingerprint");
        let alice_uid
            = UserID::from("<alice@example.org>");

        let bob_fpr: Fingerprint =
            "DDFB 2EBB DEC8 EC0F 0E15  094C 3F8E 9902 09D9 DA14"
           .parse().expect("valid fingerprint");
        let bob_uid
            = UserID::from("<bob@example.org>");
        // Certified by: C0C2 4473 EF73 5AFD DF3A  BB10 194A 7AD6 E115 92A9
        // Certified by: D8FA 1443 AE5A EAEB ACA3  0758 F697 6825 601D F253

        let carol_fpr: Fingerprint =
            "92BE 1C5C CD60 EC26 4184  6225 4593 B214 7E0F D8AF"
           .parse().expect("valid fingerprint");
        let carol_uid
            = UserID::from("<carol@example.org>");
        // Certified by: D8FA 1443 AE5A EAEB ACA3  0758 F697 6825 601D F253

        let dave_fpr: Fingerprint =
            "2127 3CCF A677 DC61 473A  9F7C B98A 97F2 093E FF40"
           .parse().expect("valid fingerprint");
        let dave_uid
            = UserID::from("<dave@example.org>");
        // Certified by: 92BE 1C5C CD60 EC26 4184  6225 4593 B214 7E0F D8AF

        let elmar_fpr: Fingerprint =
            "6114 73BE 9317 2816 E50D  401C F578 FEC6 558D D36F"
           .parse().expect("valid fingerprint");
        let elmar_uid
            = UserID::from("<elmar@example.org>");
        // Certified by: 060C 6C3F 7487 DC74 F230  F136 D43B 93CA 66C9 C93E
        // Certified by: 2127 3CCF A677 DC61 473A  9F7C B98A 97F2 093E FF40

        let frank_fpr: Fingerprint =
            "C0C2 4473 EF73 5AFD DF3A  BB10 194A 7AD6 E115 92A9"
           .parse().expect("valid fingerprint");
        let frank_uid
            = UserID::from("<frank@example.org>");
        // Certified by: 6114 73BE 9317 2816 E50D  401C F578 FEC6 558D D36F

        let george_fpr: Fingerprint =
            "5FF7 7D77 7FF2 480E D56C  8F21 C7B3 B4FA B65C A92A"
           .parse().expect("valid fingerprint");
        let george_uid
            = UserID::from("<george@example.org>");
        // Certified by: 060C 6C3F 7487 DC74 F230  F136 D43B 93CA 66C9 C93E
        // Certified by: DDFB 2EBB DEC8 EC0F 0E15  094C 3F8E 9902 09D9 DA14

        let henry_fpr: Fingerprint =
            "6C5F 49CA 23A8 D00A 965F  1757 4756 CAE4 2ADD 4F02"
           .parse().expect("valid fingerprint");
        let henry_uid
            = UserID::from("<henry@example.org>");
        // Certified by: 5FF7 7D77 7FF2 480E D56C  8F21 C7B3 B4FA B65C A92A

        let isaac_fpr: Fingerprint =
            "2AA6 4722 489B B380 5582  4556 CADE CDD7 1FE6 A115"
           .parse().expect("valid fingerprint");
        let isaac_uid
            = UserID::from("<isaac@example.org>");
        // Certified by: 6C5F 49CA 23A8 D00A 965F  1757 4756 CAE4 2ADD 4F02

        let jenny_fpr: Fingerprint =
            "060C 6C3F 7487 DC74 F230  F136 D43B 93CA 66C9 C93E"
           .parse().expect("valid fingerprint");
        let jenny_uid
            = UserID::from("<jenny@example.org>");

        let certs: Vec<Cert> = CertParser::from_bytes(
            &crate::tests::wot("roundabout.pgp"))?
            .map(|c| c.expect("Valid certificate"))
            .collect();
        let n = Network::new(
            certs
                .iter()
                .filter_map(|c| c.with_policy(p, None).ok())
                .collect()
        )?;

        eprintln!("{:?}", n);

        let r = RootedNetwork::new(&n, &[ alice_fpr.clone() ]);

        sp(&r, &alice_fpr, &alice_uid.clone(),
           &[ (120, &[ &alice_fpr ][..]) ][..],
           None);

        sp(&r, &bob_fpr, &bob_uid.clone(),
           &[
               (60,
                &[ &alice_fpr, &bob_fpr ][..]
               ),
               (120,
                &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr,
                    &frank_fpr, &bob_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &carol_fpr, &carol_uid.clone(),
           &[ (120, &[ &alice_fpr, &carol_fpr ][..]) ][..],
           None);

        sp(&r, &dave_fpr, &dave_uid.clone(),
           &[ (120, &[ &alice_fpr, &carol_fpr, &dave_fpr ][..]) ][..],
           None);

        sp(&r, &elmar_fpr, &elmar_uid.clone(),
           &[ (120, &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr ][..]) ][..],
           None);

        sp(&r, &frank_fpr, &frank_uid.clone(),
           &[
               (120,
                &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr,
                    &frank_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &george_fpr, &george_uid.clone(),
           &[
               (60,
                &[ &alice_fpr, &bob_fpr, &george_fpr ][..]
               ),
               (60,
                &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr,
                    &frank_fpr, &bob_fpr, &george_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &henry_fpr, &henry_uid.clone(),
           &[
               (60,
                &[ &alice_fpr, &bob_fpr, &george_fpr, &henry_fpr ][..]
               ),
               (60,
                &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr,
                    &frank_fpr, &bob_fpr, &george_fpr, &henry_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &isaac_fpr, &isaac_uid.clone(),
           &[
               (60,
                &[ &alice_fpr, &bob_fpr, &george_fpr, &henry_fpr, &isaac_fpr ][..]
               ),
           ][..],
           None);

        sp(&r, &jenny_fpr, &jenny_uid.clone(),
           &[ ][..],
           None);



        let r = RootedNetwork::new(&n, &[ jenny_fpr.clone() ]);

        sp(&r, &alice_fpr, &alice_uid.clone(),
           &[][..],
           None);

        sp(&r, &bob_fpr, &bob_uid.clone(),
           &[
               (100,
                &[ &jenny_fpr, &elmar_fpr, &frank_fpr, &bob_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &carol_fpr, &carol_uid.clone(),
           &[][..],
           None);

        sp(&r, &dave_fpr, &dave_uid.clone(),
           &[][..],
           None);

        sp(&r, &elmar_fpr, &elmar_uid.clone(),
           &[
               (100,
                &[ &jenny_fpr, &elmar_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &frank_fpr, &frank_uid.clone(),
           &[
               (100,
                &[ &jenny_fpr, &elmar_fpr, &frank_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &george_fpr, &george_uid.clone(),
           &[
               (100,
                &[ &jenny_fpr, &george_fpr ][..]
               ),
               (100,
                &[ &jenny_fpr, &elmar_fpr, &frank_fpr, &bob_fpr, &george_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &henry_fpr, &henry_uid.clone(),
           &[
               (100,
                &[ &jenny_fpr, &george_fpr, &henry_fpr ][..]
               ),
               (20,
                &[ &jenny_fpr, &elmar_fpr, &frank_fpr, &bob_fpr, &george_fpr, &henry_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &isaac_fpr, &isaac_uid.clone(),
           &[][..],
           None);

        sp(&r, &jenny_fpr, &jenny_uid.clone(),
           &[ (120, &[ &jenny_fpr ][..]) ][..],
           None);



        let r = RootedNetwork::new(&n, &[ alice_fpr.clone(), jenny_fpr.clone() ]);

        sp(&r, &alice_fpr, &alice_uid.clone(),
           &[ (120, &[ &alice_fpr ][..]) ][..],
           None);

        // Use a high target trust to make sure we don't find J -> E
        // -> F -> B (E -> F -> B was already used by A -> C -> D -> E
        // -> F -> B).
        sp(&r, &bob_fpr, &bob_uid.clone(),
           &[
               (60,
                &[ &alice_fpr, &bob_fpr ][..]
                ),
               (120,
                &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr,
                    &frank_fpr, &bob_fpr ][..]
                ),
           ][..],
           Some(240));

        sp(&r, &carol_fpr, &carol_uid.clone(),
           &[ (120, &[ &alice_fpr, &carol_fpr ][..]) ][..],
           None);

        sp(&r, &dave_fpr, &dave_uid.clone(),
           &[ (120, &[ &alice_fpr, &carol_fpr, &dave_fpr ][..]) ][..],
           None);

        sp(&r, &elmar_fpr, &elmar_uid.clone(),
           &[
               (100,
                &[ &jenny_fpr, &elmar_fpr ][..]
               ),
               (120,
                &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr ][..]
               ),
           ],
           None);

        sp(&r, &frank_fpr, &frank_uid.clone(),
           &[
               (100,
                &[ &jenny_fpr, &elmar_fpr, &frank_fpr ][..]
               ),
               (20,
                &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr,
                    &frank_fpr ][..]
               ),
           ][..],
           None);

        sp(&r, &george_fpr, &george_uid.clone(),
           &[
               (60,
                &[ &alice_fpr, &bob_fpr, &george_fpr ][..]
               ),
               (100,
                &[ &jenny_fpr, &george_fpr ][..]
               ),
               (60,
                &[ &jenny_fpr, &elmar_fpr, &frank_fpr, &bob_fpr, &george_fpr ][..]
               ),
           ][..],
           Some(240));

        sp(&r, &henry_fpr, &henry_uid.clone(),
           &[
               (60,
                &[ &alice_fpr, &bob_fpr, &george_fpr, &henry_fpr ][..]
               ),
               (60,
                &[ &jenny_fpr, &george_fpr, &henry_fpr ][..]
               ),
           ][..],
           None);

        sp(&r, &isaac_fpr, &isaac_uid.clone(),
           &[
               (60,
                &[ &alice_fpr, &bob_fpr, &george_fpr, &henry_fpr, &isaac_fpr ][..]
               ),
           ][..],
           None);

        sp(&r, &jenny_fpr, &jenny_uid.clone(),
           &[ (120, &[ &jenny_fpr ][..]) ][..],
           None);


        Ok(())
    }


    #[test]
    #[allow(unused)]
    fn local_optima() -> Result<()> {
        let p = &StandardPolicy::new();

        let alice_fpr: Fingerprint =
            "82AD 4D60 D2DE E052 822A  396B A2A0 1212 B15F 5A08"
           .parse().expect("valid fingerprint");
        let alice_uid
            = UserID::from("<alice@example.org>");

        let bob_fpr: Fingerprint =
            "372D 56EA 867E 5664 0FAD  27F7 C575 249E 41A4 0BA6"
           .parse().expect("valid fingerprint");
        let bob_uid
            = UserID::from("<bob@example.org>");
        // Certified by: 82AD 4D60 D2DE E052 822A  396B A2A0 1212 B15F 5A08

        let carol_fpr: Fingerprint =
            "A6C2 17C6 4A56 20EE 6E3F  A740 87A8 96F1 D1F0 C1A1"
           .parse().expect("valid fingerprint");
        let carol_uid
            = UserID::from("<carol@example.org>");
        // Certified by: 372D 56EA 867E 5664 0FAD  27F7 C575 249E 41A4 0BA6

        let dave_fpr: Fingerprint =
            "24B9 4613 8842 0D7E 6B01  54C9 BF69 DA6A 0D1E E8B5"
           .parse().expect("valid fingerprint");
        let dave_uid
            = UserID::from("<dave@example.org>");
        // Certified by: 372D 56EA 867E 5664 0FAD  27F7 C575 249E 41A4 0BA6

        let ellen_fpr: Fingerprint =
            "3020 279A 2F06 13B5 2C6B  A2B8 E2EB CBF5 148E 705E"
           .parse().expect("valid fingerprint");
        let ellen_uid
            = UserID::from("<ellen@example.org>");
        // Certified by: 24B9 4613 8842 0D7E 6B01  54C9 BF69 DA6A 0D1E E8B5
        // Certified by: A6C2 17C6 4A56 20EE 6E3F  A740 87A8 96F1 D1F0 C1A1

        let francis_fpr: Fingerprint =
            "F8D3 D4B7 A47C 4849 72FA  BAF2 3CCF BE20 0D58 6F5B"
           .parse().expect("valid fingerprint");
        let francis_uid
            = UserID::from("<francis@example.org>");
        // Certified by: 3020 279A 2F06 13B5 2C6B  A2B8 E2EB CBF5 148E 705E
        // Certified by: 372D 56EA 867E 5664 0FAD  27F7 C575 249E 41A4 0BA6

        let georgina_fpr: Fingerprint =
            "15AA 8DAA 32F2 89FC DF3E  7E17 6224 FF4F AAE1 0456"
           .parse().expect("valid fingerprint");
        let georgina_uid
            = UserID::from("<georgina@example.org>");
        // Certified by: 3020 279A 2F06 13B5 2C6B  A2B8 E2EB CBF5 148E 705E

        let henry_fpr: Fingerprint =
            "34B9 4D88 5D44 C52B 4C5D  803C A093 79AE 26D1 22F3"
           .parse().expect("valid fingerprint");
        let henry_uid
            = UserID::from("<henry@example.org>");
        // Certified by: 3020 279A 2F06 13B5 2C6B  A2B8 E2EB CBF5 148E 705E


        let certs: Vec<Cert> = CertParser::from_bytes(
            &crate::tests::wot("local-optima.pgp"))?
            .map(|c| c.expect("Valid certificate"))
            .collect();
        let n = Network::new(
            certs
                .iter()
                .filter_map(|c| c.with_policy(p, None).ok())
                .collect()
        )?;

        eprintln!("{:?}", n);

        let r = RootedNetwork::new(&n, &[ alice_fpr.clone() ]);

        sp(&r, &alice_fpr, &alice_uid.clone(),
           &[ (120, &[ &alice_fpr ][..]) ][..],
           None);

        sp(&r, &bob_fpr, &bob_uid.clone(),
           &[
               (120,
                &[ &alice_fpr, &bob_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &carol_fpr, &carol_uid.clone(),
           &[
               (100,
                &[ &alice_fpr, &bob_fpr, &carol_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &dave_fpr, &dave_uid.clone(),
           &[
               (50,
                &[ &alice_fpr, &bob_fpr, &dave_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &ellen_fpr, &ellen_uid.clone(),
           &[
               (50,
                &[ &alice_fpr, &bob_fpr, &dave_fpr, &ellen_fpr ][..]
               ),
               (70,
                &[ &alice_fpr, &bob_fpr, &carol_fpr, &ellen_fpr ][..]
               ),
           ][..],
           None);

        sp(&r, &francis_fpr, &francis_uid.clone(),
           &[
               (75,
                &[ &alice_fpr, &bob_fpr, &francis_fpr ][..]
               ),
               (45,
                &[ &alice_fpr, &bob_fpr, &carol_fpr, &ellen_fpr, &francis_fpr ][..]
               ),
           ][..],
           None);

        sp(&r, &georgina_fpr, &georgina_uid.clone(),
           &[
               (30,
                &[ &alice_fpr, &bob_fpr, &dave_fpr, &ellen_fpr, &georgina_fpr ][..]
               ),
           ][..],
           None);

        sp(&r, &henry_fpr, &henry_uid.clone(),
           &[
               (50,
                &[ &alice_fpr, &bob_fpr, &dave_fpr, &ellen_fpr, &henry_fpr ][..]
               ),
               (70,
                &[ &alice_fpr, &bob_fpr, &carol_fpr, &ellen_fpr, &henry_fpr ][..]
               ),
           ][..],
           None);

        let r = RootedNetwork::new(&n, &[ bob_fpr.clone() ]);

        sp(&r, &alice_fpr, &alice_uid.clone(),
           &[][..],
           None);

        sp(&r, &bob_fpr, &bob_uid.clone(),
           &[ (120, &[ &bob_fpr ][..]) ][..],
           None);

        sp(&r, &carol_fpr, &carol_uid.clone(),
           &[
               (100,
                &[ &bob_fpr, &carol_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &dave_fpr, &dave_uid.clone(),
           &[
               (50,
                &[ &bob_fpr, &dave_fpr ][..]
               )
           ][..],
           None);

        sp(&r, &ellen_fpr, &ellen_uid.clone(),
           &[
               (50,
                &[ &bob_fpr, &dave_fpr, &ellen_fpr ][..]
               ),
               (100,
                &[ &bob_fpr, &carol_fpr, &ellen_fpr ][..]
               ),
           ][..],
           None);

        sp(&r, &francis_fpr, &francis_uid.clone(),
           &[
               (75,
                &[ &bob_fpr, &francis_fpr ][..]
               ),
               (100,
                &[ &bob_fpr, &carol_fpr, &ellen_fpr, &francis_fpr ][..]
                ),
               (20,
                &[ &bob_fpr, &dave_fpr, &ellen_fpr, &francis_fpr ][..]
               ),
           ][..],
           Some(240));

        Ok(())
    }

    // #[test]
    // fn debian() -> Result<()> {
    //     let p = &StandardPolicy::new();
    // 
    //     let certs: Vec<Cert> = CertParser::from_file(
    //         "/usr/share/keyrings/debian-keyring.gpg")?
    //         // Skip invalid certificates.
    //         .filter_map(|c| c.ok())
    //         .collect();
    //     let n = Network::new(
    //         certs
    //             .iter()
    //             .filter_map(|c| c.with_policy(p, None).ok())
    //             .collect()
    //     )?;
    // 
    //     let clint_fpr: Fingerprint
    //         = "2100 A32C 46F8 95AF 3A08  783A F6D3 495B B0AE 9A02"
    //         .parse().expect("valid fingerprint");
    // 
    //     let dkg_fpr: Fingerprint
    //         = "C4BC 2DDB 38CC E964 85EB  E9C2 F206 9117 9038 E5C6"
    //         .parse().expect("valid fingerprint");
    //     // Clint has signed both of these keys.
    //     let dkg_fifthhorseman
    //         = UserID::from("Daniel Kahn Gillmor <dkg@fifthhorseman.net>");
    //     let _dkg_debian
    //         = UserID::from("Daniel Kahn Gillmor <dkg@debian.org>");
    // 
    //     sp(&n, &dkg_fpr, &dkg_fpr, &dkg_fifthhorseman,
    //        &[
    //            &dkg_fpr,
    //        ][..],
    //        Some(120));
    //     sp(&n, &clint_fpr, &dkg_fpr, &dkg_fifthhorseman,
    //        &[
    //            &clint_fpr,
    //            &dkg_fpr
    //        ][..],
    //        Some(120));
    // 
    //     Ok(())
    // }
}
