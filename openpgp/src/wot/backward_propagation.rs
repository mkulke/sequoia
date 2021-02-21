use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;

use crate::Fingerprint;
use crate::packet::prelude::*;

use super::Certification;
use super::CertificationSet;
use super::Network;
use super::Path;
use super::PriorityQueue;
use super::TRACE;

#[derive(Debug, Eq, Clone)]
struct Cost {
    // The required depth (i.e., the number of hops to the
    // target).  *Less* is better.
    depth: usize,

    // The trust amount along this path.  More is better.
    amount: usize,
}

impl Ord for Cost {
    fn cmp(&self, other: &Self) -> Ordering {
        self.depth.cmp(&other.depth).reverse()
            .then(self.amount.cmp(&self.amount))
    }
}

impl PartialOrd for Cost {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Cost {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

// We now do our relaxtion thing in reverse: from the target
// towards the roots.
#[derive(Clone)]
struct ForwardPointer<'a> {
    // If None, then the target.
    next: Option<Certification<'a>>,
}

impl<'a> fmt::Debug for ForwardPointer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("ForwardPointer");
        let x = if let Some(ref c) = self.next {
            x.field("next",
                    &(c.issuer_cert.fingerprint().to_string(),
                      c.issuer_cert.primary_userid().map(|ua| {
                          String::from_utf8_lossy(ua.userid().value()).into_owned()
                      })
                      .unwrap_or("<Missing User ID>".into())))
        } else {
            x.field("next", &"target")
        };
        x.finish()
    }
}

pub(super) trait CertificationFilter {
    // depth, amount, whether to use the embedded regex (true) or
    // ignore it (false).
    fn cost(&self, c: &Certification) -> (u8, u8, bool) {
        (c.depth, c.amount, true)
    }
}

pub(super) struct IdempotentCertificationFilter {
}

impl IdempotentCertificationFilter {
    pub fn new() -> Self {
        Self {}
    }
}

impl CertificationFilter for IdempotentCertificationFilter {}

pub(super) struct SuppressCertificationFilter {
    // A certification's trust amount will be supressed by this
    // amount.
    amount: HashMap<(Fingerprint, Fingerprint), u8>,
}

impl CertificationFilter for SuppressCertificationFilter {
    fn cost(&self, c: &Certification) -> (u8, u8, bool) {
        tracer!(TRACE, "SuppressCertificationFilter::cost", 0);
        if let Some(&delta) = self.amount.get(&(c.issuer_cert.fingerprint(),
                                                c.target_cert.fingerprint()))
        {
            // Be careful to now underflow.
            let amount = std::cmp::max(c.amount, delta) - delta;
            t!("Suppressing trust amount: {} -> {}", c.amount, amount);
            (c.depth, amount, true)
        } else {
            (c.depth, c.amount, true)
        }
    }
}

impl SuppressCertificationFilter {
    pub fn new() -> Self {
        Self {
            amount: HashMap::new(),
        }
    }

    /// Add supression rules for all certifications along the specified
    /// path.
    ///
    /// Each edge is supressed by amount.
    pub fn suppress_path(&mut self, path: &Path, amount_to_suppress: u8) {
        assert!(0 < amount_to_suppress);
        assert!(amount_to_suppress <= 120);

        for c in path.certifications() {
            match self.amount.entry((c.issuer_cert.fingerprint(),
                                     c.target_cert.fingerprint())) {
                Entry::Occupied(mut oe) => {
                    let amount = oe.get_mut();
                    *amount += amount_to_suppress;
                    assert!(*amount <= 120);
                }
                e @ Entry::Vacant(_) => {
                    e.or_insert(amount_to_suppress);
                }
            }
        }
    }
}

impl<'a> Network<'a> {
    /// Performs backward propagation from a binding towards a set of
    /// roots.
    ///
    /// If there is a path in the network from the root to the target,
    /// this algorithm will find it.  However, because it prefers
    /// shorter paths to longer paths, the path may not be optimal in
    /// terms of the amount of trust.
    ///
    /// # Return Value
    ///
    /// This function returns a hash from certificate fingerprints to
    /// paths to the target.  The has does not only include paths from
    /// the roots; it also includes paths from interior nodes.  This
    /// information can be combined with the results of a forward
    /// propagation (or some other heuristic) to find better
    /// authentication paths.
    ///
    /// # Algorithm
    ///
    /// This algorithm essentially reverses the edges in the network
    /// and then performs a Dijkstra from the target towards the
    /// roots.  When visiting a certificate (X), it considers each
    /// certifications on it (A-X, B-X, ...).  If the a certification
    /// (A-X, B-X, ...) is valid for the certificate's (X's) current
    /// path (X ... Target), and it (A-X) is better than the issuer's
    /// existing forward pointer (A-Y), than the issuer's (A's)
    /// forward pointer is updated to reference X.
    ///
    /// A certification is valid if it has any regular expressions and
    /// they match the target User ID.  Further, the certification's
    /// depth must be sufficient for the current path.  Finally, if a
    /// certification certifies the target, then it must certify the
    /// target for the requested User ID.
    ///
    /// When comparing two forward pointers, the one with the shorter
    /// path is preferred.  If the two forward pointers have the same
    /// trust amount, then the one with larger trust amount is
    /// preferred.
    ///
    /// # Example
    ///
    /// Consider the following network:
    ///
    /// ```text
    ///                                   255/120
    ///                                 C         D
    ///                               _ o ------> o
    ///                      255/120  /|            \  0/120
    ///                              /              _\|
    /// Root ...> o --------------> o --------------> o
    ///           A     2/100       B      0/30       E
    /// ```
    ///
    /// The tuples stand for the trust depth and the amount of trust.
    /// So in 255/120, 255 stands for the trust depth, and 120 stands
    /// for the trust amount.  (In this case, both are maximal.)
    ///
    /// Let us assume that we want to authenticate E and Root is our
    /// only trust root.  Using backward propagation, we start at the
    /// target, E, and consider each certification made on E: D-E and
    /// B-E.
    ///
    /// Say we start with D-E (the order doesn't matter).  Since D
    /// doesn't yet have a forward pointer, we set its forward pointer
    /// to E and add it (D) to the queue.  Then we consider B-E.
    /// Since B doesn't yet have a forward pointer, we set its forward
    /// pointer to E, and we add it (B) to the queue.
    ///
    /// ```text
    /// queue = [ D, B ];
    /// forward_pointers = [ (B -> E), (D -> E) ];
    /// ```
    ///
    /// Next we pop an element from the queue.  Because B and D's
    /// provisional paths are the same length (1), we compare the
    /// amount of trust along each path.  D's amount of trust is 120
    /// whereas B's is only 30.  So, we pop D.
    ///
    /// D is only certified by C.  Looking at C, we see that it
    /// doesn't yet have a forward pointer so we set its forward
    /// pointer to D, and we add C to the queue.
    ///
    /// ```text
    /// queue = [ B, C ];
    /// forward_pointers = [ (B -> E), (C -> D), (D -> E) ];
    /// ```
    ///
    /// The queue now contains B and C.  We prefer B, because its path
    /// length is shorter (1 vs 2).  B is certified by A.  Since A's
    /// forward pointer is empty, we set it to point to B.
    ///
    /// ```text
    /// queue = [ C, A ];
    /// forward_pointers = [ (A -> B), (B -> E), (C-> D), (D -> E) ];
    /// ```
    ///
    /// We now pop C from the queue: the current paths starting at B
    /// and C have the same path length, but the trust amount for the
    /// current path starting at C is larger (120 vs 100).
    ///
    /// C is certified by B.  We compare B's current forward pointer
    /// to C's certification of B.
    ///
    ///   B' forward pointer:        length: 1, amount: 30
    ///   B-C + C's forward pointer: length: 3, amount: 120
    ///
    /// We prefer the existing forward pointer because the path is
    /// shorter even though the amount of trust is less.  If we had
    /// taken the longer path, then any forward pointers pointing to B
    /// might become invalid.  This is, in fact, the case here: A-B
    /// has a trust depth of 2.  But to use B-C-D-E, A-B would need a
    /// trust depth of at least 3!
    ///
    /// Thus, because we never replace an existing forward pointer
    /// with a forward pointer for a longer path, all forward pointers
    /// remain---by construction---valid.
    ///
    /// # Arguments
    ///
    /// cost is a callback to extract the depth, amount and regex set
    /// from a certification.  To simple use the values in the
    /// certification return None using the callback: `|_| None`.
    pub(super) fn backward_propagate<CF>(&self,
                                         roots: &[ Fingerprint ],
                                         target_fpr: Fingerprint,
                                         target_userid: UserID,
                                         cf: &CF)
        -> HashMap<Fingerprint, (Path<'a>, usize)>
        where
           CF: CertificationFilter,
    {
        tracer!(TRACE, "Network::backward_propagate", 0);
        t!("Roots:\n{}",
           roots.iter().enumerate().map(|(i, fpr)| {
               if let Some(cert) = self.nodes.get(fpr) {
                   format!("  {}. {}, {}",
                           i, fpr,
                           cert.primary_userid()
                               .map(|ua| {
                                   String::from_utf8_lossy(
                                       ua.userid().value()).into_owned()
                               })
                               .unwrap_or("<no User ID>".to_owned()))
               } else {
                   format!("  {}. {} (not found)",
                           i, fpr)
               }
           })
           .collect::<Vec<_>>()
           .join("\n"));
        t!("target: {}, {}",
           target_fpr, String::from_utf8_lossy(target_userid.value()));
        t!("Have {} nodes, {} have made at least one certification.",
           self.nodes.len(), self.edges.len());

        // Sort and dedup roots (if necessary).
        let mut roots_;
        let roots = if roots.len() > 1 {
            roots_ = roots.to_vec();
            roots_.sort();
            roots_.dedup();
            &roots_
        } else {
            roots
        };

        // If fpr is a root.
        let is_root = |fpr: &Fingerprint| -> bool {
            roots.binary_search(fpr).is_ok()
        };


        // The trivial case: the target is a root or not in the network.
        if let Some(target) = self.nodes.get(&target_fpr) {
            if is_root(&target_fpr) {
                // Check whether target_userid is a self sig.
                if ! target.userids().any(|ua| ua.userid() == &target_userid) {
                    t!("{}: root does not contain target user id, ignoring.",
                       target_fpr);
                    return HashMap::new();
                } else {
                    let mut auth_rpaths: HashMap<Fingerprint, (Path, usize)>
                        = HashMap::new();
                    auth_rpaths.insert(
                        target_fpr, (Path::new(target.clone()), 120));
                    return auth_rpaths;
                }
            }
        } else {
            t!("Target not in network.");
            return HashMap::new();
        }


        // Dijkstra.

        // The key is the issuer.
        let mut distance: HashMap<Fingerprint, ForwardPointer> = HashMap::new();
        let mut queue: PriorityQueue<Fingerprint, Cost>
            = PriorityQueue::new();

        // This is a macro, because lifetimes :/.
        macro_rules! fp_cost {
            ($fp:expr) => ({
                let mut fp: &ForwardPointer = $fp;
                let mut amount = 120;
                let mut depth = 0;

                while let Some(ref c) = fp.next {
                    let (_, c_amount, _) = cf.cost(c);
                    amount = std::cmp::min(c_amount, amount);
                    depth += 1;
                    fp = distance.get(&c.target_cert.fingerprint()).unwrap();
                }

                Cost {
                    amount: amount as usize,
                    depth: depth as usize,
                }
            });
        }

        let cost = Cost { depth: 0, amount: 120 };
        queue.push(target_fpr.clone(), cost);
        distance.insert(
            target_fpr.clone(),
            ForwardPointer {
                next: None,
            });

        // Iterate over each node in the priority queue.
        while let Some((signee_fpr, _)) = queue.pop() {
            // Get all the bindings that signed cert.
            let certification_sets: &Vec<CertificationSet<'a>>
                = if let Some(cs) = self.redges.get(&signee_fpr) {
                    cs
                } else {
                    // Nothing certified it.  The path is a dead end.
                    t!("{} was not certified, dead end", signee_fpr);
                    continue;
                };

            t!("Visiting <{}, {}>, certified {} times",
               signee_fpr,
               self.nodes.get(&signee_fpr).expect("valid")
                   .primary_userid()
                   .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
               .unwrap_or("<no User ID>".to_owned()),
               certification_sets.len());

            // Get the cert's current forward pointer.
            //
            // We need to clone this, because we want to manipulate
            // 'distance' and we can't do that if there is a reference
            // to something in it.
            let fp: ForwardPointer
                = distance.get(&signee_fpr).expect("was queued").clone();
            let fp_cost = fp_cost!(&fp);

            t!("forward pointer: {:?}", fp);

            for (&_userid, certification)
                in certification_sets.iter()
                    // Skip paths via the roots.  They make no sense.
                    .filter_map(|cs| {
                        if is_root(&cs.target_cert.fingerprint()) {
                            None
                        } else {
                            Some(cs)
                        }
                    })
                    .flat_map(|cs| cs.certifications.iter())
            {
                let issuer_fpr = certification.issuer_cert.fingerprint();

                let (certification_depth,
                     certification_amount,
                     certification_use_re) = cf.cost(certification);

                t!("  Considering certification by: \
                    <{}, {}>, depth: {} (of {}), amount: {} (of {}), regexes: {:?}",
                   certification.issuer_cert.keyid(),
                   certification.issuer_cert
                       .primary_userid()
                       .map(|ua| {
                           String::from_utf8_lossy(ua.userid().value())
                               .into_owned()
                       })
                       .unwrap_or("<no User ID>".to_owned()),
                   certification_depth,
                   certification.depth,
                   certification_amount,
                   certification.amount,
                   if certification_use_re || certification.re_set.matches_everything()
                       { "*".into() }
                   else
                       { format!("{:?}", certification.re_set) });

                if certification_amount == 0 {
                    t!("    Certification amount is 0, skipping");
                    continue;
                }

                if signee_fpr == target_fpr
                    && certification.target_userid != &target_userid
                {
                    t!("    Certification certifies target, but for the wrong \
                        user id (want: {}, got: {})",
                       String::from_utf8_lossy(target_userid.value()),
                       String::from_utf8_lossy(certification.target_userid.value()));
                    continue;
                }

                if (certification_depth as usize) < fp_cost.depth {
                    t!("    Certification does not have enough depth \
                        ({}, needed: {}), skipping",
                       certification_depth, fp_cost.depth);
                    continue;
                }

                if certification_use_re
                    && ! certification.re_set.matches_userid(&target_userid)
                {
                    t!("  Certification's re does not match target userid, skipping.");
                    continue;
                }

                let proposed_fp: ForwardPointer<'a>  = ForwardPointer {
                    next: Some(certification.clone()),
                };
                let proposed_fp_cost = Cost {
                    depth: fp_cost.depth + 1,
                    amount: std::cmp::min(
                        certification_amount as usize,
                        fp_cost.amount),
                };

                t!("    Proposed forward pointer: {:?}", proposed_fp);

                // distance.entry takes a mutable ref, so we can't
                // compute the current fp's cost there.
                let current_fp_cost = if let Some(current_fp)
                    = distance.get(&issuer_fpr.clone())
                {
                    Some(fp_cost!(&current_fp))
                } else {
                    None
                };

                match distance.entry(issuer_fpr.clone()) {
                    Entry::Occupied(mut oe) => {
                        let current_fp_cost = current_fp_cost.unwrap();
                        let current_fp = oe.get_mut();

                        t!("    Current forward pointer: {:?}", current_fp);

                        // We prefer a shorter path (in terms of
                        // edges) as this allows us to reach more of
                        // the graph.
                        //
                        // If the path length is equal, we prefer the
                        // larger amount of trust.

                        if proposed_fp_cost.depth < current_fp_cost.depth {
                            if proposed_fp_cost.amount < current_fp_cost.amount {
                                // We have two local optima: one
                                // has a shorter path, the other a
                                // higher trust amount.  We prefer
                                // the shorter path, and mark this
                                // node as being a local optimum.
                                t!("    Shorter path, but worse amount of trust");
                                oe.insert(proposed_fp);
                            } else {
                                // Proposed bp is strictly better.
                                t!("    Shorter path and better amount of trust");
                                oe.insert(proposed_fp);
                            }
                        } else if proposed_fp_cost.depth == current_fp_cost.depth
                            && proposed_fp_cost.amount > current_fp_cost.amount
                        {
                            // Strictly better.
                            t!("    Same path length, better amount");
                            oe.insert(proposed_fp);
                        } else if proposed_fp_cost.depth > current_fp_cost.depth
                            && proposed_fp_cost.amount > current_fp_cost.amount
                        {
                            // There's another possible path through here.
                            t!("    More trust, but longer path");
                        } else {
                            t!("    Current fp is strictly better");
                        }
                    }
                    e @ Entry::Vacant(_) => {
                        // We haven't see it before.
                        t!("  Discovered {}, {}", issuer_fpr,
                           self.nodes.get(&issuer_fpr).expect("valid")
                               .primary_userid()
                               .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                               .unwrap_or("<no User ID>".to_owned()));
                        if is_root(&issuer_fpr) {
                            t!("    Not queuing, root.");
                        } else {
                            t!("    Queuing");
                            queue.push(issuer_fpr, proposed_fp_cost);
                        }
                        e.or_insert(proposed_fp);
                    }
                }
            }
        }


        // Follow the forward pointers and reconstruct the paths.
        let mut auth_rpaths: HashMap<Fingerprint, (Path, usize)>
            = HashMap::new();

        for (issuer_fpr, mut fp) in distance.iter() {
            let issuer = if let Some(ref c) = fp.next {
                &c.issuer_cert
            } else {
                self.nodes.get(&issuer_fpr).expect("exists")
            };

            t!("Recovering path starting at {}, {}",
               issuer_fpr,
               issuer.primary_userid()
                   .map(|ua| {
                       String::from_utf8_lossy(ua.userid().value()).into_owned()
                   })
                   .unwrap_or("<no User ID>".to_owned()));

            let mut amount = 120;

            // nodes[0] is the root; nodes[nodes.len() - 1] is the target.
            let mut nodes: Vec<Certification<'a>> = Vec::new();
            while let Some(ref c) = fp.next {
                t!("  {:?}", fp);
                let (_, c_amount, _) = cf.cost(c);
                amount = std::cmp::min(c_amount, amount);

                nodes.push(c.clone());
                fp = distance.get(&c.target_cert.fingerprint())
                    .expect("exists");
            }
            t!("  {:?}", fp);

            t!("\nShortest path from {}, {}:\n  {}\n  Target: {}, {}",
               issuer_fpr,
               issuer.primary_userid()
                   .map(|ua| {
                       String::from_utf8_lossy(ua.userid().value()).into_owned()
                   })
                   .unwrap_or("<no User ID>".to_owned()),
               nodes.iter()
                   .enumerate()
                   .map(|(i, n)| {
                       format!("{}: {:?}", i, n)
                   })
                  .collect::<Vec<_>>()
                  .join("\n  "),
               target_fpr,
               target_userid);

            if nodes.len() == 0 {
                // We've got a root.  Make sure that it has a self
                // signature with the required User ID.
                if ! issuer.userids().any(|ua| ua.userid() == &target_userid) {
                    t!("{}: root does not contain target user id, ignoring.",
                       target_fpr);
                    continue;
                }
            }

            let mut p = Path::new(issuer.clone());
            for n in nodes.iter() {
                p.try_append(n.clone()).expect("valid path");
            }

            t!("Authenticated <{}, {}>: {:?}",
               target_fpr, target_userid, p);

            auth_rpaths.insert(issuer_fpr.clone(), (p, amount as usize));
        }

        if TRACE {
            t!("auth_rpaths:");
            let mut v: Vec<_> = auth_rpaths.iter().collect();
            v.sort_by(|(fpr_a, _), (fpr_b, _)| {
                let userid_a = self.nodes.get(fpr_a).unwrap()
                    .primary_userid().map(|ua| String::from_utf8_lossy(ua.userid().value())).unwrap_or("".into());
                let userid_b = self.nodes.get(fpr_b).unwrap()
                    .primary_userid().map(|ua| String::from_utf8_lossy(ua.userid().value())).unwrap_or("".into());

                userid_a.cmp(&userid_b).
                    then(fpr_a.cmp(&fpr_b))
            });
            for (fpr, (path, amount)) in v {
                let userid = self.nodes.get(fpr).unwrap()
                    .primary_userid().map(|ua| {
                        String::from_utf8_lossy(ua.userid().value())
                    })
                    .unwrap_or("<missing User ID>".into());
                t!("  <{}, {}>: {}",
                   fpr, userid,
                   format!("{} trust amount (max: {}), {} edges",
                           amount, path.amount(),
                           path.len() - 1));
            }
        }

        auth_rpaths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Result;
    use crate::cert::prelude::*;
    use crate::parse::Parse;
    use crate::policy::StandardPolicy;

    fn pcmp(v: &(Path, usize), residual_depth: usize, amount: usize,
            certs: &[ &Fingerprint ])
    {
        let (got_path, got_amount) = v;
        let got_certs: Vec<Fingerprint>
            = got_path.certificates().map(|c| c.fingerprint()).collect();

        if got_certs.len() != certs.len()
            || got_certs.iter().zip(certs.iter()).any(|(a, b)| &a != b)
        {
            panic!("Paths don't match.  {}Got path:\n {:?}, expected:\n {}",
                   if got_certs.len() != certs.len() {
                       format!("Got {} certs, expected {}.  ",
                               got_certs.len(), certs.len())
                   } else {
                       "".into()
                   },
                   got_path,
                   certs.iter().enumerate()
                       .map(|(i, f)| format!("  {}. {}", i, f))
                       .collect::<Vec<String>>()
                       .join("\n "));
        }

        assert_eq!(*got_amount, amount, "amount");
        assert_eq!(got_path.residual_depth(), residual_depth, "residual amount");
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

        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        ellen_fpr.clone(),
                                        ellen_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        pcmp(auth.get(&ellen_fpr).unwrap(),
             usize::MAX, 120,
             &[ &ellen_fpr ]);
        pcmp(auth.get(&dave_fpr).unwrap(),
             1, 100,
             &[ &dave_fpr, &ellen_fpr ]);
        pcmp(auth.get(&carol_fpr).unwrap(),
             0, 100,
             &[ &carol_fpr, &dave_fpr, &ellen_fpr ]);

        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        dave_fpr.clone(),
                                        dave_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        assert!(&auth.get(&ellen_fpr).is_none());
        pcmp(&auth.get(&dave_fpr).unwrap(),
             usize::MAX, 120,
             &[ &dave_fpr ]);
        pcmp(&auth.get(&carol_fpr).unwrap(),
             1, 100,
             &[ &carol_fpr, &dave_fpr ]);
        pcmp(&auth.get(&bob_fpr).unwrap(),
             0, 100,
             &[ &bob_fpr, &carol_fpr, &dave_fpr ]);
        pcmp(&auth.get(&alice_fpr).unwrap(),
             0, 100,
             &[ &alice_fpr, &bob_fpr, &carol_fpr, &dave_fpr ]);

        let auth = n.backward_propagate(&[ bob_fpr.clone() ],
                                        dave_fpr.clone(),
                                        dave_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        assert!(&auth.get(&ellen_fpr).is_none());
        pcmp(&auth.get(&dave_fpr).unwrap(),
             usize::MAX, 120,
             &[ &dave_fpr ]);
        pcmp(&auth.get(&carol_fpr).unwrap(),
             1, 100,
             &[ &carol_fpr, &dave_fpr ]);
        pcmp(&auth.get(&bob_fpr).unwrap(),
             0, 100,
             &[ &bob_fpr, &carol_fpr, &dave_fpr ]);
        // There is a path from Alice to Dave.  But, it is via a root
        // (Bob).  This is non-sense.  We are looking for paths from
        // the roots and valid suffixes.
        assert!(&auth.get(&alice_fpr).is_none());

        let auth = n.backward_propagate(&[ alice_fpr.clone(),
                                           carol_fpr.clone() ],
                                        dave_fpr.clone(),
                                        dave_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        assert!(&auth.get(&ellen_fpr).is_none());
        pcmp(&auth.get(&dave_fpr).unwrap(),
             usize::MAX, 120,
             &[ &dave_fpr ]);
        pcmp(&auth.get(&carol_fpr).unwrap(),
             1, 100,
             &[ &carol_fpr, &dave_fpr ]);
        // There are paths from Alice and Bob to Dave.  But, they are
        // Carol, a root (Bob).  This is non-sense.  We are looking
        // for paths from the roots and valid suffixes.
        assert!(&auth.get(&bob_fpr).is_none());
        assert!(&auth.get(&alice_fpr).is_none());


        // Try to authenticate dave's key for an User ID that no one
        // has certified.
        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        dave_fpr.clone(),
                                        ellen_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        assert!(&auth.get(&ellen_fpr).is_none());
        assert!(&auth.get(&dave_fpr).is_none());
        assert!(&auth.get(&carol_fpr).is_none());
        assert!(&auth.get(&bob_fpr).is_none());
        assert!(&auth.get(&alice_fpr).is_none());

        // Target is not in the network.
        let fpr: Fingerprint
            = "0123 4567 89AB CDEF  0123 4567 89AB CDEF".parse().expect("valid");
        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        fpr.clone(),
                                        ellen_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        assert!(&auth.get(&ellen_fpr).is_none());
        assert!(&auth.get(&dave_fpr).is_none());
        assert!(&auth.get(&carol_fpr).is_none());
        assert!(&auth.get(&bob_fpr).is_none());
        assert!(&auth.get(&alice_fpr).is_none());

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

        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        frank_fpr.clone(),
                                        frank_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        pcmp(&auth.get(&frank_fpr).unwrap(),
             usize::MAX, 120,
             &[ &frank_fpr ]);
        pcmp(&auth.get(&ed_fpr).unwrap(),
             0, 120,
             &[ &ed_fpr, &frank_fpr ]);
        pcmp(&auth.get(&dave_fpr).unwrap(),
             0, 30,
             &[ &dave_fpr, &ed_fpr, &frank_fpr ]);
        pcmp(&auth.get(&carol_fpr).unwrap(),
             0, 30,
             &[ &carol_fpr, &dave_fpr, &ed_fpr, &frank_fpr ]);
        pcmp(&auth.get(&bob_fpr).unwrap(),
             0, 30,
             &[ &bob_fpr, &carol_fpr, &dave_fpr, &ed_fpr, &frank_fpr ]);
        assert!(&auth.get(&alice_fpr).is_none());


        let auth = n.backward_propagate(&[ bob_fpr.clone() ],
                                        frank_fpr.clone(),
                                        frank_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        pcmp(&auth.get(&frank_fpr).unwrap(),
             usize::MAX, 120,
             &[ &frank_fpr ]);
        pcmp(&auth.get(&ed_fpr).unwrap(),
             0, 120,
             &[ &ed_fpr, &frank_fpr ]);
        pcmp(&auth.get(&dave_fpr).unwrap(),
             0, 30,
             &[ &dave_fpr, &ed_fpr, &frank_fpr ]);
        pcmp(&auth.get(&carol_fpr).unwrap(),
             0, 30,
             &[ &carol_fpr, &dave_fpr, &ed_fpr, &frank_fpr ]);
        pcmp(&auth.get(&bob_fpr).unwrap(),
             0, 30,
             &[ &bob_fpr, &carol_fpr, &dave_fpr, &ed_fpr, &frank_fpr ]);
        assert!(&auth.get(&alice_fpr).is_none());

        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        ed_fpr.clone(),
                                        ed_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        assert!(&auth.get(&frank_fpr).is_none());
        pcmp(&auth.get(&ed_fpr).unwrap(),
             usize::MAX, 120,
             &[ &ed_fpr ]);
        pcmp(&auth.get(&dave_fpr).unwrap(),
             1, 30,
             &[ &dave_fpr, &ed_fpr ]);
        pcmp(&auth.get(&carol_fpr).unwrap(),
             1, 30,
             &[ &carol_fpr, &dave_fpr, &ed_fpr ]);
        pcmp(&auth.get(&bob_fpr).unwrap(),
             1, 30,
             &[ &bob_fpr, &carol_fpr, &dave_fpr, &ed_fpr ]);
        pcmp(&auth.get(&alice_fpr).unwrap(),
             0, 30,
             &[ &alice_fpr, &bob_fpr, &carol_fpr, &dave_fpr, &ed_fpr ]);

        let auth = n.backward_propagate(&[ dave_fpr.clone() ],
                                        carol_fpr.clone(),
                                        carol_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        assert!(&auth.get(&frank_fpr).is_none());
        assert!(&auth.get(&ed_fpr).is_none());
        pcmp(&auth.get(&dave_fpr).unwrap(),
             254, 90,
             &[ &dave_fpr, &bob_fpr, &carol_fpr ]);
        pcmp(&auth.get(&carol_fpr).unwrap(),
             usize::MAX, 120,
             &[ &carol_fpr ]);
        pcmp(&auth.get(&bob_fpr).unwrap(),
             255, 90,
             &[ &bob_fpr, &carol_fpr ]);
        // The backward propagation algorithm doesn't know that alice
        // is not reachable from the root (dave).
        pcmp(&auth.get(&alice_fpr).unwrap(),
             2, 90,
             &[ &alice_fpr, &bob_fpr, &carol_fpr ]);

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

        let auth = n.backward_propagate(&[ root_fpr.clone() ],
                                        target_fpr.clone(),
                                        target_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        pcmp(&auth.get(&root_fpr).unwrap(),
             90, 120,
             &[
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
             ]);


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

        let auth = n.backward_propagate(&[ root_fpr.clone() ],
                                        target_fpr.clone(),
                                        target_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        pcmp(&auth.get(&root_fpr).unwrap(),
             93, 30,
             &[
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
             ]);

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

        let auth = n.backward_propagate(&[ root_fpr.clone() ],
                                        target_fpr.clone(),
                                        target_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        pcmp(&auth.get(&root_fpr).unwrap(),
             94, 30,
             &[
                 &root_fpr,
                 &b_0_fpr,
                 &b_1_fpr,
                 &c_1_fpr,
                 &d_0_fpr,
                 &d_1_fpr,
                 &e_0_fpr,
                 &f_0_fpr,
                 &target_fpr
             ]);

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
        // Certified by: 2127 3CCF A677 DC61 473A  9F7C B98A 97F2 093E FF40
        // Certified by: 060C 6C3F 7487 DC74 F230  F136 D43B 93CA 66C9 C93E

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
        // Certified by: DDFB 2EBB DEC8 EC0F 0E15  094C 3F8E 9902 09D9 DA14
        // Certified by: 060C 6C3F 7487 DC74 F230  F136 D43B 93CA 66C9 C93E

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

        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        isaac_fpr.clone(),
                                        isaac_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        pcmp(&auth.get(&alice_fpr).unwrap(),
             0, 60,
             &[ &alice_fpr, &bob_fpr, &george_fpr, &henry_fpr, &isaac_fpr ]);
        assert!(&auth.get(&carol_fpr).is_none());
        assert!(&auth.get(&jenny_fpr).is_none());


        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        henry_fpr.clone(),
                                        henry_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        // The backward propagation algorithm doesn't know that jenny
        // is not reachable from the root (alice).
        pcmp(&auth.get(&jenny_fpr).unwrap(),
             0, 100,
             &[ &jenny_fpr, &george_fpr, &henry_fpr ]);

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

        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        henry_fpr.clone(),
                                        henry_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        pcmp(auth.get(&alice_fpr).unwrap(),
             0, 100,
             &[ &alice_fpr, &bob_fpr, &carol_fpr, &ellen_fpr, &henry_fpr ]);
        pcmp(auth.get(&bob_fpr).unwrap(),
             0, 100,
             &[ &bob_fpr, &carol_fpr, &ellen_fpr, &henry_fpr ]);
        pcmp(auth.get(&carol_fpr).unwrap(),
             0, 100,
             &[ &carol_fpr, &ellen_fpr, &henry_fpr ]);
        pcmp(auth.get(&dave_fpr).unwrap(),
             0, 50,
             &[ &dave_fpr, &ellen_fpr, &henry_fpr ]);
        pcmp(auth.get(&ellen_fpr).unwrap(),
             0, 120,
             &[ &ellen_fpr, &henry_fpr ]);
        assert!(auth.get(&francis_fpr).is_none());
        assert!(auth.get(&georgina_fpr).is_none());
        pcmp(&auth.get(&henry_fpr).unwrap(),
             usize::MAX, 120,
             &[ &henry_fpr ]);

        let auth = n.backward_propagate(&[ alice_fpr.clone() ],
                                        francis_fpr.clone(),
                                        francis_uid.clone(),
                                        &IdempotentCertificationFilter::new());

        // Recall: given a choice, we prefer the forward pointer that
        // has the least depth.
        pcmp(auth.get(&alice_fpr).unwrap(),
             149, 75,
             &[ &alice_fpr, &bob_fpr, &francis_fpr ]);
        pcmp(auth.get(&bob_fpr).unwrap(),
             200, 75,
             &[ &bob_fpr, &francis_fpr ]);
        pcmp(auth.get(&carol_fpr).unwrap(),
             49, 100,
             &[ &carol_fpr, &ellen_fpr, &francis_fpr ]);
        pcmp(auth.get(&dave_fpr).unwrap(),
             99, 50,
             &[ &dave_fpr, &ellen_fpr, &francis_fpr ]);
        pcmp(auth.get(&ellen_fpr).unwrap(),
             100, 120,
             &[ &ellen_fpr, &francis_fpr ]);
        pcmp(&auth.get(&francis_fpr).unwrap(),
             usize::MAX, 120,
             &[ &francis_fpr ]);
        assert!(auth.get(&georgina_fpr).is_none());
        assert!(auth.get(&henry_fpr).is_none());

        Ok(())
    }
}
