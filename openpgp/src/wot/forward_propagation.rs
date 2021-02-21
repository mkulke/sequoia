use std::cmp::Ordering;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;

use crate::Fingerprint;

use super::Certification;
use super::CertificationSet;
use super::Network;
use super::Path;
use super::PriorityQueue;
use super::TRACE;

#[derive(Debug, Eq, Clone)]
struct Cost {
    // 0: This certificate is not a trusted introducer.
    // 1: Trusted introducer.
    // 2: Meta-trusted introducer[
    // etc.
    //
    // Higher is better.
    depth: usize,

    // The trust amount along this path.  Higher is better.
    amount: usize,
}

impl Ord for Cost {
    fn cmp(&self, other: &Self) -> Ordering {
        self.depth.cmp(&other.depth)
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

#[derive(Clone)]
struct BackPointer<'a> {
    // If None, then a root.
    prev: Option<Certification<'a>>,
}

impl<'a> fmt::Debug for BackPointer<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut x = f.debug_struct("BackPointer");
        let x = if let Some(ref c) = self.prev {
            x.field("prev",
                    &(c.issuer_cert.fingerprint().to_string(),
                      c.issuer_cert.primary_userid().map(|ua| {
                          String::from_utf8_lossy(ua.userid().value()).into_owned()
                      })
                      .unwrap_or("<Missing User ID>".into())))
        } else {
            x.field("prev", &"root")
        };
        x.finish()
    }
}

impl<'a> Network<'a> {
    // Computes an authentication network using forward propagation.
    //
    // Unfortunately, authenticating a binding in the WoT is NP
    // complete.  Although authenticating a binding appears to be an
    // isomorphism of the shortest path problem, which can be solved
    // using Dijkstra's algorithm, which runs in polynomial time, it
    // unfortunately is not.  The issue is that because an edge's
    // trust depth imposes non-local constraints, it violates a core
    // assumption of Dijkstra's algorithm.
    //
    // To understand why the WoT's trust depth is incompatible with
    // Dijkstra's algorithm, we first need to recall how Dijkstra's
    // algorithm works.  For each node in the network, Dijkstra's
    // algorithm initializes a distance and a back pointer.  It then
    // walks the graph.  As it examines each edge, it updates these
    // variables.  At the end of the algorithm, the shortest path to
    // each node is found by following the back pointers to the
    // source.  This works when the following holds: if A ... B -> C
    // is the shortest path from A to C, then A ... B is the shortest
    // path from A to B; if the shortest path from A to B were
    // actually A ...' B, then the shortest path from A to C would
    // instead be A ...' B -> C!
    //
    // In the WoT, the best path to B could every well be A ...' B
    // while the best path to C is A ... B -> C.  Consider the
    // following network:
    //
    //              A
    //            _ o
    //     3/60   /|  \  2/60
    //          /      _\| C    1/120      D     0/120      E
    //   Root o        _  o -------------> o -------------> o
    //          \       /|
    //    2/120  _\|  /   1/120
    //              o
    //              B
    //
    // "x/y" is a tuple corresponding to the certification's depth and
    // amount.
    //
    // In this network, we can authenticate D with full trust (amount
    // = 120) using the path:
    //
    //   Root -> B -> C -> D
    //
    // But to authenticate E, we have to use:
    //
    //   Root -> A -> C -> D -> E
    //
    // Root -> B -> C -> D -> E is not valid, becase B says that C can
    // be a trusted introducer of depth = 1, but we need B to be a
    // trusted introducer with a depth of at least 2 to authenticate E
    // along that path!
    //
    // ## Heuristic
    //
    // This function identifies best paths by making the following
    // simplifications:
    //
    //  - If a certification includes a regular expression, it is
    //    ignored.
    //
    //  - When comparing two certifications, the certificate with the
    //  larger depth is always preferred.
    //
    // Using these simplifications, we are able to use Dijkstra's
    // algorithm to authenticate nodes in the network.  These
    // simplifications mean that we may not identify some
    // authentication paths, or that paths that we identify are not
    // optimal.  However, we will never claim a path is authenticated
    // more than it actually is.  Further, the simplifications are
    // constructive in the sense that adding another certification to
    // the network will never result in node not being authenticated
    // (although the path found may be weaker).
    pub(super) fn forward_propagate(&self, roots: &[Fingerprint])
        -> HashMap<Fingerprint, Path>
    {
        tracer!(TRACE, "Network::forward_propagate", 0);
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
        t!("Have {} nodes, {} have made at least one certification.",
           self.nodes.len(), self.edges.len());

        // We're doing a Dijkstra, which works as follows.  There are
        // two main data structures:
        //
        //   - A max-priority queue, and
        //   - A vector of backpointers (one entry for each node).
        //
        // The roots are inserted into the priority queue, and their
        // distances set to 0.
        //
        // Then, while the priority queue is not empty, we remove the
        // node with the shortest path from the queue, and examine
        // each of its edges in turn:
        //
        //   - If the edge's target has not yet been considered
        //     (distance[target] is NULL), its distance is set to
        //     distance[node] + weight[edge] and it is added to the
        //     priority queue.
        //
        //   - Otherwise, if distance[source] + weight[edge] <
        //     distance[target], then target's backpoint is changed to
        //     source.
        //
        // At the end, the distance vector contains the shortest
        // distance from the root, and the path can be recovered by
        // following the back pointers.

        // The key is the issuer.
        let mut distance: HashMap<Fingerprint, BackPointer> = HashMap::new();
        let mut queue: PriorityQueue<Fingerprint, Cost>
            = PriorityQueue::new();

        // This is a macro, because lifetimes :/.
        macro_rules! bp_cost {
            ($bp:expr) => ({
                let mut bp: &BackPointer = $bp;
                let mut amount = 120;
                let mut depth = u8::MAX;

                t!("Computing cost:");

                let mut len = 0;
                while let Some(ref c) = bp.prev {
                    amount = std::cmp::min(c.amount, amount);
                    depth = std::cmp::min(c.depth - len, depth);
                    t!("  {}. Certification: {:?} => cost: {}, {}",
                       len, c, amount, depth);
                    bp = distance.get(&c.issuer_cert.fingerprint()).unwrap();
                    len += 1;
                }

                Cost {
                    amount: amount as usize,
                    depth: depth as usize,
                }
            });
        }


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

        for root_fpr in roots.iter() {
            if let Some(_) = self.nodes.get(root_fpr) {
                let cost = Cost { depth: usize::MAX, amount: 120 };
                queue.push(root_fpr.clone(), cost);
                distance.insert(
                    root_fpr.clone(),
                    BackPointer {
                        prev: None,
                    });
            } else {
                t!("Root {} not in network, ignoring.", root_fpr);
            }
        }


        // Iterate over each node in the priority queue.
        while let Some((issuer_fpr, _)) = queue.pop() {
            // Get all the bindings that issuer certified.
            let certification_sets: &Vec<CertificationSet<'a>>
                = if let Some(cs) = self.edges.get(&issuer_fpr) {
                    cs
                } else {
                    // It didn't certify anything.  The path is a dead
                    // end.
                    t!("{} made no certifications, dead end", issuer_fpr);
                    continue;
                };

            t!("Visiting <{}, {}>, certified {} certificates",
               issuer_fpr,
               self.nodes.get(&issuer_fpr).expect("valid")
                   .primary_userid()
                   .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                   .unwrap_or("<no User ID>".to_owned()),
               certification_sets.len());

            // Get the issuer's current backpointer.
            //
            // We need to clone this, because we want to manipulate
            // 'distance' and we can't do that if there is a reference
            // to something in it.
            let bp: BackPointer
                = distance.get(&issuer_fpr).expect("was queued").clone();
            let bp_cost = bp_cost!(&bp);

            t!("  Certified by: {:?}, cost: {:?}",
               bp, bp_cost);

            for (&userid, certification)
                in certification_sets.iter()
                    .flat_map(|cs| cs.certifications.iter())
            {
                let target_fpr = certification.target_cert.fingerprint();

                t!("  Considering certification of: <{}, {}>, depth: {}, amount: {}, regexes: {:?}",
                   certification.target_cert.keyid(),
                   String::from_utf8_lossy(userid),
                   certification.depth,
                   certification.amount,
                   if certification.re_set.matches_everything() { "*".into() }
                   else { format!("{:?}", certification.re_set) });

                if ! certification.re_set.matches_everything() {
                    t!("  Certification has non-empty regex, skipping");
                    continue;
                }

                let proposed_bp: BackPointer<'a>  = BackPointer {
                    prev: Some(certification.clone()),
                };
                let proposed_bp_cost = Cost {
                    depth: std::cmp::min(
                        certification.depth as usize,
                        bp_cost.depth - 1),
                    amount: std::cmp::min(
                        certification.amount as usize,
                        bp_cost.amount),
                };

                t!("    Proposed back pointer: {:?}\n  cost: {:?}",
                   proposed_bp, proposed_bp_cost);

                // distance.entry takes a mutable ref, so we can't
                // compute the current bp's cost there.
                let current_bp_cost = if let Some(current_bp)
                    = distance.get(&target_fpr.clone())
                {
                    Some(bp_cost!(&current_bp))
                } else {
                    None
                };

                match distance.entry(target_fpr.clone()) {
                    Entry::Occupied(mut oe) => {
                        let current_bp_cost = current_bp_cost.unwrap();
                        let current_bp = oe.get_mut();

                        t!("    Current back pointer: {:?}", current_bp);

                        // In terms of the number of hops, the
                        // 'current_bp' is not longer than
                        // 'proposed_bp'.  But, if the path under
                        // consideration (bp + certification) is
                        // strictly better, then we prefer it.
                        //
                        // Strictly better is:
                        //
                        //   - Larger trust depth.
                        //   - Same trust depth, but larger trust amount.

                        if proposed_bp_cost.depth > current_bp_cost.depth {
                            if proposed_bp_cost.amount < current_bp_cost.amount {
                                // We have two local optima: one
                                // has a higher depth, the other a
                                // higher trust amount.  We prefer
                                // the higher depth, and mark this
                                // node as being a local optimum.
                                t!("    Better depth, worse amount of trust");
                                oe.insert(proposed_bp);
                            } else {
                                // Proposed bp is strictly better.
                                t!("    Better depth, better amount of trust");
                                oe.insert(proposed_bp);
                            }
                        } else if proposed_bp_cost.depth == current_bp_cost.depth
                            && proposed_bp_cost.amount > current_bp_cost.amount
                        {
                            // Strictly better.
                            t!("    Same depth, better amount");
                            oe.insert(proposed_bp);
                        } else if proposed_bp_cost.depth > 0
                            && proposed_bp_cost.depth < current_bp_cost.depth
                            && proposed_bp_cost.amount > current_bp_cost.amount
                        {
                            // There's another possible path through here.
                            t!("    Worse depth, better amount");
                        } else {
                            t!("    Current bp is strictly better");
                        }
                    }
                    e @ Entry::Vacant(_) => {
                        // We haven't see it before.
                        t!("  Discovered {}, {}", target_fpr,
                           self.nodes.get(&target_fpr).expect("valid")
                               .primary_userid()
                               .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                               .unwrap_or("<no User ID>".to_owned()));
                        if proposed_bp_cost.depth > 0 {
                            t!("    Queuing {:?}", proposed_bp_cost);
                            queue.push(target_fpr, proposed_bp_cost);
                        }
                        e.or_insert(proposed_bp);
                    }
                }
            }
        }


        // Follow the back pointers and reconstruct the paths.
        let mut auth_paths: HashMap<Fingerprint, Path>
            = HashMap::new();

        for (cert_fpr, mut bp) in distance.iter() {
            let cert = if let Some(ref c) = bp.prev {
                &c.target_cert
            } else {
                self.nodes.get(&cert_fpr).expect("exists")
            };

            t!("Recovering path to {}, {}",
               cert_fpr,
               cert.primary_userid()
                   .map(|ua| {
                       String::from_utf8_lossy(ua.userid().value()).into_owned()
                   })
                   .unwrap_or("<no User ID>".to_owned()));

            // The path is reversed: nodes[nodes.len() - 1] is the root.
            let mut nodes: Vec<Certification<'a>> = Vec::new();
            while let Some(ref c) = bp.prev {
                t!("  {:?}", bp);
                nodes.push(c.clone());
                bp = distance.get(&c.issuer_cert.fingerprint())
                    .expect("exists");
            }
            t!("  {:?}", bp);

            let root = if nodes.len() == 0 {
                cert
            } else {
                &nodes[nodes.len() - 1].issuer_cert
            };

            t!("\nShortest path to {}, {}:\n  Root: {}\n  {}",
               cert_fpr,
               cert.primary_userid()
                   .map(|ua| {
                       String::from_utf8_lossy(ua.userid().value()).into_owned()
                   })
                   .unwrap_or("<no User ID>".to_owned()),
               root,
               nodes.iter()
                   .rev()
                   .enumerate()
                   .map(|(i, n)| format!("{}: {:?}", i, n))
                   .collect::<Vec<_>>()
                   .join("\n  "));

            let mut p = Path::new(root.clone());
            for n in nodes.iter().rev() {
                p.try_append(n.clone()).expect("valid path");
            }

            t!("Authenticated <{}, {}>: {:?}",
               cert_fpr,
               bp.prev.as_ref().map(|c| {
                   String::from_utf8_lossy(
                       c.target_userid.value())
                       .into_owned()
               })
               .unwrap_or_else(|| "root".to_owned()),
               p);

            auth_paths.insert(cert_fpr.clone(), p);
        }

        auth_paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::Result;
    use crate::cert::prelude::*;
    use crate::packet::prelude::*;
    use crate::parse::Parse;
    use crate::policy::StandardPolicy;

    fn pcmp(p: &Path, residual_depth: usize, amount: usize,
            certs: &[ &Fingerprint ])
    {
        let p_certs: Vec<Fingerprint>
            = p.certificates().map(|c| c.fingerprint()).collect();

        assert_eq!(p_certs.len(), certs.len());

        for (got, expected) in p_certs.iter().zip(certs.iter()) {
            assert_eq!(&got, expected);
        }

        assert_eq!(p.amount(), amount);
        assert_eq!(p.residual_depth(), residual_depth);
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

        let auth = n.forward_propagate(&[ alice_fpr.clone() ]);

        pcmp(auth.get(&alice_fpr).unwrap(),
             usize::MAX, 120,
             &[ &alice_fpr ]);
        pcmp(auth.get(&bob_fpr).unwrap(),
             2, 100,
             &[ &alice_fpr, &bob_fpr ]);
        pcmp(auth.get(&carol_fpr).unwrap(),
             1, 100,
             &[ &alice_fpr, &bob_fpr, &carol_fpr ]);
        pcmp(auth.get(&dave_fpr).unwrap(),
             0, 100,
             &[ &alice_fpr, &bob_fpr, &carol_fpr, &dave_fpr ]);
        // Not enough depth.
        assert!(auth.get(&ellen_fpr).is_none());
        // Unreachable.
        assert!(auth.get(&frank_fpr).is_none());

        Ok(())
    }

    #[test]
    #[allow(unused)]
    fn cycle() -> Result<()> {
        let p = &StandardPolicy::new();

        let frank_fpr: Fingerprint =
            "F4AC E7B8 A36C B151 AC65  3EA6 6143 9493 CA15 9770"
           .parse().expect("valid fingerprint");
        let frank_uid
            = UserID::from("<frank@example.org>");
        // Certified by: 6BFE 8673 D01E E032 D5B6  E9AC 6164 26A1 906D 67CE

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

        let ed_fpr: Fingerprint =
            "6BFE 8673 D01E E032 D5B6  E9AC 6164 26A1 906D 67CE"
           .parse().expect("valid fingerprint");
        let ed_uid
            = UserID::from("<ed@example.org>");
        // Certified by: CBFB F6C4 9357 380F 633E  E785 F85C EC70 7AF8 A1FE

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

        let auth = n.forward_propagate(&[ alice_fpr.clone() ]);

        pcmp(auth.get(&alice_fpr).unwrap(),
             usize::MAX, 120,
             &[ &alice_fpr ]);

        // alice -> bob
        pcmp(auth.get(&bob_fpr).unwrap(),
             3, 120,
             &[ &alice_fpr, &bob_fpr ]);

        // alice -> bob -> carol (90)
        pcmp(auth.get(&carol_fpr).unwrap(),
             2, 90,
             &[ &alice_fpr, &bob_fpr, &carol_fpr ]);

        // alice -> bob -> carol -> dave (60)
        pcmp(auth.get(&dave_fpr).unwrap(),
             1, 60,
             &[ &alice_fpr, &bob_fpr, &carol_fpr, &dave_fpr ]);

        // alice -> bob -> carol -> dave -> ed (30)
        pcmp(auth.get(&ed_fpr).unwrap(),
             0, 30,
             &[ &alice_fpr, &bob_fpr, &carol_fpr, &dave_fpr, &ed_fpr ]);

        // alice -> bob -> carol -> dave -> ed -> frank (not enough depth)
        assert!(auth.get(&frank_fpr).is_none());


        let auth = n.forward_propagate(&[ bob_fpr.clone() ]);

        // bob -> carol (90)
        pcmp(auth.get(&carol_fpr).unwrap(),
             255, 90,
             &[ &bob_fpr, &carol_fpr ]);

        // bob -> carol -> dave (60)
        pcmp(auth.get(&dave_fpr).unwrap(),
             254, 60,
             &[ &bob_fpr, &carol_fpr, &dave_fpr ]);

        // bob -> carol -> dave -> ed (30)
        pcmp(auth.get(&ed_fpr).unwrap(),
             1, 30,
             &[ &bob_fpr, &carol_fpr, &dave_fpr, &ed_fpr ]);

        // bob -> carol -> dave -> ed -> frank (30)
        pcmp(auth.get(&frank_fpr).unwrap(),
             0, 30,
             &[ &bob_fpr, &carol_fpr, &dave_fpr, &ed_fpr, &frank_fpr ]);


        let auth = n.forward_propagate(&[ carol_fpr.clone() ]);

        // carol -> dave
        pcmp(auth.get(&dave_fpr).unwrap(),
             255, 60,
             &[ &carol_fpr, &dave_fpr ]);

        // carol -> dave -> bob
        pcmp(auth.get(&bob_fpr).unwrap(),
             254, 60,
             &[ &carol_fpr, &dave_fpr, &bob_fpr ]);

        // carol -> dave -> ed
        pcmp(auth.get(&ed_fpr).unwrap(),
             1, 30,
             &[ &carol_fpr, &dave_fpr, &ed_fpr ]);

        // carol -> dave -> ed -> frank
        pcmp(auth.get(&frank_fpr).unwrap(),
             0, 30,
             &[ &carol_fpr, &dave_fpr, &ed_fpr, &frank_fpr ]);


        let auth = n.forward_propagate(&[ dave_fpr.clone() ]);

        // dave -> bob -> carol
        pcmp(auth.get(&carol_fpr).unwrap(),
             254, 90,
             &[ &dave_fpr, &bob_fpr, &carol_fpr ]);

        // dave -> ed -> frank
        pcmp(auth.get(&frank_fpr).unwrap(),
             0, 30,
             &[ &dave_fpr, &ed_fpr, &frank_fpr ]);

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

        let auth = n.forward_propagate(&[ root_fpr.clone() ]);

        // root -> a-0 -> b-0 -> ... -> f-0 -> target
        pcmp(auth.get(&target_fpr).unwrap(),
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

        let auth = n.forward_propagate(&[ alice_fpr.clone() ]);

        pcmp(auth.get(&alice_fpr).unwrap(),
             usize::MAX, 120,
             &[ &alice_fpr ]);

        // alice -> carol
        pcmp(auth.get(&carol_fpr).unwrap(),
             6, 120,
             &[ &alice_fpr, &carol_fpr ]);

        // alice -> carol -> dave
        pcmp(auth.get(&dave_fpr).unwrap(),
             5, 120,
             &[ &alice_fpr, &carol_fpr, &dave_fpr ]);

        // alice -> carol -> dave -> elmar (120)
        pcmp(auth.get(&elmar_fpr).unwrap(),
             4, 120,
             &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr ]);

        // alice -> carol -> dave -> elmar -> frank (120)
        pcmp(auth.get(&frank_fpr).unwrap(),
             3, 120,
             &[ &alice_fpr, &carol_fpr, &dave_fpr, &elmar_fpr, &frank_fpr ]);

        // Recall: forward propagation prefers the path with the
        // highest depth.  The best way to authenticate bob is: A -> C
        // -> D -> E -> F -> B.

        // alice -> bob
        pcmp(auth.get(&bob_fpr).unwrap(),
             100, 60,
             &[ &alice_fpr, &bob_fpr ]);

        // alice -> bob -> george
        pcmp(auth.get(&george_fpr).unwrap(),
             2, 60,
             &[ &alice_fpr, &bob_fpr, &george_fpr ]);

        // alice -> bob -> george -> henry
        pcmp(auth.get(&henry_fpr).unwrap(),
             1, 60,
             &[ &alice_fpr, &bob_fpr, &george_fpr, &henry_fpr ]);

        // alice -> bob -> george -> henry -> isaac
        pcmp(auth.get(&isaac_fpr).unwrap(),
             0, 60,
             &[ &alice_fpr, &bob_fpr, &george_fpr, &henry_fpr, &isaac_fpr ]);

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

        let auth = n.forward_propagate(&[ alice_fpr.clone() ]);

        pcmp(auth.get(&alice_fpr).unwrap(),
             usize::MAX, 120,
             &[ &alice_fpr ]);

        // alice -> bob
        pcmp(auth.get(&bob_fpr).unwrap(),
             150, 120,
             &[ &alice_fpr, &bob_fpr ]);

        // alice -> bob -> carol
        pcmp(auth.get(&carol_fpr).unwrap(),
             50, 100,
             &[ &alice_fpr, &bob_fpr, &carol_fpr ]);

        // alice -> bob -> dave
        pcmp(auth.get(&dave_fpr).unwrap(),
             100, 50,
             &[ &alice_fpr, &bob_fpr, &dave_fpr ]);

        // alice -> bob -> elmar
        //
        // This is not the best authentication path (A - B - C - E has
        // a higher trust amount), but it is the best in terms of
        // forward propagation (the highest depth).
        pcmp(auth.get(&ellen_fpr).unwrap(),
             99, 50,
             &[ &alice_fpr, &bob_fpr, &dave_fpr, &ellen_fpr ]);

        pcmp(auth.get(&francis_fpr).unwrap(),
             149, 75,
             &[ &alice_fpr, &bob_fpr, &francis_fpr ]);

        pcmp(auth.get(&henry_fpr).unwrap(),
             0, 50,
             &[ &alice_fpr, &bob_fpr, &dave_fpr, &ellen_fpr, &henry_fpr ]);

        pcmp(auth.get(&georgina_fpr).unwrap(),
             0, 30,
             &[ &alice_fpr, &bob_fpr, &dave_fpr, &ellen_fpr, &georgina_fpr ]);

        Ok(())
    }
}
