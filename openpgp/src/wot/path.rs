use std::fmt;

use crate::Result;
use crate::packet::prelude::*;
use crate::cert::prelude::*;
use crate::Fingerprint;

use super::Certification;
use super::TRACE;

/// A network path.
#[derive(Clone)]
pub struct Path<'a> {
    // The root.
    root: ValidCert<'a>,

    // Then the transition from the previous node to the next, and the
    // next node.
    edges: Vec<Certification<'a>>,

    // Residual depth.  To append a certification, this must be >0.
    // After adding a new certification, the new residual depth is:
    // min(residual_depth - 1, certification.depth).
    residual_depth: usize,
}

impl<'a> fmt::Debug for Path<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Path [\n")?;

        let print_vc = |f: &mut fmt::Formatter<'_>, vc: &ValidCert<'a>|
            -> fmt::Result
        {
            f.write_str("  ")?;
            if let Ok(ua) = vc.primary_userid() {
                f.write_str(
                    &String::from_utf8_lossy(
                        ua.userid().value())[..])?;
            } else {
                f.write_str("[no User ID]")?;
            }
            f.write_str("\n  ")?;
            f.write_str(&vc.keyid().to_string())?;
            f.write_str("\n")?;
            Ok(())
        };

        print_vc(f, &self.root)?;

        for certification in self.edges.iter() {
            f.write_str(
                "           |\n")?;
            f.write_str(&format!(
                "           | depth: {}\n", certification.depth)[..])?;
            f.write_str(&format!(
                "           | amount: {}\n", certification.amount)[..])?;
            f.write_str(&format!(
                "           | regexes: {}\n",
                if certification.re_set.matches_everything() {
                    String::from("*")
                } else {
                    format!("{:?}", &certification.re_set)
                }))?;
            f.write_str(
                "           v\n")?;

            print_vc(f, &certification.target_cert)?;
        }
        f.write_str("]")?;

        Ok(())
    }
}

impl<'a> Path<'a> {
    /// Instantiates a path starting at the specified root.
    ///
    /// We assume that the root is ultimately trusted (its trust depth
    /// is unlimited and its trust amount is maximal).
    pub(super) fn new(root: ValidCert<'a>) -> Self
    {
        Self {
            root: root,

            // Most paths will be direct (len: 2) or via one trusted
            // introducer (len: 3); meta-introducers are really used.
            edges: Vec::with_capacity(3 - 1),

            residual_depth: usize::MAX,
        }
    }

    /// Returns the path's root.
    pub fn root(&self) -> &ValidCert<'a> {
        &self.root
    }

    /// Returns the last node in the path.
    pub fn tail(&self) -> &ValidCert<'a> {
        if self.edges.len() == 0 {
            &self.root
        } else {
            &self.edges[self.edges.len() - 1].target_cert
        }
    }

    /// Returns an iterator over the path's certificates (the nodes).
    ///
    /// The certificates are returned from the root towards the target.
    pub fn certificates(&'a self) -> impl Iterator<Item=ValidCert<'a>> {
        std::iter::once(self.root.clone())
            .chain(self.edges.iter().map(|certification| {
                certification.target_cert.clone()
            }))
    }

    /// Returns the number of nodes in the path.
    pub fn len(&self) -> usize {
        1 + self.edges.len()
    }

    /// Returns the certifications.
    ///
    /// The certifications are returned from the root towards the target.
    pub fn certifications(&'a self) -> impl Iterator<Item=&Certification<'a>> {
        self.edges.iter()
    }

    /// Returns the tail's trust depth.
    pub fn residual_depth(&self) -> usize {
        self.residual_depth
    }

    /// The amount that the tail is trusted.
    pub fn amount(&self) -> usize {
        self.edges.iter().map(|e| e.amount).min().unwrap_or(120) as usize
    }

    /// Appends 'certification' to the path if the path allows it.
    ///
    /// A path may not allow it if the trust depth is insufficient.
    /// Paths are also not allowed to contain cycles.
    pub(super) fn try_append(&mut self, certification: Certification<'a>)
        -> Result<()>
    {
        tracer!(false, "Path::try_append", 0);
        t!("  path: {:?}", self);
        t!("  certification: {:?}", certification);

        if self.tail().fingerprint() != certification.issuer_cert.fingerprint() {
            return Err(anyhow::format_err!(
                "Path's tail ({}) did not issuer certification ({})",
                self.tail().fingerprint(), certification.issuer_cert.fingerprint()));
        }

        if self.residual_depth == 0 {
            return Err(anyhow::format_err!("Not enough depth"));
        }

        // Check for cycles.
        if self.root.fingerprint()
                == certification.target_cert.fingerprint()
            || self.edges.iter().any(|c| {
                c.target_cert.fingerprint()
                    == certification.target_cert.fingerprint()
            })
        {
            return Err(anyhow::format_err!(
                "Adding {} would create a cycle",
                certification.target_cert.fingerprint()));
        }

        self.residual_depth
            = std::cmp::min(self.residual_depth - 1,
                            certification.depth as usize);
        self.edges.push(certification);

        Ok(())
    }

    /// Appends a Path.
    pub(super) fn extend(&mut self, suffix: &Path<'a>) -> Result<()> {
        for certification in suffix.edges.iter() {
            self.try_append(certification.clone())?;
        }

        Ok(())
    }

    /// Appends an RPath.
    pub(super) fn weld(&mut self, rest: RPath<'a>) -> Result<()> {
        tracer!(TRACE, "Path::weld", 0);
        t!("{:?}", self);
        t!("{:?}", rest);
        for c in rest.edges.into_iter().rev() {
            self.try_append(c)?;
        }
        Ok(())
    }

    pub(super) fn replace_tail(&mut self, tail: Certification<'a>) {
        let l = self.edges.len();
        self.edges[l - 1] = tail;
    }
}

/// A collection of paths.
///
/// The amount is the amount while respecting the total capacity of
/// the edges.
#[derive(Clone)]
pub struct Paths<'a> {
    paths: Vec<(Path<'a>, usize)>,
}

impl<'a> Paths<'a> {
    pub(super) fn new() -> Self {
        Self {
            paths: Vec::new(),
        }
    }

    /// The paths.
    ///
    /// Returns an iterator over each path and its trust amount.
    pub fn iter(&self) -> impl Iterator<Item=&(Path<'a>, usize)> {
        self.paths.iter()
    }

    /// The aggregate trust amount.
    ///
    /// This respects the network's capacity.  Thus, if multiple paths
    /// use the same edge, the total trust amount may be less than
    /// simple the trust amount of each individual path.
    pub fn amount(&self) -> usize {
        self.paths.iter().map(|(_, a)| a).sum()
    }

    pub(super) fn push(&mut self, path: Path<'a>, amount: usize) {
        assert!(amount <= path.amount());

        self.paths.push((path, amount));
    }
}

impl<'a> fmt::Debug for Paths<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Paths [\n")?;
        for (i, (p, a)) in self.iter().enumerate() {
            f.write_str(&format!("  PATH {}, trust amount: {}:\n{:?}",
                                 i, a, p))?;
        }
        f.write_str("]")?;
        Ok(())
    }
}

/// A network path suffix.
#[derive(Clone)]
pub(super) struct RPath<'a> {
    pub target_fpr: Fingerprint,
    pub target_userid: UserID,

    // The certification.
    pub edges: Vec<Certification<'a>>,
}

impl<'a> fmt::Debug for RPath<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RPath [\n")?;

        f.write_str("          ???\n")?;
        f.write_str("           |\n")?;
        for (i, c) in self.edges.iter().rev().enumerate() {
            if i == 0 {
                f.write_str(
                    &format!("  {}\n",
                             &c.issuer_cert.primary_userid()
                             .map(|ua| String::from_utf8_lossy(ua.userid().value()).into_owned())
                             .unwrap_or("<missing User ID>".into())))?;
                f.write_str(
                    &format!("  {}\n", c.issuer_cert.fingerprint()))?;
            }

            f.write_str(
                "           |\n")?;
            f.write_str(&format!(
                "           | depth: {}\n", c.depth)[..])?;
            f.write_str(&format!(
                "           | amount: {}\n", c.amount)[..])?;
            f.write_str(&format!(
                "           | regexes: {:?}\n", c.re_set)[..])?;
            f.write_str(
                "           v\n")?;
            f.write_str(
                &format!("  {}\n",
                         &String::from_utf8_lossy(c.target_userid.value())))?;
            f.write_str(
                &format!("  {}\n", c.target_cert.fingerprint()))?;
        }

        if self.edges.len() == 0 {
            f.write_str(
                &format!("  {}\n",
                         &String::from_utf8_lossy(self.target_userid.value())))?;
            f.write_str(
                &format!("  {}", self.target_fpr))?;
        }

        f.write_str("]")?;

        Ok(())
    }
}

impl<'a> RPath<'a> {
    /// Instantiates a path starting at the specified root.
    pub fn new(target_userid: UserID, target_fpr: Fingerprint) -> Self
    {
        Self {
            target_userid,
            target_fpr,
            edges: vec![],
        }
    }

    pub fn from_path(p: Path<'a>, target_fpr: Fingerprint, target_userid: UserID)
        -> Self
    {
        RPath {
            target_fpr,
            target_userid,
            edges: p.edges.into_iter().rev().collect(),
        }
    }

    /// Returns the number of nodes in the path.
    pub fn len(&self) -> usize {
        1 + self.edges.len()
    }

    /// Prepends 'certification' to the path if the path allows it.
    pub fn try_prepend(&self, certification: Certification<'a>)
        -> Result<Self>
    {
        // XXX: Check trust amount!
        tracer!(false, "RPath::try_prepend", 0);
        t!("  path: {:?}", self);
        t!("  certification: {:?}", certification);

        // XXX: Check target_userid, target_fpr.

        if certification.re_set.matches_everything() {
            for c in self.edges.iter() {
                // Check that this introducer can be used to certify the
                // target.
                if ! certification.re_set.matches_userid(&c.target_userid) {
                    return Err(anyhow::format_err!(
                        "Certification's REs don't match user id ({})",
                        c.target_userid));
                }
            }
        }

        // Check for cycles.
        if self.edges.iter().any(|c| {
            c.target_cert.fingerprint()
                == certification.target_cert.fingerprint()
        })
        {
            return Err(anyhow::format_err!(
                "Adding {} would create a cycle",
                certification.target_cert.fingerprint()));
        }


        // The path remains possible.
        let mut path = self.clone();
        path.edges.push(certification);

        Ok(path)
    }

    pub fn head(&self) -> Fingerprint {
        if self.edges.len() == 0 {
            self.target_fpr.clone()
        } else {
            self.edges[self.edges.len() - 1].issuer_cert.fingerprint()
        }
    }

    pub fn empty(&self) -> bool {
        self.edges.len() == 0
    }
}
