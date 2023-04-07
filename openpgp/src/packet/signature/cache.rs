//! A signature verification cache.
//!
//! Signature verification is expensive.  To mitigate this, Sequoia
//! includes a signature verification cache.  This is keyed on the
//! hash of the signature's MPIs, and the value is the hash of the
//! signature's context.  That is, we don't cache whether a signature
//! is valid, but whether a signature is valid for a given context.
//! Since this context is needed to use the cache, it's hard to misuse
//! the cache.
//!
//! The signature cache also supports serializing and parsing the
//! cache (see [`SignatureVerificationCache::merge`] and
//! [`SignatureVerificationCache::dump`]).  This is particularly
//! helpful for one-shot programs, which are not usually able to
//! profit from a cache.
//!
//! The cache file needs to be managed carefully.  In particular, you
//! probably don't want to allow it to grow without bound.  To help
//! manage the cache, the entries indicate if they were added
//! ([`Entry::added`]), and whether they were accessed
//! ([`Entry::accessed`]).
use std::collections::BTreeMap;
use std::collections::btree_map;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::RwLock;

use crate::crypto::hash::Digest;
use crate::HashAlgorithm;
use crate::packet::Key;
use crate::packet::key;
use crate::packet::Signature;
use crate::Result;

const TRACE: bool = false;

/// The cache.
static SIGNATURE_VERIFICATION_CACHE: SignatureVerificationCache
    = SignatureVerificationCache::empty();

/// The hash algorithm that we use.
///
/// This is faster than SHA-256 on 64-bit hardware.
const HASH_ALGO: HashAlgorithm = HashAlgorithm::SHA512;

/// We use SHA-512, which has 512 / 8 bytes = 64 bytes.  We truncate
/// it to the first 256 bits, i.e. we do SHA-512-256.  We're only
/// worried about second pre-image resistance, so this is enough even
/// when the signature uses SHA-512.
const HASH_BYTES_UNTRUNCATED: usize = 512 / 8;
const HASH_BYTES_TRUNCATED: usize = HASH_BYTES_UNTRUNCATED / 2;

#[non_exhaustive]
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
enum Error {
    /// Parse error.
    #[error("Error parsing cache entry: {0}")]
    ParseError(String),
}

/// The type of a value in the signature verification cache.
#[derive(Debug)]
pub struct Value {
    value: [u8; HASH_BYTES_TRUNCATED],

    /// Whether the entry was added.
    ///
    /// Entries added by [`SignatureVerificationCache::merge`] have
    /// this cleared.
    added: bool,

    /// Whether the entry was accessed.
    ///
    /// Entries added by [`SignatureVerificationCache::merge`] have
    /// this cleared.
    accessed: AtomicBool,
}

impl Clone for Value {
    fn clone(&self) -> Value {
        Self {
            value: self.value().clone(),
            added: self.added,
            accessed: AtomicBool::from(self.accessed.load(Ordering::Relaxed)),
        }
    }
}

impl Value {
    /// Instantiate a value.
    ///
    /// `added` is whether this should be considered an add or not.
    fn new(value: [u8; HASH_BYTES_TRUNCATED], added: bool) -> Self {
        Value {
            value,
            added,
            accessed: false.into(),
        }
    }

    /// The entry's value.
    ///
    /// This value is opaque and must not be interpreted.
    fn value(&self) -> &[u8; HASH_BYTES_TRUNCATED] {
        &self.value
    }

    /// Whether the entry was added.
    ///
    /// Entries added by [`SignatureVerificationCache::merge`] have
    /// this cleared.
    pub fn added(&self) -> bool {
        self.added
    }

    /// Whether the entry was accessed.
    ///
    /// Entries added by [`SignatureVerificationCache::merge`] have
    /// this cleared.
    pub fn accessed(&self) -> bool {
        self.accessed.load(Ordering::Relaxed)
    }
}

/// An entry in the signature verification cache.
///
/// You can iterate over the cache using
/// [`SignatureVerificationCache::dump`].
pub struct Entry {
    key: [u8; HASH_BYTES_TRUNCATED],
    value: Value,
}

impl Entry {
    /// Computes the cache entry from the signature and its context.
    pub(super) fn new(sig: &Signature,
                      computed_digest: &[u8],
                      key: &Key<key::PublicParts, key::UnspecifiedRole>)
        -> Result<Self>
    {
        use crate::serialize::Marshal;

        // Hash(Version || Signature MPIs)
        //
        // - Version: one byte, currently 0.
        // - Signature MPIs: variable number of bytes, the signature's MPIs
        let mut context = HASH_ALGO.context()?;
        sig.mpis.export(&mut context)?;
        let sig_hash = context.into_digest()?;

        // Hash(Version || Hash Algorithm || Digest || Key.mpis())
        //
        // - Version: one byte, currently 0.
        // - Hash algorithm: one byte, the hash algorithm
        // - Digest: HashAlgorithm::len() bytes, the digest's length
        // - Key: variable number of bytes, the key's MPIs
        let mut context = HASH_ALGO.context()?;
        context.update(&[
            0u8,
            u8::from(sig.hash_algo())
        ]);
        context.update(computed_digest);
        key.mpis().export(&mut context)?;
        let context_hash = context.into_digest()?;

        let mut key = [0u8; HASH_BYTES_TRUNCATED];
        key.copy_from_slice(&sig_hash[..HASH_BYTES_TRUNCATED]);

        let mut value = [0u8; HASH_BYTES_TRUNCATED];
        value.copy_from_slice(&context_hash[..HASH_BYTES_TRUNCATED]);

        Ok(Entry {
            key: key,
            value: Value::new(value, true),
        })
    }

    fn from_components(key: [u8; HASH_BYTES_TRUNCATED],
                       value: Value) -> Self {
        Entry {
            key,
            value,
        }
    }

    /// Parse an cache entry.
    ///
    /// This parses a cache entry.  This is the opposite of
    /// `Entry::serialize`.  It's primarily useful for restoring the
    /// cache via [`SignatureVerificationCache::merge`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes_len = bytes.len();

        if bytes_len != Entry::SERIALIZED_LEN {
            return Err(Error::ParseError(format!(
                "Unexpected length: got {}, expected: {}",
               bytes_len, Entry::SERIALIZED_LEN)).into());
        }

        let mut offset = 0;
        macro_rules! chomp {
            ($count:expr) => {{
                offset += $count;
                &bytes[offset-$count..offset]
            }};
        }

        let version = chomp!(1)[0];
        if version != 0 {
            return Err(Error::ParseError(format!(
                "Unsupported version: got {}", version)).into());
        }

        let len = chomp!(1)[0] as usize;
        if len != bytes_len {
            return Err(Error::ParseError(format!(
                "Invalid length: length is {}, got {} bytes",
                len, bytes_len)).into());
        }

        let hash_algo = chomp!(1)[0];
        if hash_algo != HASH_ALGO.into() {
            return Err(Error::ParseError(format!(
                "Unexpected hash algorithm: got: {}, expected: {}",
                hash_algo, u8::from(HASH_ALGO))).into());
        }

        let mut signature_hash = [0u8; HASH_BYTES_TRUNCATED];
        signature_hash.copy_from_slice(chomp!(HASH_BYTES_TRUNCATED));

        let mut context_hash = [0u8; HASH_BYTES_TRUNCATED];
        context_hash.copy_from_slice(chomp!(HASH_BYTES_TRUNCATED));

        let mut context = HASH_ALGO.context().expect("have SHA-512");
        context.update(&bytes[..offset]);
        let computed_checksum
            = context.into_digest().expect("have SHA-512");
        debug_assert!(computed_checksum.len()
                      == HASH_BYTES_UNTRUNCATED);
        let computed_checksum
            = &computed_checksum[..Entry::CHECKSUM_LEN];

        let checksum = chomp!(Entry::CHECKSUM_LEN);

        assert_eq!(offset, Entry::SERIALIZED_LEN);

        if computed_checksum != checksum  {
            return Err(Error::ParseError(format!(
                "Checksum mismatch: got: {:?}, expected: {:?}",
                computed_checksum, checksum)).into());
        }

        Ok(Entry {
            key: signature_hash,
            value: Value::new(context_hash, false),
        })
    }

    const CHECKSUM_LEN: usize = 5;
    const SERIALIZED_LEN: usize =
        // Version.
        1
        // Len (including the version, length, hash and checksum)
        + 1
        // Hash algorithm
        + 1
        // Hash(signature's mpis)
        + HASH_BYTES_TRUNCATED
        // Hash(signature's context)
        + HASH_BYTES_TRUNCATED
        // Truncated hash (most significant bytes) of
        // the above `Hash(Version || .. || Hash(signature's context))`.
        + Self::CHECKSUM_LEN;

    /// Serialize the entry.
    ///
    /// This value is opaque and must not be interpreted.
    ///
    /// When calling [`SignatureVerificationCache::merge`], this value
    /// must be provided as is.
    pub fn serialize(&self, output: &mut dyn Write) -> Result<()> {
        assert!(Entry::SERIALIZED_LEN <= u8::MAX as usize);

        let mut len = 0;
        let mut write = |buffer: &[u8]| -> Result<()> {
            output.write_all(buffer)?;
            len += buffer.len();
            Ok(())
        };

        let header: [u8; 3] = [
            // Version.
            0,
            // Len
            Self::SERIALIZED_LEN as u8,
            // Hash algorithm.
            u8::from(HASH_ALGO),
        ];
        write(&header[..])?;

        // Signature hash.
        write(&self.key)?;

        // Context hash.
        write(self.value.value())?;

        // Checksum.
        let mut context = HASH_ALGO.context().expect("have SHA-512");
        context.update(&header);
        context.update(&self.key);
        context.update(self.value.value());
        let checksum = context.into_digest().expect("have SHA-512");
        debug_assert!(checksum.len() == HASH_BYTES_UNTRUNCATED);

        write(&checksum[..Self::CHECKSUM_LEN])?;

        assert_eq!(len, Self::SERIALIZED_LEN);

        Ok(())
    }

    /// Serialize the entry to a vector.
    ///
    /// This value is opaque and must not be interpreted.
    ///
    /// When calling [`SignatureVerificationCache::merge`], this value
    /// must be provided as is.
    ///
    /// If you already have something that implements
    /// `std::io::Write`, you're better off using
    /// [`Entry::serialize`].
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SERIALIZED_LEN);
        self.serialize(&mut bytes)
            .expect("serializing to a vec is infallible");
        bytes
    }

    /// Looks up the entry in the cache.
    ///
    /// - If the entry is not present, returns `None`.
    ///
    /// - If the entry is present, and the signature is valid, returns
    ///   `Some(true)`.
    ///
    /// - If the entry is present, but the signature is not valid,
    ///   returns `Some(false)`.
    pub(super) fn lookup(&self) -> Option<bool> {
        SIGNATURE_VERIFICATION_CACHE
            .contains(&self.key, &self.value.value)
    }

    /// Inserts the entry in the cache.
    ///
    /// `verified` indicates whether the signature could be verified
    /// (`true`), or not (`false`).
    pub(super) fn insert(self, verified: bool) {
        // We don't insert negative results.
        if verified {
            SIGNATURE_VERIFICATION_CACHE
                .insert(self.key, self.value.value);
        }
    }

    /// Whether the entry was added.
    ///
    /// Entries added by [`SignatureVerificationCache::merge`] have
    /// this cleared.
    pub fn added(&self) -> bool {
        self.value.added
    }

    /// Whether the entry was accessed.
    ///
    /// Entries added by [`SignatureVerificationCache::merge`] have
    /// this cleared.
    pub fn accessed(&self) -> bool {
        self.value.accessed.load(Ordering::Relaxed)
    }
}

// We split on the `BUCKETS_BITS` least significant bits of the key's
// most significant byte to reduce locking contention.
const BUCKETS_BITS: usize = 4;
const BUCKETS: usize = 1 << BUCKETS_BITS;
const BUCKETS_MASK: u8 = (BUCKETS - 1) as u8;

/// A signature verification cache.
pub struct SignatureVerificationCache {
    updated: AtomicBool,
    buckets: [
        RwLock<BTreeMap<
                // SHA-512(mpi::Signature),
                [u8; HASH_BYTES_TRUNCATED],
                Value>>;
        BUCKETS
    ],
}

impl SignatureVerificationCache {
    const fn empty() -> Self {
        SignatureVerificationCache {
            updated: AtomicBool::new(false),
            buckets: [
                // 0
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                // 8
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
                RwLock::new(BTreeMap::new()),
            ],
        }
    }

    /// Returns the bucket that a signature goes into.
    fn bucket(signature_hash: &[u8]) -> usize {
        (signature_hash[0] & BUCKETS_MASK) as usize
    }

    /// Initializes the signature verification cache.
    ///
    /// This merges the entries with the existing signature cache.
    ///
    /// The values are the values returned by [`Entry::key`] and
    /// [`Entry::value`], respectively.
    ///
    /// The iterator is `Send` and `Sync`, because this function may
    /// spawn a thread to avoid blocking the main thread.
    pub fn merge<'a>(
        entries: impl Iterator<Item=Entry> + Send + Sync + 'static)
    {
        // Sanity check the constants here: this function is run once.

        // Must fit in a byte.
        assert!(BUCKETS_BITS <= 8);

        // Consistency check.
        assert_eq!(BUCKETS, 1 << BUCKETS_BITS);

        let _detached_thread = std::thread::spawn(move || {
            let mut buckets: [
                Vec<([u8; HASH_BYTES_TRUNCATED],
                     [u8; HASH_BYTES_TRUNCATED])>;
                BUCKETS
            ] = Default::default();

            for entry in entries {
                let signature_hash = entry.key;
                let context_hash = entry.value.value;

                let i = Self::bucket(&signature_hash);
                buckets[i].push((signature_hash, context_hash));
            }

            for (bucket, items)
                in SIGNATURE_VERIFICATION_CACHE.buckets.iter().zip(buckets)
            {
                let mut bucket = bucket.write().unwrap();

                bucket.extend(
                    items.into_iter().map(|(k, v)| {
                        let mut k_array = [0u8; HASH_BYTES_TRUNCATED];
                        k_array.copy_from_slice(&k);

                        let mut v_array = [0u8; HASH_BYTES_TRUNCATED];
                        v_array.copy_from_slice(&v);

                        (k_array, Value::new(v_array, false))
                    }));
            }
        });
    }

    /// Returns whether the cache contains `signature_hash`, and if
    /// the context matches `verification_hash`.
    fn contains(&self,
                signature_hash: &[u8],
                verification_hash: &[u8])
        -> Option<bool>
    {
        assert_eq!(signature_hash.len(), HASH_BYTES_TRUNCATED);

        let i = Self::bucket(signature_hash);
        let entries = self.buckets[i].read().unwrap();
        if let Some(entry) = entries.get(signature_hash) {
            entry.accessed.store(true, Ordering::Relaxed);
            assert_eq!(verification_hash.len(), HASH_BYTES_TRUNCATED);
            Some(&entry.value()[..] == verification_hash)
        } else {
            None
        }
    }

    /// Inserts a verified signature.
    fn insert(&self,
              signature_hash: [u8; HASH_BYTES_TRUNCATED],
              verification_hash: [u8; HASH_BYTES_TRUNCATED])
    {
        let i = Self::bucket(&signature_hash);
        let mut entries = self.buckets[i].write().unwrap();
        match entries.entry(signature_hash) {
            btree_map::Entry::Vacant(e) => {
                // Some entry was added.  Note it.
                self.updated.store(true, Ordering::Relaxed);

                // Add the entry.
                e.insert(Value::new(verification_hash, true));
            }
            btree_map::Entry::Occupied(e) => {
                if &e.get().value()[..] != &verification_hash[..] {
                    eprintln!("sequoia-openpgp: Signature cache corrupted.");
                }
            }
        }
    }

    /// Returns whether the cache has been updated.
    ///
    /// This returns whether an entry was inserted into the cache
    /// since the program started or the last time
    /// [`SignatureVerificationCache::clear_updated`] was called.
    ///
    /// This does not include entries added via
    /// [`SignatureVerificationCache::merge`].
    pub fn updated() -> bool {
        SIGNATURE_VERIFICATION_CACHE
            .updated.load(Ordering::Relaxed)
    }

    /// Resets the update counter.
    pub fn clear_updated() {
        SIGNATURE_VERIFICATION_CACHE
            .updated.store(false, Ordering::Relaxed);
    }

    /// Dumps the contents of the cache.
    ///
    /// This clones the cache to avoid holding locks too long.
    ///
    /// The values returned by [`Entry::key`] and [`Entry::value`] may
    /// be written to a file, and restored using
    /// [`SignatureVerificationCache::merge`].
    ///
    /// Before saving them, you may want to check if there were any
    /// updates using [`SignatureVerificationCache::updated`].
    ///
    /// Also, you may want to prune the entries to avoid having the
    /// cache grow too large.
    pub fn dump<'a>() -> impl IntoIterator<Item=Entry> {
        DumpIter {
            bucket: 0,
            iter: None,
        }
    }
}

/// Iterates over all entries in the cache.
///
/// Note: to avoid lock contention, this may or may not return
/// individual entries added after it was instantiated.
struct DumpIter {
    bucket: usize,
    iter: Option<std::vec::IntoIter<Entry>>,
}

impl Iterator for DumpIter {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut iter) = self.iter {
                if let Some(item) = iter.next() {
                    return Some(item);
                }
            }

            if self.bucket == BUCKETS {
                return None;
            }

            let bucket = &SIGNATURE_VERIFICATION_CACHE.buckets[self.bucket];
            self.bucket += 1;

            let bucket = bucket.read().unwrap();

            self.iter = Some(
                bucket.iter()
                    .map(|(k, v)| {
                        Entry::from_components(k.clone(), v.clone())
                    })
                    .collect::<Vec<_>>()
                    .into_iter())
        }
    }
}
