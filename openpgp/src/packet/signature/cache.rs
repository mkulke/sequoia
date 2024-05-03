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
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::sync::MutexGuard;

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

/// An entry in the signature verification cache.
///
/// You can iterate over the cache using
/// [`SignatureVerificationCache::dump`].
pub struct Entry {
    key: [u8; HASH_BYTES_TRUNCATED],
}

impl Entry {
    /// Computes the cache entry from the signature and its context.
    pub(super) fn new(sig: &Signature,
                      computed_digest: &[u8],
                      key: &Key<key::PublicParts, key::UnspecifiedRole>)
        -> Result<Self>
    {
        use crate::serialize::Marshal;

        // Hash(Version || Signature MPIs || Hash Algorithm || Digest || Key.mpis())
        //
        // - Version: one byte, currently 0.
        // - Signature MPIs: variable number of bytes, the signature's MPIs
        // - Hash algorithm: one byte, the hash algorithm
        // - Digest: HashAlgorithm::len() bytes, the digest's length
        // - Key: variable number of bytes, the key's MPIs
        //
        // XXX: encode the length of the MPIs to prevent aliasing.
        let mut context = HASH_ALGO.context()?;
        sig.mpis.export(&mut context)?;

        context.update(&[
            u8::from(sig.hash_algo())
        ]);
        context.update(computed_digest);
        key.mpis().export(&mut context)?;
        let context_hash = context.into_digest()?;

        let mut context = ZERO_ENTRY;
        context.copy_from_slice(&context_hash[..ENTRY_BYTES]);

        Ok(Entry {
            key: context,
        })
    }

    const SERIALIZED_LEN: usize = ENTRY_BYTES;

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

        let mut key = ZERO_ENTRY;
        key.copy_from_slice(bytes);
        Ok(Entry {
            key,
        })
    }

    /// Serialize the entry.
    ///
    /// This value is opaque and must not be interpreted.
    ///
    /// When calling [`SignatureVerificationCache::merge`], this value
    /// must be provided as is.
    pub fn serialize(&self, output: &mut dyn Write) -> Result<()> {
        assert!(Entry::SERIALIZED_LEN <= u8::MAX as usize);
        assert_eq!(self.key.len(), Entry::SERIALIZED_LEN);

        output.write_all(&self.key)?;

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
        SIGNATURE_VERIFICATION_CACHE.contains(&self.key)
    }

    /// Inserts the entry in the cache.
    ///
    /// `verified` indicates whether the signature could be verified
    /// (`true`), or not (`false`).
    pub(super) fn insert(self, verified: bool) {
        // We don't insert negative results.
        if verified {
            SIGNATURE_VERIFICATION_CACHE.insert(self.key);
        }
    }
}

// We split on the `BUCKETS_BITS` most significant bits of the key's
// most significant byte to reduce locking contention.
const BUCKETS_BITS: usize = 4;
const BUCKETS: usize = 1 << BUCKETS_BITS;
const BUCKETS_MASK: u8 = (BUCKETS - 1) as u8;

/// A signature verification cache.
pub struct SignatureVerificationCache {
    path: Option<PathBuf>,
    mmapped: bool,
    memory: [
        Mutex<Option<Box<[SET]>>>;
        BUCKETS
    ],
    hits: AtomicUsize,
    misses: AtomicUsize,
    preloads: AtomicUsize,
    insertions: AtomicUsize,
    evictions: AtomicUsize,
}

// A single hash, which includes both the signature and the
// signature's context.
const ENTRY_BYTES: usize = HASH_BYTES_TRUNCATED;

// The cache's set associativity.
const ASSOCIATIVITY_LOG2: usize = 2;
const ASSOCIATIVITY: usize = 1 << ASSOCIATIVITY_LOG2;
const SET_BYTES: usize = ENTRY_BYTES << ASSOCIATIVITY_LOG2;

// The cache's size.
const TAG_BITS: usize = 18;
const SETS: usize = 1 << TAG_BITS;

const TOTAL_ENTRIES: usize = SETS << ASSOCIATIVITY_LOG2;
const CACHE_BYTES: usize = SETS * SET_BYTES;


type ENTRY = [u8; ENTRY_BYTES];
type SET = [ENTRY; ASSOCIATIVITY];
type CACHE = [SET; SETS];

const ZERO_ENTRY: ENTRY = [0u8; ENTRY_BYTES];

impl SignatureVerificationCache {
    const fn empty() -> Self {
        SignatureVerificationCache {
            path: None,
            mmapped: false,
            memory: [
                // 0
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                // 8
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
                Mutex::new(None),
            ],
            hits: AtomicUsize::new(0),
            misses: AtomicUsize::new(0),
            insertions: AtomicUsize::new(0),
            evictions: AtomicUsize::new(0),
            preloads: AtomicUsize::new(0),
        }
    }

    // The number of allocated lines and the capacity.
    fn usage() -> (usize, usize) {
        let mut allocated: usize = 0;

        for bucket in 0..BUCKETS {
            let memory = SignatureVerificationCache::memory(bucket);

            if let Some(memory) = memory.as_ref() {
                allocated += memory.iter()
                    .flat_map(|set| {
                        set.into_iter().map(|e| {
                            if e == &ZERO_ENTRY {
                                0
                            } else {
                                1
                            }
                        })
                    })
                    .sum::<usize>();
            }
        }

        (allocated, TOTAL_ENTRIES)
    }

    // Return the bucket.
    fn memory(bucket: usize)
        -> MutexGuard<'static, Option<Box<[SET]>>>
    {
        tracer!(false, "SignatureVerificationCache::memory");

        let mut memory = SIGNATURE_VERIFICATION_CACHE.memory[bucket].lock().unwrap();
        if memory.is_some() {
            return memory;
        }

        if let Some(_path) = SIGNATURE_VERIFICATION_CACHE.path.as_ref() {
            todo!()
        }

        t!("Allocating bucket {}: {} bytes ({}-associative, \
            {} entries with {} bytes per entry)",
           bucket, CACHE_BYTES / BUCKETS, ASSOCIATIVITY,
           TOTAL_ENTRIES / BUCKETS, ENTRY_BYTES);

        let layout = std::alloc::Layout::from_size_align(
            CACHE_BYTES / BUCKETS, ENTRY_BYTES).unwrap();
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return memory;
        }
        let ptr = ptr as *mut SET;

        let slice: *mut [SET] = std::ptr::slice_from_raw_parts_mut(
            ptr, SETS / BUCKETS);

        *memory = Some(unsafe { Box::from_raw(slice) });

        memory
    }

    /// Returns the bucket, and the set that a signature goes into.
    fn index(hash: &[u8]) -> (usize, usize) {
        let mut addr = 0usize;

        let mut bits = TAG_BITS;
        let mut i = 0;

        while bits >= 8 {
            addr = (addr << 8) | (hash[i] as usize);
            i += 1;
            bits -= 8;
        }

        if bits > 0 {
            addr <<= bits;
            addr += (hash[i] >> (8 - bits)) as usize;
        }

        assert!(addr < SETS);

        let bucket = addr >> (TAG_BITS - BUCKETS_BITS);
        assert!(bucket < BUCKETS);

        let addr = addr & ((1 << (TAG_BITS - BUCKETS_BITS)) - 1);
        assert!(addr < SETS / BUCKETS);

        (bucket, addr)
    }

    /// Returns whether the cache contains `hash`.
    fn contains(&self, hash: &[u8]) -> Option<bool>
    {
        assert_eq!(hash.len(), ENTRY_BYTES);

        let (bucket, i) = Self::index(hash);
        let memory = SignatureVerificationCache::memory(bucket);
        if let Some(sets) = memory.as_ref() {
            if sets[i].iter().any(|entry| entry == hash) {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(true)
            } else {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        } else {
            None
        }
    }

    fn insert_locked(memory: &mut MutexGuard<'_, Option<Box<[SET]>>>,
                     addr: usize, hash: [u8; ENTRY_BYTES])
    {
        tracer!(false, "SignatureVerificationCache::insert_locked");

        if let Some(sets) = memory.as_mut() {
            t!("insert({:02x}{:02x}{:02x}{:02x}...)",
               hash[0], hash[1], hash[2], hash[3]);

            t!(" -> set {} ({:02x})", addr, addr);
            let set = &mut sets[addr];

            // See if it is already there.
            if set.iter().enumerate().any(|(j, entry)| {
                if entry == &hash {
                    t!("Already present (line {})", j);
                    true
                } else {
                    false
                }
            }) {
                return;
            }

            // Look for a free entry.
            if let Some((j, entry)) = set.iter_mut().enumerate().find(|(_, entry)| entry == &&ZERO_ENTRY) {
                t!("Using unallocated line {}", j);
                *entry = hash;
                SIGNATURE_VERIFICATION_CACHE.insertions.fetch_add(1, Ordering::Relaxed);
                return;
            }

            // Choose a random entry to replace.
            let j = if ASSOCIATIVITY_LOG2 == 0 {
                0
            } else {
                let mut random = [0u8; 1];
                crate::crypto::random(&mut random);
                let random = random[0] & (ASSOCIATIVITY as u8 - 1);
                assert!((random as usize) < ASSOCIATIVITY);
                random
            };

            {
                let hash = set[j as usize];
                t!("Evicting line {} {:02x}{:02x}{:02x}{:02x}...)",
                   j, hash[0], hash[1], hash[2], hash[3]);
                SIGNATURE_VERIFICATION_CACHE.evictions.fetch_add(1, Ordering::Relaxed);
            }

            SIGNATURE_VERIFICATION_CACHE.insertions.fetch_add(1, Ordering::Relaxed);
            set[j as usize] = hash;
        }
    }

    /// Inserts a verified signature.
    fn insert(&self, hash: [u8; ENTRY_BYTES])
    {
        let (bucket, i) = Self::index(&hash);
        let mut memory = SignatureVerificationCache::memory(bucket);
        Self::insert_locked(&mut memory, i, hash);
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
        // Must fit in a byte.
        assert!(BUCKETS_BITS <= 8);

        // Consistency check.
        assert_eq!(BUCKETS, 1 << BUCKETS_BITS);

        let _detached_thread = std::thread::spawn(move || {
            tracer!(TRACE, "SignatureVerificationCache::merge");

            time_it!("Load signature cache", {
                let mut buckets: [MutexGuard<Option<Box<[SET]>>>; BUCKETS]
                    = [
                        SignatureVerificationCache::memory(0),
                        SignatureVerificationCache::memory(1),
                        SignatureVerificationCache::memory(2),
                        SignatureVerificationCache::memory(3),
                        SignatureVerificationCache::memory(4),
                        SignatureVerificationCache::memory(5),
                        SignatureVerificationCache::memory(6),
                        SignatureVerificationCache::memory(7),
                        SignatureVerificationCache::memory(8),
                        SignatureVerificationCache::memory(9),
                        SignatureVerificationCache::memory(10),
                        SignatureVerificationCache::memory(11),
                        SignatureVerificationCache::memory(12),
                        SignatureVerificationCache::memory(13),
                        SignatureVerificationCache::memory(14),
                        SignatureVerificationCache::memory(15),
                    ];

                let mut inserted = 0;

                for entry in entries {
                    inserted += 1;
                    let (bucket, i) = Self::index(&entry.key);
                    Self::insert_locked(&mut buckets[bucket], i, entry.key);
                    SIGNATURE_VERIFICATION_CACHE.preloads.fetch_add(1, Ordering::Relaxed);
                }

                drop(buckets);
                if TRACE {
                    let (allocated, capacity) = Self::usage();

                    t!("{} of {} ({}%) entries allocated",
                       allocated, capacity,
                       (allocated * 100 + 50) / capacity);
                    t!("Preloaded {} entries (capacity: {})",
                       inserted, capacity);
                }
            })
        });
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
        // XXX
        true
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
        tracer!(TRACE, "SignatureVerificationCache::dump");

        t!("{}-way associative cache: {} entries; {} sets, {} bytes per entry",
           ASSOCIATIVITY, TOTAL_ENTRIES, SETS, ENTRY_BYTES);
        let cache_size = TOTAL_ENTRIES * ENTRY_BYTES;
        let bucket_size = cache_size / BUCKETS;
        t!("Cache size: {} ({} per cache bucket)",
           if cache_size > 1024 * 1024 {
               format!("{} MB", cache_size / 1024 / 1024)
           } else if cache_size > 1024 {
               format!("{} KB", cache_size / 1024)
           } else {
               format!("{} bytes", cache_size)
           },
           if bucket_size > 1024 * 1024 {
               format!("{} MB", bucket_size / 1024 / 1024)
           } else if bucket_size > 1024 {
               format!("{} KB", bucket_size / 1024)
           } else {
               format!("{} bytes", bucket_size)
           });

        let preloads = SIGNATURE_VERIFICATION_CACHE.preloads.load(Ordering::Relaxed);
        t!("preloaded: {}", preloads);
        t!("new insertions: {}",
           SIGNATURE_VERIFICATION_CACHE.insertions.load(Ordering::Relaxed) - preloads);
        t!("evictions: {}", SIGNATURE_VERIFICATION_CACHE.evictions.load(Ordering::Relaxed));
        t!("hits: {}", SIGNATURE_VERIFICATION_CACHE.hits.load(Ordering::Relaxed));
        t!("misses: {}", SIGNATURE_VERIFICATION_CACHE.misses.load(Ordering::Relaxed));

        let mut entries = Vec::new();
        for bucket in 0..BUCKETS {
            let memory = SignatureVerificationCache::memory(bucket);

            if let Some(memory) = memory.as_ref() {
                entries.extend(memory.iter()
                    .flat_map(|set: &SET| {
                        set.into_iter()
                            .filter(|&e: &&ENTRY| e != &ZERO_ENTRY)
                            .map(|e| {
                                Entry { key: *e }
                            })
                    }));
            }
        }

        let (allocated, capacity) = SignatureVerificationCache::usage();
        t!("{} of {} ({}%) entries allocated",
           allocated, capacity,
           (allocated * 100 + 50) / capacity);

        DumpIter {
            iter: entries.into_iter(),
        }
    }
}

/// Iterates over all entries in the cache.
///
/// Note: to avoid lock contention, this may or may not return
/// individual entries added after it was instantiated.
struct DumpIter {
    iter: std::vec::IntoIter<Entry>,
}

impl Iterator for DumpIter {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}
