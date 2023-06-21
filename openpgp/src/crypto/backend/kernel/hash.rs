use crate::crypto::hash::Digest;
use crate::types::HashAlgorithm;
use crate::Result;

use kcapi::md::KcapiHash;
use kcapi::KcapiResult;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
struct KernelHasher {
    hasher: std::sync::Arc<std::sync::Mutex<KcapiHash>>,
    algo: HashAlgorithm,
    update_result: KcapiResult<()>,
}

impl Digest for KernelHasher {
    fn algo(&self) -> HashAlgorithm {
        self.algo
    }

    fn digest_size(&self) -> usize {
        self.hasher.lock().expect("lock not to be poisoned").digestsize
    }

    fn update(&mut self, data: &[u8]) {
        if self.update_result.is_ok() {
            let hasher = self.hasher.lock().expect("lock not to be poisoned");
            self.update_result = hasher.update(data.to_vec());
        }
    }

    fn digest(&mut self, digest: &mut [u8]) -> Result<()> {
        self.update_result.clone()?;
        let hasher = self.hasher.lock().expect("lock not to be poisoned");
        let result = hasher.finalize()?;
        digest.copy_from_slice(&result[..digest.len()]);
        Ok(())
    }
}

impl std::io::Write for KernelHasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        // Do nothing.
        Ok(())
    }
}

impl HashAlgorithm {
    /// Whether Sequoia supports this algorithm.
    pub fn is_supported(self) -> bool {
        self.new_hasher().is_ok()
    }

    /// Creates a new hash context for this algorithm.
    ///
    /// # Errors
    ///
    /// Fails with `Error::UnsupportedHashAlgorithm` if Sequoia does
    /// not support this algorithm. See
    /// [`HashAlgorithm::is_supported`].
    ///
    ///   [`HashAlgorithm::is_supported`]: HashAlgorithm::is_supported()
    pub(crate) fn new_hasher(self) -> Result<Box<dyn Digest>> {
        let algo_name = match self {
            HashAlgorithm::SHA1 => "sha1",
            HashAlgorithm::MD5 => "md5",
            HashAlgorithm::SHA256 => "sha256",
            HashAlgorithm::SHA384 => "sha384",
            HashAlgorithm::SHA512 => "sha512",
            HashAlgorithm::SHA224 => "sha224",
            _ => return Err(crate::Error::UnsupportedHashAlgorithm(self).into()),
        };
        Ok(Box::new(KernelHasher {
            hasher: Arc::new(Mutex::new(KcapiHash::new(algo_name)?)),
            algo: self,
            update_result: Ok(()),
        }))
    }
}
