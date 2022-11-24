use openpgp::KeyHandle;
use sequoia_openpgp as openpgp;

/// Result specialization
pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The certificate was not found in the store
    #[error("Certificate not in store: {keyhandle}")]
    CertNotFound { keyhandle: KeyHandle },

    /// A CertD error occurred
    #[error("CertD error")]
    CertDError(#[from] openpgp_cert_d::Error),

    /// A trust-root error
    #[error(transparent)]
    TrustRootError(#[from] TrustRootError),

    /// An IO error occurred
    #[error("IO error")]
    IoError(#[from] std::io::Error),

    /// Other kind of Error
    #[error(transparent)]
    Other(#[from] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(thiserror::Error, Debug)]
pub enum TrustRootError {
    /// The trust root must be certification capable
    #[error("The trust-root must be certification-capable.")]
    NotCertificationCapable,

    /// There is no trust-root
    #[error("No trust-root certificate found.")]
    NoTrustRoot,

    /// Trust-root is not valid
    #[error("Invalid trust-root.")]
    InvalidTrustRoot,
}

pub(crate) type SequoiaOpenpgpError = Box<dyn std::error::Error + Send + Sync>;
