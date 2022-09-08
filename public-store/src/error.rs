use openpgp::Fingerprint;
use sequoia_openpgp as openpgp;

/// Result specialization
pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The certificate was not found in the store
    #[error("Certificate not in store: {fingerprint}")]
    CertNotFound { fingerprint: Fingerprint },
    /// A trust-root error
    #[error(transparent)]
    TrustRootError(#[from] TrustRootError),
    /// A CertD error occurred
    #[error("CertD error")]
    CertDError(#[from] openpgp_cert_d::Error),
    /// An IO error occurred
    #[error("IO error")]
    IoError(#[from] std::io::Error),
    /// Any other error
    #[error(transparent)]
    Other(#[from] anyhow::Error), // source and Display delegate to anyhow::Error
}

#[derive(thiserror::Error, Debug)]
pub enum TrustRootError {
    /// The trust root must be certification capable
    #[error("The trust-root must be certification-capable.")]
    NotCertificationCapable,
    /// No trust-root found
    #[error("No trust-root found in store directory")]
    TrustRootNotFound,
}
