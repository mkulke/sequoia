use openpgp::Fingerprint;
use sequoia_openpgp as openpgp;

/// Result specialization
pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The certificate was not found in the store
    #[error("Certificate not in store: {fingerprint}")]
    CertNotFound { fingerprint: Fingerprint },
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
