//! Elliptic Curve Diffie-Hellman.
use std::convert::{TryFrom, TryInto};

use crate::crypto::ecdh::{decrypt_unwrap, encrypt_wrap};
use crate::crypto::mpi;
use crate::crypto::mpi::{Ciphertext, SecretKeyMaterial};
use crate::crypto::SessionKey;
use crate::packet::{key, Key};
use crate::types::Curve;
use crate::{Error, Result};

/// Wraps a session key using Elliptic Curve Diffie-Hellman.
#[unimpl::unimpl]
pub fn encrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    session_key: &SessionKey,
) -> Result<Ciphertext>
where
    R: key::KeyRole,;

/// Unwraps a session key using Elliptic Curve Diffie-Hellman.
#[unimpl::unimpl]
pub fn decrypt<R>(
    recipient: &Key<key::PublicParts, R>,
    recipient_sec: &SecretKeyMaterial,
    ciphertext: &Ciphertext,
) -> Result<SessionKey>
where
    R: key::KeyRole,;
