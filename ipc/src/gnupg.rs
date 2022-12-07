//! GnuPG RPC support.

#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::ffi::OsStr;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use futures::{Stream, StreamExt};

use std::task::{Poll, self};
use std::pin::Pin;

use sequoia_openpgp as openpgp;
use openpgp::types::{HashAlgorithm, Timestamp};
use openpgp::fmt::hex;
use openpgp::cert::ValidCert;
use openpgp::crypto;
use openpgp::packet::prelude::*;
use openpgp::parse::Parse;

use crate::Result;
use crate::assuan;
use crate::Keygrip;
use crate::sexp::Sexp;

/// A GnuPG context.
#[derive(Debug)]
pub struct Context {
    homedir: Option<PathBuf>,
    sockets: BTreeMap<String, PathBuf>,
    ephemeral: Option<tempfile::TempDir>,
    // XXX: Remove me once hack for Cygwin won't be necessary.
    #[cfg(windows)]
    cygwin: bool,
}

impl Context {
    /// Creates a new context for the default GnuPG home directory.
    pub fn new() -> Result<Self> {
        Self::make(None, None)
    }

    /// Creates a new context for the given GnuPG home directory.
    pub fn with_homedir<P>(homedir: P) -> Result<Self>
        where P: AsRef<Path>
    {
        Self::make(Some(homedir.as_ref()), None)
    }

    /// Creates a new ephemeral context.
    ///
    /// The created home directory will be deleted once this object is
    /// dropped.
    pub fn ephemeral() -> Result<Self> {
        Self::make(None, Some(tempfile::tempdir()?))
    }

    fn make(homedir: Option<&Path>, ephemeral: Option<tempfile::TempDir>)
            -> Result<Self> {
        let mut sockets: BTreeMap<String, PathBuf> = Default::default();

        let ephemeral_dir = ephemeral.as_ref().map(|tmp| tmp.path());
        let homedir = ephemeral_dir.or(homedir);
        // Guess if we're dealing with Unix/Cygwin or native Windows variant
        // We need to do that in order to pass paths in correct style to gpgconf
        let a_gpg_path = Self::gpgconf(&None, &["--list-dirs", "homedir"], 1)?;
        let first_byte = a_gpg_path.get(0).and_then(|c| c.get(0)).and_then(|c| c.get(0));
        let gpg_style = match first_byte {
            Some(b'/') => Mode::Unix,
            _ => Mode::native(),
        };
        let homedir = homedir.map(|dir|
            convert_path(dir, gpg_style)
                .unwrap_or_else(|_| PathBuf::from(dir))
        );

        for fields in Self::gpgconf(&homedir, &["--list-dirs"], 2)? {
            let key = std::str::from_utf8(&fields[0])?;

            // For now, we're only interested in sockets.
            let socket = match key.strip_suffix("-socket") {
                Some(socket) => socket,
                _ => continue,
            };

            // NOTE: Directories and socket paths are percent-encoded if no
            // argument to "--list-dirs" is given
            let mut value = std::str::from_utf8(&fields[1])?.to_owned();
            // FIXME: Percent-decode everything, but for now at least decode
            // colons to support Windows drive letters
            value = value.replace("%3a", ":");
            // Store paths in native format, following the least surprise rule.
            let path = convert_path(&value, Mode::native())?;

            sockets.insert(socket.into(), path);
        }

        /// Whether we're dealing with gpg that expects Windows or Unix-style paths.
        #[derive(Copy, Clone)]
        #[allow(dead_code)]
        enum Mode {
            Windows,
            Unix
        }

        impl Mode {
            fn native() -> Self {
                platform! {
                    unix => Mode::Unix,
                    windows => Mode::Windows,
                }
            }
        }

        #[cfg(not(windows))]
        fn convert_path(path: impl AsRef<OsStr>, mode: Mode) -> Result<PathBuf> {
            match mode {
                Mode::Unix => Ok(PathBuf::from(path.as_ref())),
                Mode::Windows => Err(anyhow::anyhow!(
                    "Converting to Windows-style paths is only supported on Windows"
                )),
            }
        }

        #[cfg(windows)]
        fn convert_path(path: impl AsRef<OsStr>, mode: Mode) -> Result<PathBuf> {
            let conversion_type = match mode {
                Mode::Windows => "--windows",
                Mode::Unix => "--unix",
            };
            crate::new_background_command("cygpath")
		.arg(conversion_type)
		.arg(path.as_ref())
                .output()
                .map_err(Into::into)
                .and_then(|out|
                    if out.status.success() {
                        let output = std::str::from_utf8(&out.stdout)?.trim();
                        Ok(PathBuf::from(output))
                    } else {
                        Err(anyhow::anyhow!(
                            "Executing cygpath encountered error for path {}",
                            path.as_ref().to_string_lossy()
                        ))
                    }
                )
        }

        Ok(Context {
            homedir,
            sockets,
            ephemeral,
            #[cfg(windows)]
            cygwin: cfg!(windows) && matches!(gpg_style, Mode::Unix),
        })
    }

    fn gpgconf(homedir: &Option<PathBuf>, arguments: &[&str], nfields: usize)
               -> Result<Vec<Vec<Vec<u8>>>> {
        let nl = |&c: &u8| c as char == '\n';
        let colon = |&c: &u8| c as char == ':';

        let mut gpgconf = crate::new_background_command("gpgconf");
        if let Some(homedir) = homedir {
            gpgconf.arg("--homedir").arg(homedir);

            // https://dev.gnupg.org/T4496
            gpgconf.env("GNUPGHOME", homedir);
        }

        gpgconf.args(arguments);

        let output = gpgconf.output().map_err(|e| {
            Error::GPGConf(e.to_string())
        })?;

        if output.status.success() {
            let mut result = Vec::new();
            for mut line in output.stdout.split(nl) {
                if line.is_empty() {
                    // EOF.
                    break;
                }

                // Make sure to also skip \r on Windows
                if line[line.len() - 1] == b'\r' {
                    line = &line[..line.len() - 1];
                }

                let fields =
                    line.splitn(nfields, colon).map(|f| f.to_vec())
                    .collect::<Vec<_>>();

                if fields.len() != nfields {
                    return Err(Error::GPGConf(
                        format!("Malformed response, expected {} fields, \
                                 on line: {:?}", nfields, line)).into());
                }

                result.push(fields);
            }
            Ok(result)
        } else {
            Err(Error::GPGConf(String::from_utf8_lossy(
                &output.stderr).into_owned()).into())
        }
    }

    /// Returns the path to `homedir` directory.
    ///
    /// The path returned will be in a local format, i. e. one accepted by
    /// available `gpgconf` or `gpg` tools.
    ///
    ///
    pub fn homedir(&self) -> Option<&Path> {
        self.homedir.as_deref()
    }

    /// Returns the path to a GnuPG socket.
    pub fn socket<C>(&self, socket: C) -> Result<&Path>
        where C: AsRef<str>
    {
        self.sockets.get(socket.as_ref())
            .map(|p| p.as_path())
            .ok_or_else(|| {
            Error::GPGConf(format!("No such socket {:?}",
                                   socket.as_ref())).into()
        })
    }

    /// Creates directories for RPC communication.
    pub fn create_socket_dir(&self) -> Result<()> {
        // FIXME: GnuPG as packaged by MinGW fails to create socketdir because
        // it follows upstream Unix logic, which expects Unix-like `/var/run`
        // sockets to work. Additionally, GnuPG expects to work with and set
        // correct POSIX permissions that MinGW does not even support/emulate,
        // so this fails loudly.
        // Instead, don't do anything and rely on on homedir being treated
        // (correctly) as a fallback here.
        #[cfg(windows)]
        if self.cygwin {
            return Ok(());
        }

        Self::gpgconf(&self.homedir, &["--create-socketdir"], 1)?;
        Ok(())
    }

    /// Removes directories for RPC communication.
    ///
    /// Note: This will stop all servers once they note that their
    /// socket is gone.
    pub fn remove_socket_dir(&self) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--remove-socketdir"], 1)?;
        Ok(())
    }

    /// Starts a GnuPG component.
    pub fn start(&self, component: &str) -> Result<()> {
        self.create_socket_dir()?;
        Self::gpgconf(&self.homedir, &["--launch", component], 1)?;
        Ok(())
    }

    /// Stops a GnuPG component.
    pub fn stop(&self, component: &str) -> Result<()> {
        Self::gpgconf(&self.homedir, &["--kill", component], 1)?;
        Ok(())
    }

    /// Stops all GnuPG components.
    pub fn stop_all(&self) -> Result<()> {
        self.stop("all")
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        if self.ephemeral.is_some() {
            let _ = self.stop_all();
            let _ = self.remove_socket_dir();
        }
    }
}

/// A connection to a GnuPG agent.
pub struct Agent {
    c: assuan::Client,
}

impl Deref for Agent {
    type Target = assuan::Client;

    fn deref(&self) -> &Self::Target {
        &self.c
    }
}

impl DerefMut for Agent {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.c
    }
}

impl Stream for Agent {
    type Item = Result<assuan::Response>;

    /// Attempt to pull out the next value of this stream, returning
    /// None if the stream is finished.
    ///
    /// Note: It _is_ safe to call this again after the stream
    /// finished, i.e. returned `Ready(None)`.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.c).poll_next(cx)
    }
}

impl Agent {
    /// Connects to the agent.
    ///
    /// Note: This function does not try to start the server.  If no
    /// server is running for the given context, this operation will
    /// fail.
    pub async fn connect(ctx: &Context) -> Result<Self> {
        let path = ctx.socket("agent")?;
        Self::connect_to(path).await
    }

    /// Connects to the agent at the given path.
    ///
    /// Note: This function does not try to start the server.  If no
    /// server is running for the given context, this operation will
    /// fail.
    pub async fn connect_to<P>(path: P) -> Result<Self>
        where P: AsRef<Path>
    {
        Ok(Agent { c: assuan::Client::connect(path).await? })
    }

    /// Creates a signature over the `digest` produced by `algo` using
    /// `key` with the secret bits managed by the agent.
    pub async fn sign<'a>(&'a mut self,
                          key: &'a KeyPair,
                          algo: HashAlgorithm, digest: &'a [u8])
        -> Result<crypto::mpi::Signature>
    {
        for option in Self::options() {
            self.send_simple(option).await?;
        }

        let grip = Keygrip::of(key.public.mpis())?;
        self.send_simple(format!("SIGKEY {}", grip)).await?;
        self.send_simple(
            format!("SETKEYDESC {}",
                    assuan::escape(&key.password_prompt))).await?;

        let algo = u8::from(algo);
        let digest = hex::encode(&digest);
        self.send_simple(format!("SETHASH {} {}", algo, digest)).await?;
        self.send("PKSIGN")?;

        let mut data = Vec::new();
        while let Some(r) = self.next().await {
            match r? {
                assuan::Response::Ok { .. }
                | assuan::Response::Comment { .. }
                | assuan::Response::Status { .. } =>
                    (), // Ignore.
                assuan::Response::Error { ref message, .. } =>
                    return assuan::operation_failed(self, message).await,
                assuan::Response::Data { ref partial } =>
                    data.extend_from_slice(partial),
                r =>
                    return assuan::protocol_error(&r),
            }
        }

        Sexp::from_bytes(&data)?.to_signature()
    }

    /// Decrypts `ciphertext` using `key` with the secret bits managed
    /// by the agent.
    pub async fn decrypt<'a>(&'a mut self,
                          key: &'a KeyPair,
                          ciphertext: &'a crypto::mpi::Ciphertext)
        -> Result<crypto::SessionKey>
    {
        for option in Self::options() {
            self.send_simple(option).await?;
        }

        let grip = Keygrip::of(key.public.mpis())?;
        self.send_simple(format!("SETKEY {}", grip)).await?;
        self.send_simple(format!("SETKEYDESC {}",
                                  assuan::escape(&key.password_prompt))).await?;
        self.send("PKDECRYPT")?;
        while let Some(r) = self.next().await {
            match r? {
                assuan::Response::Inquire { ref keyword, .. }
                if keyword == "CIPHERTEXT" =>
                    (), // What we expect.
                assuan::Response::Comment { .. }
                | assuan::Response::Status { .. } =>
                    (), // Ignore.
                assuan::Response::Error { ref message, .. } =>
                    return assuan::operation_failed(self, message).await,
                r =>
                    return assuan::protocol_error(&r),
            }
        }

        let mut buf = Vec::new();
        Sexp::try_from(ciphertext)?.serialize(&mut buf)?;
        self.data(&buf)?;
        let mut padding = true;
        let mut data = Vec::new();
        while let Some(r) = self.next().await {
            match r? {
                assuan::Response::Ok { .. }
                | assuan::Response::Comment { .. } =>
                    (), // Ignore.
                assuan::Response::Status { ref keyword, ref message } =>
                    if keyword == "PADDING" {
                        padding = message != "0";
                    },
                assuan::Response::Error { ref message, .. } =>
                    return assuan::operation_failed(self, message).await,
                assuan::Response::Data { ref partial } =>
                    data.extend_from_slice(partial),
                r =>
                    return assuan::protocol_error(&r),
            }
        }

        // Get rid of the safety-0.
        //
        // gpg-agent seems to add a trailing 0, supposedly for good
        // measure.
        if data.iter().last() == Some(&0) {
            let l = data.len();
            data.truncate(l - 1);
        }

        Sexp::from_bytes(&data)?.finish_decryption(
            &key.public, ciphertext, padding)
    }

    /// Computes options that we want to communicate.
    fn options() -> Vec<String> {
        use std::env::var;

        let mut r = Vec::new();

        if let Ok(tty) = var("GPG_TTY") {
            r.push(format!("OPTION ttyname={}", tty));
        } else {
            #[cfg(unix)]
            unsafe {
                use std::ffi::CStr;
                let tty = libc::ttyname(0);
                if ! tty.is_null() {
                    if let Ok(tty) = CStr::from_ptr(tty).to_str() {
                        r.push(format!("OPTION ttyname={}", tty));
                    }
                }
            }
        }

        if let Ok(term) = var("TERM") {
            r.push(format!("OPTION ttytype={}", term));
        }

        if let Ok(display) = var("DISPLAY") {
            r.push(format!("OPTION display={}", display));
        }

        if let Ok(xauthority) = var("XAUTHORITY") {
            r.push(format!("OPTION xauthority={}", xauthority));
        }

        if let Ok(dbus) = var("DBUS_SESSION_BUS_ADDRESS") {
            r.push(format!("OPTION putenv=DBUS_SESSION_BUS_ADDRESS={}", dbus));
        }

        // We're going to pop() options off the end, therefore reverse
        // the vec here to preserve the above ordering, which is the
        // one GnuPG uses.
        r.reverse();
        r
    }
}

/// A cryptographic key pair.
///
/// A `KeyPair` is a combination of public and secret key.  This
/// particular implementation does not have the secret key, but
/// diverges the cryptographic operations to `gpg-agent`.
pub struct KeyPair {
    public: Key<key::PublicParts, key::UnspecifiedRole>,
    agent_socket: PathBuf,
    password_prompt: String,
}

impl KeyPair {
    /// Returns a `KeyPair` for `key` with the secret bits managed by
    /// the agent.
    ///
    /// This provides a convenient, synchronous interface for use with
    /// the low-level Sequoia crate.
    pub fn new<R>(ctx: &Context, key: &Key<key::PublicParts, R>)
                  -> Result<KeyPair>
        where R: key::KeyRole
    {
        Ok(KeyPair {
            password_prompt: format!(
                "Please enter the passphrase to \
                 unlock the OpenPGP secret key:\n\
                 ID {:X}, created {}.",
                key.keyid(), Timestamp::try_from(key.creation_time()).unwrap()),
            public: key.role_as_unspecified().clone(),
            agent_socket: ctx.socket("agent")?.into(),
        })
    }

    /// Changes the password prompt to include information about the
    /// cert.
    ///
    /// Use this function to give more context to the user when she is
    /// prompted for a password.  This function will generate a prompt
    /// that is very similar to the prompts that GnuPG generates.
    ///
    /// To set an arbitrary password prompt, use
    /// [`KeyPair::with_password_prompt`].
    pub fn with_cert(self, cert: &ValidCert) -> Self {
        let primary_id = cert.keyid();
        let keyid = self.public.keyid();
        let prompt = match (primary_id == keyid,
                            cert.primary_userid()
                            .map(|uid| uid.clone())
                            .ok())
        {
            (true, Some(uid)) => format!(
                "Please enter the passphrase to \
                 unlock the OpenPGP secret key:\n\
                 {}\n\
                 ID {:X}, created {}.",
                uid.userid(),
                keyid,
                Timestamp::try_from(self.public.creation_time())
                    .expect("creation time is representable"),
            ),
            (false, Some(uid)) => format!(
                "Please enter the passphrase to \
                 unlock the OpenPGP secret key:\n\
                 {}\n\
                 ID {:X}, created {} (main key ID {}).",
                uid.userid(),
                keyid,
                Timestamp::try_from(self.public.creation_time())
                    .expect("creation time is representable"),
                primary_id,
            ),
            (true, None) => format!(
                "Please enter the passphrase to \
                 unlock the OpenPGP secret key:\n\
                 ID {:X}, created {}.",
                keyid,
                Timestamp::try_from(self.public.creation_time())
                    .expect("creation time is representable"),
            ),
            (false, None) => format!(
                "Please enter the passphrase to \
                 unlock the OpenPGP secret key:\n\
                 ID {:X}, created {} (main key ID {}).",
                keyid,
                Timestamp::try_from(self.public.creation_time())
                    .expect("creation time is representable"),
                primary_id,
            ),
        };
        self.with_password_prompt(prompt)
    }

    /// Changes the password prompt.
    ///
    /// Use this function to give more context to the user when she is
    /// prompted for a password.
    ///
    /// To set an password prompt that uses information from the
    /// OpenPGP certificate, use [`KeyPair::with_cert`].
    pub fn with_password_prompt(mut self, prompt: String) -> Self {
        self.password_prompt = prompt;
        self
    }
}

impl crypto::Signer for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public
    }

    fn sign(&mut self, hash_algo: HashAlgorithm, digest: &[u8])
            -> openpgp::Result<openpgp::crypto::mpi::Signature>
    {
        use crate::openpgp::types::PublicKeyAlgorithm::*;
        use crate::openpgp::crypto::mpi::PublicKey;

        #[allow(deprecated)]
        match (self.public.pk_algo(), self.public.mpis())
        {
            (RSASign, PublicKey::RSA { .. })
                | (RSAEncryptSign, PublicKey::RSA { .. })
                | (DSA, PublicKey::DSA { .. })
                | (EdDSA, PublicKey::EdDSA { .. })
                | (ECDSA, PublicKey::ECDSA { .. }) => {
                    let rt = tokio::runtime::Runtime::new()?;

                    rt.block_on(async move {
                        let mut a = Agent::connect_to(&self.agent_socket).await?;
                        let sig = a.sign(self, hash_algo, digest).await?;
                        Ok(sig)
                    })
                },

            (pk_algo, _) => Err(openpgp::Error::InvalidOperation(format!(
                "unsupported combination of algorithm {:?} and key {:?}",
                pk_algo, self.public)).into()),
        }
    }
}

impl crypto::Decryptor for KeyPair {
    fn public(&self) -> &Key<key::PublicParts, key::UnspecifiedRole> {
        &self.public
    }

    fn decrypt(&mut self, ciphertext: &crypto::mpi::Ciphertext,
               _plaintext_len: Option<usize>)
               -> openpgp::Result<crypto::SessionKey>
    {
        use crate::openpgp::crypto::mpi::{PublicKey, Ciphertext};

        match (self.public.mpis(), ciphertext) {
            (PublicKey::RSA { .. }, Ciphertext::RSA { .. })
                | (PublicKey::ElGamal { .. }, Ciphertext::ElGamal { .. })
                | (PublicKey::ECDH { .. }, Ciphertext::ECDH { .. }) => {
                    let rt = tokio::runtime::Runtime::new()?;

                    rt.block_on(async move {
                        let mut a = Agent::connect_to(&self.agent_socket).await?;
                        let sk = a.decrypt(self, ciphertext).await?;
                        Ok(sk)
                    })
                },

            (public, ciphertext) =>
                Err(openpgp::Error::InvalidOperation(format!(
                    "unsupported combination of key pair {:?} \
                     and ciphertext {:?}",
                    public, ciphertext)).into()),
        }
    }
}


#[derive(thiserror::Error, Debug)]
/// Errors used in this module.
pub enum Error {
    /// Errors related to `gpgconf`.
    #[error("gpgconf: {0}")]
    GPGConf(String),
    /// The remote operation failed.
    #[error("Operation failed: {0}")]
    OperationFailed(String),
    /// The remote party violated the protocol.
    #[error("Protocol violation: {0}")]
    ProtocolError(String),

}
