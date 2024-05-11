//! GnuPG RPC support.

#![warn(missing_docs)]

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use crate::Result;

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
        let _ = self.create_socket_dir(); // Best effort.
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
