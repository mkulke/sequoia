//! Unix Domain Socket emulation for Windows.

use std::io::Read;
use std::path::Path;
use std::fs::File;

use anyhow::anyhow;
use anyhow::Context;

use crate::Result;

/// Socket connection data.
#[derive(Debug)]
pub struct Rendezvous {
    pub port: u16,
    pub uds_emulation: UdsEmulation,
    pub nonce: [u8; 16],
}

/// Unix domain socket emulation type (Windows only).
///
/// Until Windows 10 Update 1803, Windows did not support native UNIX domain
/// sockets. To work around that, developers historically used TCP (readily
/// available) connection coupled with an authentication nonce (or "cookie").
#[derive(Debug)]
pub enum UdsEmulation {
    /// Cygwin socket emulation.
    ///
    /// File format: `!<socket >%u %c %08x-%08x-%08x-%08x` (scanf style)
    /// %u: local TCP port
    /// %c: socket type ("s" for `SOCK_STREAM`, "d" for `SOCK_DGRAM`)
    /// %08x-%08x-%08x-%08x: authentication nonce
    ///
    /// Starting with client, both sides first exchange the 16-byte authentication
    /// nonce, after which they exchange `ucred` structure (socket.h).
    Cygwin,
    /// Libassuan's custom socket emulation.
    ///
    /// File format: `<PORT>\n<NONCE>`
    /// PORT: textual local TCP port (e.g. "12345")
    /// NONCE: raw 16-byte authentication nonce
    ///
    /// After connecting, client has to authenticate itself by sending the
    /// 16-byte authentication nonce.
    Libassuan,
}

/// Reads socket connection info from a Windows file emulating a Unix socket.
///
/// Inspired by `read_port_and nonce` from assuan-socket.c.
pub fn read_port_and_nonce(fname: &Path) -> Result<Rendezvous> {
    let mut file = File::open(fname).with_context(|| {
        format!("Opening gpg-agent socket {}", fname.display())
    })?;
    // Socket connection info will be in either a <= 54 byte long Cygwin format
    // or ~5+1+16 (modulo whitespace separators) custom libassuan format
    let mut contents = Vec::with_capacity(64);
    file.read_to_end(&mut contents)?;

    read_port_and_nonce_from_string(&contents)
}

fn read_port_and_nonce_from_string(contents: &[u8]) -> Result<Rendezvous> {
    let maybe_utf8 = std::str::from_utf8(contents).ok();

    match maybe_utf8.and_then(|buf| buf.strip_prefix("!<socket >")) {
        // libassuan's Cygwin compatible socket emulation.
        // Format: "!<socket >%u %c %08x-%08x-%08x-%08x\x00" (scanf-like)
        Some(buf) => {
            let opt_skip_nul = buf.strip_suffix('\x00').unwrap_or(buf);
            // Split into parts: port, kind of socket and nonce
            let mut iter = opt_skip_nul.split_terminator(' ');
            match (iter.next(), iter.next(), iter.next()) {
                (Some(port), Some("s"), Some(nonce)) => {
                    let port = port.parse()?;

                    // This is wasteful but an allocation-free alternative is
                    // even more verbose and also does not warrant pulling a
                    // hex string parser dependency.
                    let nonce_chunks = nonce.split_terminator('-')
                        .map(|dword| u32::from_str_radix(dword, 16).map_err(Into::into))
                        .collect::<Result<Vec<_>>>();

                    let nonce = match nonce_chunks.ok().as_deref() {
                        Some(&[d0, d1, d2, d3, ..]) => {
                            let mut nonce = [0u8; 16];
                            nonce[0..4].copy_from_slice(&d0.to_ne_bytes());
                            nonce[4..8].copy_from_slice(&d1.to_ne_bytes());
                            nonce[8..12].copy_from_slice(&d2.to_ne_bytes());
                            nonce[12..16].copy_from_slice(&d3.to_ne_bytes());
                            nonce
                        },
                        _ => return Err(anyhow!("Couldn't parse Cygwin socket nonce: {}", nonce)),
                    };
                    Ok(Rendezvous { port, nonce, uds_emulation: UdsEmulation::Cygwin })
                },
                _ => Err(anyhow!("Couldn't parse Cygwin socket: {}", buf)),
            }
        },
        // libassuan's own socket emulation
        // Format: [<whitespace>?, port, .., '\n', <16 byte nonce>]
        None => {
            let pos = match contents.iter().position(|&x| x == b'\n') {
                // Also ensure that there are exactly 16 bytes following
                Some(pos) if pos + 1 + 16 == contents.len() => pos,
                _ => return Err(anyhow!("Malformed socket description: {:?}", contents)),
            };
            let port = std::str::from_utf8(&contents[..pos])?.trim().parse()?;
            let mut nonce = [0u8; 16];
            nonce[..].copy_from_slice(&contents[pos + 1..]);

            Ok(Rendezvous { port, nonce, uds_emulation: UdsEmulation::Libassuan })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_port_and_nonce() -> Result<()> {
        let test_fn = super::read_port_and_nonce_from_string;
        assert!(test_fn(b"\t 12 \n1234567890123456").is_ok());
        assert!(test_fn(b"\t 12 \n123456789012345").is_err());
        assert!(test_fn(b"\t 12 \n12345678901234567").is_err());

        assert!(matches!(
            test_fn(b"  12345\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
            Ok(Rendezvous {
                port: 12345,
                uds_emulation: UdsEmulation::Libassuan,
                nonce: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            })
        ));
        assert!(matches!(
            test_fn(b"  -152\n\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"),
            Err(..)
        ));

        assert!(matches!(
            test_fn(b"!<socket >12345 s AABBCCDD-DDCCBBAA-01234567-890ABCDE\x00"),
            Ok(Rendezvous {
                port: 12345,
                uds_emulation: UdsEmulation::Cygwin,
                nonce: [
                    0xDD, 0xCC, 0xBB, 0xAA,
                    0xAA, 0xBB, 0xCC, 0xDD,
                    0x67, 0x45, 0x23, 0x01,
                    0xDE, 0xBC, 0x0A, 0x89,
                ]
            })
        ));
        assert!(matches!(
            test_fn(b"!<socket >12345 s AABBCCDD-DDCCBBAA-01234567-890ABCDE"),
            Ok(Rendezvous {
                port: 12345,
                uds_emulation: UdsEmulation::Cygwin,
                nonce: [
                    0xDD, 0xCC, 0xBB, 0xAA,
                    0xAA, 0xBB, 0xCC, 0xDD,
                    0x67, 0x45, 0x23, 0x01,
                    0xDE, 0xBC, 0x0A, 0x89,
                ]
            })
        ));

        Ok(())
    }
}
