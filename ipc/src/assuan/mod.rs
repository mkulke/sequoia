//! Assuan RPC support.

#![warn(missing_docs)]

use std::cmp;
use std::io::Write;
use std::mem;
use std::path::Path;
use std::pin::Pin;
use std::task::{Poll, Context};

use lalrpop_util::ParseError;

use futures::{Future, Stream, StreamExt};
use tokio::io::{BufReader, ReadHalf, WriteHalf};
use tokio::io::{AsyncRead, AsyncWriteExt};

use crate::openpgp;
use openpgp::crypto::mem::Protected;

use crate::Error;
use crate::Result;

mod lexer;
mod socket;
use socket::IpcStream;

// Maximum line length of the reference implementation.
const MAX_LINE_LENGTH: usize = 1000;

// Load the generated code.
lalrpop_util::lalrpop_mod!(
    #[allow(clippy::all)]
    #[allow(missing_docs, unused_parens)]
    grammar,
    "/assuan/grammar.rs"
);

/// A connection to an Assuan server.
///
/// Commands may be issued using [`Connection::send`].  Note that the
/// command is sent lazily, i.e. it is only sent if you poll for the
/// responses.
///
/// [`Connection::send`]: Client::send()
///
/// `Client` implements [`Stream`] to return all server responses
/// until the first [`Response::Ok`], [`Response::Error`], or
/// [`Response::Inquire`].
///
/// [`Stream`]: #impl-Stream
///
/// [`Response::Ok`] and [`Response::Error`] indicate success and
/// failure.  [`Response::Inquire`] means that the server requires
/// more information to complete the request.  This information may be
/// provided using [`Connection::data()`], or the operation may be
/// canceled using [`Connection::cancel()`].
///
/// [`Connection::data()`]: Client::data()
/// [`Connection::cancel()`]: Client::cancel()
pub struct Client {
    r: BufReader<ReadHalf<IpcStream>>, // xxx: abstract over
    buffer: Vec<u8>,
    done: bool,
    w: WriteState,
    trace_send: Option<Box<dyn Fn(&[u8]) + Send + Sync>>,
    trace_receive: Option<Box<dyn Fn(&[u8]) + Send + Sync>>,
}
assert_send_and_sync!(Client);

enum WriteState {
    Ready(WriteHalf<IpcStream>),
    Sending(Pin<Box<dyn Future<Output = Result<WriteHalf<IpcStream>>>
                    + Send + Sync>>),
    Transitioning,
    Dead,
}
assert_send_and_sync!(WriteState);

impl std::fmt::Debug for WriteState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>)
        -> std::result::Result<(), std::fmt::Error>
    {
        use WriteState::*;
        match self {
            Ready(_) => write!(f, "WriteState::Ready"),
            Sending(_) => write!(f, "WriteState::Sending"),
            Transitioning => write!(f, "WriteState::Transitioning"),
            Dead => write!(f, "WriteState::Dead"),
        }
    }
}

/// Percent-escapes the given string.
pub fn escape<S: AsRef<str>>(s: S) -> String {
    let mut r = String::with_capacity(s.as_ref().len());
    for c in s.as_ref().chars() {
        match c {
            '%' => r.push_str("%25"),
            ' ' => r.push('+'),
            n if n.is_ascii() && (n as u8) < 32 =>
                r.push_str(&format!("%{:02X}", n as u8)),
            _ => r.push(c),
        }
    }
    r
}

impl Client {
    /// Connects to the server.
    pub async fn connect<P>(path: P) -> Result<Client> where P: AsRef<Path> {
        let connection = socket::sock_connect(path)?;
        Ok(ConnectionFuture::new(connection).await?)
    }

    /// Lazily sends a command to the server.
    ///
    /// For the command to be actually executed, stream the responses
    /// using this objects [`Stream`] implementation.
    ///
    /// Note: It is very important to poll the client object until it
    /// returns `None`.  Otherwise, the server and client will lose
    /// synchronization, and requests and responses will no longer be
    /// correctly associated.
    ///
    /// [`Stream`]: #impl-Stream
    ///
    /// The response stream ends in either a [`Response::Ok`],
    /// [`Response::Error`], or [`Response::Inquire`].  `Ok` and
    /// `Error` indicate success and failure of the current operation.
    /// `Inquire` means that the server requires more information to
    /// complete the request.  This information may be provided using
    /// [`Connection::data()`], or the operation may be canceled using
    /// [`Connection::cancel()`].
    ///
    /// [`Response::Ok`]: super::assuan::Response::Ok
    /// [`Response::Error`]: super::assuan::Response::Error
    /// [`Response::Inquire`]: super::assuan::Response::Inquire
    /// [`Connection::data()`]: Client::data()
    /// [`Connection::cancel()`]: Client::cancel()
    ///
    /// Note: `command` is passed as-is.  Control characters, like
    /// `%`, must be %-escaped using [`escape`].
    pub fn send<'a, C: 'a>(&'a mut self, command: C) -> Result<()>
        where C: AsRef<[u8]>
    {
        if let WriteState::Sending(_) = self.w {
            return Err(openpgp::Error::InvalidOperation(
                "Busy, poll responses first".into()).into());
        }

        self.w =
            match mem::replace(&mut self.w, WriteState::Transitioning)
        {
            WriteState::Ready(mut sink) => {
                let command = command.as_ref();
                let mut c = command.to_vec();
                if ! c.ends_with(b"\n") {
                    c.push(0x0a);
                }
                if let Some(t) = self.trace_send.as_ref() {
                    t(&c);
                }
                WriteState::Sending(Box::pin(async move {
                    sink.write_all(&c).await?;
                    Ok(sink)
                }))
            },
            WriteState::Dead => {
                // We're still dead.
                self.w = WriteState::Dead;
                return Err(crate::gnupg::Error::OperationFailed(
                    "Connection dropped".into()).into());
            }
            s => panic!("Client state machine desynchronized with servers: \
                         in {:?}, should be in WriteState::Ready", s),
        };

        Ok(())
    }

    /// Sends a simple command to the server and returns the response.
    ///
    /// This method can only be used with simple commands, i.e. those
    /// which do not require handling inquiries from the server.  To
    /// send complex commands, use [`Client::send`] and handle the
    /// inquiries.
    pub async fn send_simple<C>(&mut self, cmd: C) -> Result<Protected>
    where
        C: AsRef<str>,
    {
        self.send(cmd.as_ref())?;
        let mut data = Vec::new();
        while let Some(response) = self.next().await {
            match response? {
                Response::Data { partial } => {
                    // Securely erase partial.
                    let partial = Protected::from(partial);
                    data.extend_from_slice(&partial);
                },
                Response::Ok { .. }
                | Response::Comment { .. }
                | Response::Status { .. } =>
                    (), // Ignore.
                Response::Error { ref message, .. } =>
                    return operation_failed(self, message).await,
                response =>
                    return protocol_error(&response),
            }
        }

        Ok(data.into())
    }

    /// Lazily cancels a pending operation.
    ///
    /// For the command to be actually executed, stream the responses
    /// using this objects [`Stream`] implementation.
    ///
    /// [`Stream`]: #impl-Stream
    pub fn cancel(&mut self) -> Result<()> {
        self.send("CAN")
    }

    /// Lazily sends data in response to an inquire.
    ///
    /// For the command to be actually executed, stream the responses
    /// using this objects [`Stream`] implementation.
    ///
    /// [`Stream`]: #impl-Stream
    ///
    /// The response stream ends in either a [`Response::Ok`],
    /// [`Response::Error`], or another [`Response::Inquire`].  `Ok`
    /// and `Error` indicate success and failure of the original
    /// operation that lead to the current inquiry.
    ///
    /// [`Response::Ok`]: super::assuan::Response::Ok
    /// [`Response::Error`]: super::assuan::Response::Error
    /// [`Response::Inquire`]: super::assuan::Response::Inquire
    pub fn data<'a, C: 'a>(&'a mut self, data: C) -> Result<()>
        where C: AsRef<[u8]>
    {
        let mut data = data.as_ref();
        let mut request = Vec::with_capacity(data.len());
        while ! data.is_empty() {
            if !request.is_empty() {
                request.push(0x0a);
            }
            write!(&mut request, "D ").unwrap();
            let mut line_len = 2;
            while ! data.is_empty() && line_len < MAX_LINE_LENGTH - 3 {
                let c = data[0];
                data = &data[1..];
                match c as char {
                    '%' | '\n' | '\r' => {
                        line_len += 3;
                        write!(&mut request, "%{:02X}", c).unwrap();
                    },
                    _ => {
                        line_len += 1;
                        request.push(c);
                    },
                }
            }
        }
        write!(&mut request, "\nEND").unwrap();
        self.send(request)
    }

    /// Start tracing the data that is sent to the server.
    ///
    /// Note: if a tracing function is already registered, this
    /// replaces it.
    pub fn trace_data_sent(&mut self, fun: Box<dyn Fn(&[u8]) + Send + Sync>)
    {
        self.trace_send = Some(fun);
    }

    /// Start tracing the data that is received from the server.
    ///
    /// Note: if a tracing function is already registered, this
    /// replaces it.
    pub fn trace_data_received(&mut self, fun: Box<dyn Fn(&[u8]) + Send + Sync>)
    {
        self.trace_receive = Some(fun);
    }
}

/// Returns a convenient Err value for use in the state machines.
///
/// This function must only be called after the assuan server returns
/// an ERR.  message is the error message returned from the server.
/// This function first checks that the server hasn't sent anything
/// else, which would be a protocol violation.  If that is not the
/// case, it turns the message into an Err.
// XXX: It is a slight layering violation to return gnupg::Error here.
pub(crate) async fn operation_failed<T>(agent: &mut Client,
                                        message: &Option<String>)
                                        -> Result<T>
{
    if let Some(response) = agent.next().await {
        protocol_error(&response?)
    } else {
        Err(crate::gnupg::Error::OperationFailed(
            message.as_ref().map(|e| e.to_string())
                .unwrap_or_else(|| "Unknown reason".into()))
            .into())
    }
}

/// Returns a convenient Err value for use in the state machines.
// XXX: It is a slight layering violation to return gnupg::Error here.
pub(crate) fn protocol_error<T>(response: &Response) -> Result<T> {
    Err(crate::gnupg::Error::ProtocolError(
        format!("Got unexpected response {:?}", response))
        .into())
}

/// A future that will resolve to a `Client`.
struct ConnectionFuture(Option<Client>);

impl ConnectionFuture {
    fn new(c: IpcStream) -> Self {
        let (r, w) = tokio::io::split(c);
        let buffer = Vec::with_capacity(MAX_LINE_LENGTH);
        Self(Some(Client {
            r: BufReader::new(r), buffer, done: false,
            w: WriteState::Ready(w),
            trace_send: None,
            trace_receive: None,
        }))
    }
}

impl Future for ConnectionFuture {
    type Output = Result<Client>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Consume the initial message from the server.
        let client: &mut Client = self.0.as_mut().expect("future polled after completion");
        let mut responses = client.by_ref().collect::<Vec<_>>();

        match Pin::new(&mut responses).poll(cx) {
            Poll::Ready(response) => {
                Poll::Ready(match response.iter().last() {
                    Some(Ok(Response::Ok { .. })) =>
                        Ok(self.0.take().unwrap()),
                    Some(Ok(Response::Error { code, message })) =>
                        Err(Error::HandshakeFailed(
                            format!("Error {}: {:?}", code, message)).into()),
                    l @ Some(_) =>
                        Err(Error::HandshakeFailed(
                            format!("Unexpected server response: {:?}", l)
                        ).into()),
                    None => // XXX does that happen?
                        Err(Error::HandshakeFailed(
                            "No data received from server".into()).into()),
                })
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Stream for Client {
    type Item = Result<Response>;

    /// Attempt to pull out the next value of this stream, returning
    /// None if the stream is finished.
    ///
    /// Note: It _is_ safe to call this again after the stream
    /// finished, i.e. returned `Ready(None)`.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // First, handle sending of the command.
        match self.w {
            WriteState::Ready(_) =>
                (),  // Nothing to do, poll for responses below.
            WriteState::Sending(_) => {
                self.w = if let WriteState::Sending(mut f) =
                    mem::replace(&mut self.w, WriteState::Transitioning)
                {
                    match f.as_mut().poll(cx) {
                        Poll::Ready(Ok(sink)) => WriteState::Ready(sink),
                        Poll::Pending => WriteState::Sending(f),
                        Poll::Ready(Err(e)) => {
                            self.w = WriteState::Dead;
                            return Poll::Ready(Some(Err(e)));
                        },
                    }
                } else {
                    unreachable!()
                };
            },
            WriteState::Transitioning =>
                unreachable!(),
            WriteState::Dead =>
                (),  // Nothing left to do, poll for responses below.
        }

        // Recheck if we are still sending the command.
        if let WriteState::Sending(_) = self.w {
            return Poll::Pending;
        }

        // Check if the previous response was one of ok, error, or
        // inquire.
        if self.done {
            // If so, we signal end of stream here.
            self.done = false;
            return Poll::Ready(None);
        }

        // The compiler is not smart enough to figure out disjoint borrows
        // through Pin via DerefMut (which wholly borrows `self`), so unwrap it
        let Self { buffer, done, r, trace_receive, .. } = Pin::into_inner(self);
        let mut reader = Pin::new(r);
        loop {
            // Try to yield a line from the buffer.  For that, try to
            // find linebreaks.
            if let Some(p) = buffer.iter().position(|&b| b == 0x0a) {
                let line: Vec<u8> = buffer.drain(..p+1).collect();
                // xxx: rtrim linebreak even more? crlf maybe?
                if let Some(t) = trace_receive {
                    t(&line[..line.len()-1]);
                }
                let r = Response::parse(&line[..line.len()-1])?;
                // If this response is one of ok, error, or inquire,
                // we want to surrender control to the client next
                // time she asks for an item.
                *done = r.is_done();
                return Poll::Ready(Some(Ok(r)));
            }

            // No more linebreaks in the buffer.  We need to get more.
            // First, get a new read buffer.
            // Later, append the read data to the Client's buffer

            let mut vec = vec![0u8; MAX_LINE_LENGTH];
            let mut read_buf = tokio::io::ReadBuf::new(&mut vec);

            match reader.as_mut().poll_read(cx, &mut read_buf)? {
                Poll::Ready(()) => {
                    if read_buf.filled().is_empty() {
                        // End of stream.
                        return Poll::Ready(None)
                    } else {
                        buffer.extend_from_slice(read_buf.filled());
                        continue;
                    }
                },

                Poll::Pending => {
                    return Poll::Pending;
                },
            }
        }
    }
}

/// Server response.
#[derive(Debug, PartialEq)]
pub enum Response {
    /// Operation successful.
    Ok {
        /// Optional human-readable message.
        message: Option<String>,
    },
    /// An error occurred.
    Error {
        /// Error code.
        ///
        /// This code is defined in `libgpg-error`.
        code: usize,
        /// Optional human-readable message.
        message: Option<String>,
    },
    /// Information about the ongoing operation.
    Status {
        /// Indicates what the status message is about.
        keyword: String,
        /// Human-readable message.
        message: String,
    },
    /// A comment for debugging purposes.
    Comment {
        /// Human-readable message.
        message: String,
    },
    /// Raw data returned to the client.
    Data {
        /// A chunk of raw data.
        ///
        /// Consecutive `Data` responses must be joined.
        partial: Vec<u8>,
    },
    /// Request for information from the client.
    Inquire {
        /// The subject of the inquiry.
        keyword: String,
        /// Optional parameters.
        parameters: Option<Vec<u8>>,
    },
}

impl Response {
    /// Parses the given response.
    pub fn parse(b: &[u8]) -> Result<Response> {
        match self::grammar::ResponseParser::new().parse(lexer::Lexer::new(b)) {
            Ok(r) => Ok(r),
            Err(err) => {
                let mut msg = Vec::new();
                writeln!(&mut msg, "Parsing: {:?}: {:?}", b, err)?;
                if let ParseError::UnrecognizedToken {
                    token: (start, _, end), ..
                } = err
                {
                    writeln!(&mut msg, "Context:")?;
                    let chars = b.iter().enumerate()
                        .filter_map(|(i, c)| {
                            if cmp::max(8, start) - 8 <= i
                                && i <= end + 8
                            {
                                Some((i, c))
                            } else {
                                None
                            }
                        });
                    for (i, c) in chars {
                        writeln!(&mut msg, "{} {} {}: {:?}",
                                 if i == start { "*" } else { " " },
                                 i,
                                 *c as char,
                                 c)?;
                    }
                }
                Err(anyhow::anyhow!(
                    String::from_utf8_lossy(&msg).to_string()))
            },
        }
    }

    /// Returns true if this message indicates success.
    pub fn is_ok(&self) -> bool {
        matches!(self, Response::Ok { .. } )
    }

    /// Returns true if this message indicates an error.
    pub fn is_err(&self) -> bool {
        matches!(self, Response::Error { .. })
    }

    /// Returns true if this message is an inquiry.
    pub fn is_inquire(&self) -> bool {
        matches!(self, Response::Inquire { .. })
    }

    /// Returns true if this response concludes the server's response.
    pub fn is_done(&self) -> bool {
        // All server responses end in either OK or ERR.
        self.is_ok() || self.is_err()
        // However, the server may inquire more
        // information.  We also surrender control to the
        // caller by yielding the responses we have seen
        // so far, and allow her to respond to the
        // inquiry.
            || self.is_inquire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basics() {
        assert_eq!(
            Response::parse(b"OK Pleased to meet you, process 7745")
                .unwrap(),
            Response::Ok {
                message: Some("Pleased to meet you, process 7745".into()),
            });
        assert_eq!(
            Response::parse(b"ERR 67109139 Unknown IPC command <GPG Agent>")
                .unwrap(),
            Response::Error {
                code: 67109139,
                message :Some("Unknown IPC command <GPG Agent>".into()),
            });

        let status =
          b"S KEYINFO 151BCDB0C293927B7E36660BE47F28DA8729BD19 D - - - C - - -";
        assert_eq!(
            Response::parse(status).unwrap(),
            Response::Status {
                keyword: "KEYINFO".into(),
                message:
                    "151BCDB0C293927B7E36660BE47F28DA8729BD19 D - - - C - - -"
                    .into(),
            });

        assert_eq!(
            Response::parse(b"D (7:sig-val(3:rsa(1:s1:%25%0D)))")
                .unwrap(),
            Response::Data {
                partial: b"(7:sig-val(3:rsa(1:s1:%\x0d)))".to_vec(),
            });

        assert_eq!(
            Response::parse(b"INQUIRE CIPHERTEXT")
                .unwrap(),
            Response::Inquire {
                keyword: "CIPHERTEXT".into(),
                parameters: None,
            });
    }
}
