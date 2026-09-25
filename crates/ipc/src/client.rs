//! The client half: what the application and the in-bundle command line
//! interface use to talk to the daemon.
//!
//! One connection, one handshake, then id'd requests and their answers, or one
//! subscribe stream. A daemon that does not answer is not an error to report
//! and move on from: it is Protection off, and [`ClientError::unreachable`]
//! says which.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use agentsweep_core::quarantine::Conflict;

use crate::protocol::{
    ActionReport, Hello, Message, Refusal, Request, RequestError, RevealedReceipt, Role,
    StateEvent, Status, receipts_from_value,
};
use crate::socket::{Connection, connect, default_socket_path};

/// Why a client could not be answered.
#[derive(Debug)]
pub enum ClientError {
    /// No daemon is listening, which is Protection off.
    Unreachable(io::Error),
    /// The connection failed after it was made.
    Io(io::Error),
    /// The daemon refused the handshake.
    Refused(Refusal),
    /// The daemon answered the request with a reason not to.
    Request(RequestError),
    /// The daemon answered something other than what was asked for.
    Unexpected(String),
}

impl ClientError {
    /// True when there is no daemon to talk to, which the user is shown as
    /// Protection being off rather than as a failure.
    pub fn is_unreachable(&self) -> bool {
        matches!(self, ClientError::Unreachable(_))
    }

    /// The sentence a person reads under "Protection is off".
    pub fn unreachable(&self) -> String {
        match self {
            ClientError::Unreachable(_) => "no daemon answered".to_string(),
            other => other.to_string(),
        }
    }
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Unreachable(error) => write!(f, "no daemon answered: {error}"),
            ClientError::Io(error) => write!(f, "the connection failed: {error}"),
            ClientError::Refused(refusal) => f.write_str(&refusal.message()),
            ClientError::Request(error) => f.write_str(&error.message),
            ClientError::Unexpected(detail) => {
                write!(f, "the daemon answered something else: {detail}")
            }
        }
    }
}

impl std::error::Error for ClientError {}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> ClientError {
        ClientError::Io(error)
    }
}

/// A connected client that has shaken hands with the daemon.
#[derive(Debug)]
pub struct Client {
    connection: Connection,
    socket: PathBuf,
    next_id: u64,
}

impl Client {
    /// Connects to the daemon at the documented socket and shakes hands.
    pub fn connect(role: Role) -> Result<Client, ClientError> {
        Client::connect_at(&default_socket_path(), role)
    }

    /// The same at a socket of the caller's choosing, which is how a test and
    /// a hand run reach a daemon that is not the installed one.
    pub fn connect_at(socket: &Path, role: Role) -> Result<Client, ClientError> {
        let mut connection = connect(socket).map_err(ClientError::Unreachable)?;
        connection.send(&Message::Hello(Hello::of(role)))?;
        match connection.receive()? {
            Some(Message::Welcome { .. }) => Ok(Client {
                connection,
                socket: socket.to_path_buf(),
                next_id: 1,
            }),
            Some(Message::Refused(refusal)) => Err(ClientError::Refused(refusal)),
            Some(other) => Err(ClientError::Unexpected(format!("{other:?}"))),
            // A daemon that closes the connection without a word is one that
            // is going away, which is the same to a client as one that was
            // never there.
            None => Err(ClientError::Unreachable(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the daemon closed the connection during the handshake",
            ))),
        }
    }

    /// Which socket this client is talking to.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Health, the last Scan summary and the Findings that stand.
    pub fn status(&mut self) -> Result<Status, ClientError> {
        let answer = self.ask(Request::Status)?;
        Status::from_value(&answer)
            .ok_or_else(|| ClientError::Unexpected("the status could not be read".to_string()))
    }

    /// Asks for a Full Scan and returns once it has been taken on, not once it
    /// has finished. A Full Scan that is already running or waiting is joined,
    /// which the answer says: true when this request started one, false when
    /// it joined one.
    pub fn scan_now(&mut self) -> Result<bool, ClientError> {
        let answer = self.ask(Request::ScanNow)?;
        answer
            .get("started")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| ClientError::Unexpected("the answer could not be read".to_string()))
    }

    /// Takes the Item of one Threat Finding out of its Surface. The target is
    /// a Finding id, or the id of an Item with one open Threat Finding.
    pub fn quarantine(&mut self, target: &str) -> Result<ActionReport, ClientError> {
        self.act(Request::Quarantine {
            target: target.to_string(),
        })
    }

    /// Puts a quarantined Item back. The target is a Receipt id, or the id of
    /// a Finding or an Item that one Receipt stopped.
    pub fn restore(
        &mut self,
        target: &str,
        conflict: Conflict,
    ) -> Result<ActionReport, ClientError> {
        self.act(Request::Restore {
            target: target.to_string(),
            conflict,
        })
    }

    /// Calls the content of one Finding's Item safe, bound to its hash.
    pub fn trust(&mut self, target: &str) -> Result<ActionReport, ClientError> {
        self.act(Request::Trust {
            target: target.to_string(),
        })
    }

    /// Answers a Drift Finding with "that was me".
    pub fn acknowledge(&mut self, target: &str) -> Result<ActionReport, ClientError> {
        self.act(Request::Acknowledge {
            target: target.to_string(),
        })
    }

    /// The one-click fix of Exposures 0018 and 0019.
    pub fn fix(&mut self, target: &str) -> Result<ActionReport, ClientError> {
        self.act(Request::Fix {
            target: target.to_string(),
        })
    }

    /// Switches a quarantined plugin back on for its newer, clean version.
    pub fn re_enable(&mut self, target: &str) -> Result<ActionReport, ClientError> {
        self.act(Request::ReEnable {
            target: target.to_string(),
        })
    }

    /// Every Receipt in the quarantine store with the path its Item was taken
    /// from, or only those taken from at or below one path.
    pub fn reveal_receipts(
        &mut self,
        path: Option<&str>,
    ) -> Result<Vec<RevealedReceipt>, ClientError> {
        let answer = self.ask(Request::RevealReceipt {
            path: path.map(str::to_string),
        })?;
        receipts_from_value(&answer)
            .ok_or_else(|| ClientError::Unexpected("the Receipts could not be read".to_string()))
    }

    /// Whether the Rule Feed toggle is on.
    pub fn rule_feed(&mut self) -> Result<bool, ClientError> {
        self.feed(Request::RuleFeed { enabled: None })
    }

    /// Turns the Rule Feed on or off, and answers with where it stands now.
    /// Off means no request at all and the bundled Rule Pack only.
    pub fn set_rule_feed(&mut self, enabled: bool) -> Result<bool, ClientError> {
        self.feed(Request::RuleFeed {
            enabled: Some(enabled),
        })
    }

    fn feed(&mut self, request: Request) -> Result<bool, ClientError> {
        let answer = self.ask(request)?;
        answer
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| ClientError::Unexpected("the answer could not be read".to_string()))
    }

    fn act(&mut self, request: Request) -> Result<ActionReport, ClientError> {
        let answer = self.ask(request)?;
        ActionReport::from_value(&answer)
            .ok_or_else(|| ClientError::Unexpected("the answer could not be read".to_string()))
    }

    /// Turns the connection into a stream of state events.
    ///
    /// A subscribed connection carries no more requests: the daemon writes
    /// events on it until the client goes away. A client that wants both keeps
    /// two connections, which is what the application does.
    pub fn subscribe(mut self) -> Result<Subscription, ClientError> {
        self.ask(Request::Subscribe)?;
        Ok(Subscription {
            connection: self.connection,
        })
    }

    fn ask(&mut self, request: Request) -> Result<serde_json::Value, ClientError> {
        let id = self.next_id.to_string();
        self.next_id += 1;
        self.connection.send(&Message::Request {
            id: id.clone(),
            request,
        })?;
        loop {
            match self.connection.receive()? {
                Some(Message::Response {
                    id: answered,
                    result,
                }) if answered == id => {
                    return result.map_err(ClientError::Request);
                }
                // An event may arrive between a request and its answer on a
                // connection that is also subscribed. It is not this answer.
                Some(Message::Event(_)) => {}
                Some(other) => return Err(ClientError::Unexpected(format!("{other:?}"))),
                None => {
                    return Err(ClientError::Io(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "the daemon closed the connection before answering",
                    )));
                }
            }
        }
    }
}

/// A connection the daemon writes state events on until it is dropped.
#[derive(Debug)]
pub struct Subscription {
    connection: Connection,
}

impl Subscription {
    /// The next event, `None` when the daemon closed the stream.
    pub fn next_event(&mut self) -> Result<Option<StateEvent>, ClientError> {
        match self.connection.receive()? {
            Some(Message::Event(event)) => Ok(Some(event)),
            Some(other) => Err(ClientError::Unexpected(format!("{other:?}"))),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_socket_nothing_is_listening_on_reads_as_protection_off() {
        let nowhere =
            std::env::temp_dir().join(format!("agentsweep-ipc-nobody-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&nowhere);
        let error = Client::connect_at(&nowhere, Role::Cli).expect_err("nobody is listening");
        assert!(error.is_unreachable(), "{error}");
        assert_eq!(error.unreachable(), "no daemon answered");
    }

    /// The version check is the client's as much as the daemon's: both sides
    /// of the handshake read the same function.
    #[test]
    fn the_handshake_this_build_sends_is_the_one_it_would_accept() {
        assert!(crate::protocol::check_version(&Hello::of(Role::App)).is_ok());
    }
}
