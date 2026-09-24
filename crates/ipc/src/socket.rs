//! The socket itself: where it is, who may bind it and who may connect.
//!
//! `$TMPDIR/de.byte5.agentsweep.sock`, mode 0600, with a stale socket unlinked
//! at start (spec section 6.3). The path is under the per-user temporary
//! directory rather than under Application Support because `sun_path` is 104
//! bytes on macOS and a long user name would overflow a path under the data
//! directory (`docs/research/rust-stack.md` section 9).
//!
//! Nothing here is asynchronous. The daemon serves each connection on a thread
//! of its own, which is what the rest of AgentSweep is shaped like: a Scan is
//! processor-bound and a YARA-X scanner cannot move between threads, so an
//! asynchronous runtime would buy the daemon nothing and cost every crate that
//! links it.

use std::io;
use std::path::{Path, PathBuf};

use interprocess::local_socket::traits::{Listener as _, Stream as _, StreamCommon as _};
use interprocess::local_socket::{GenericFilePath, ListenerOptions, Stream, ToFsName};
use serde_json::Value;

use crate::frame::{read_frame, write_frame};
use crate::peer::Peer;
use crate::protocol::Message;

/// The file name of the socket, under the per-user temporary directory.
pub const SOCKET_NAME: &str = "de.byte5.agentsweep.sock";

/// The longest a Unix socket path may be on macOS, including the terminator.
const SUN_PATH: usize = 104;

/// Where the daemon listens: `$TMPDIR/de.byte5.agentsweep.sock`.
///
/// `std::env::temp_dir` reads `TMPDIR`, which on macOS is the per-user
/// directory launchd sets, created 0700 for the user alone.
pub fn default_socket_path() -> PathBuf {
    std::env::temp_dir().join(SOCKET_NAME)
}

/// Refuses a path a Unix socket cannot be bound at.
pub fn check_socket_path(path: &Path) -> io::Result<()> {
    let length = path.as_os_str().as_encoded_bytes().len();
    if length >= SUN_PATH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("a socket path of {length} bytes does not fit in {SUN_PATH}"),
        ));
    }
    Ok(())
}

/// One connection, either end of it.
///
/// It reads and writes whole messages and nothing else, so neither side ever
/// sees a half-message or a message the other side did not mean to send.
#[derive(Debug)]
pub struct Connection {
    stream: Stream,
    peer: Peer,
}

impl Connection {
    /// Wraps a connected stream, reading what the socket says about the peer.
    pub fn of(stream: Stream) -> Connection {
        let peer = read_peer(&stream);
        Connection { stream, peer }
    }

    /// What the socket says about the process on the other end.
    pub fn peer(&self) -> Peer {
        self.peer
    }

    /// Sends one message.
    pub fn send(&mut self, message: &Message) -> io::Result<()> {
        write_frame(&mut self.stream, &message.to_value())
    }

    /// Reads one message, `None` when the peer closed the connection cleanly.
    ///
    /// An object that is not a message of this protocol is an error: the
    /// vocabulary is closed, and something that speaks another one is not a
    /// peer to go on talking to.
    pub fn receive(&mut self) -> io::Result<Option<Message>> {
        let Some(value) = read_frame(&mut self.stream)? else {
            return Ok(None);
        };
        match Message::from_value(&value) {
            Some(message) => Ok(Some(message)),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("not a message of this protocol: {}", summarise(&value)),
            )),
        }
    }
}

/// What a message that could not be read is called in an error, which is its
/// `type` and nothing else: a field of it may be a value.
fn summarise(value: &Value) -> String {
    value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("an object with no type")
        .to_string()
}

/// The daemon's end of the socket.
///
/// Binding unlinks whatever is at the path first, because a Unix socket file
/// outlives the process that made it, and then narrows the file to the user
/// alone. macOS does not support choosing the mode before the bind, so the
/// window between the two is closed by the directory: the per-user temporary
/// directory is 0700, and the handshake refuses anything that reaches the
/// socket anyway.
#[derive(Debug)]
pub struct SocketListener {
    listener: interprocess::local_socket::Listener,
    path: PathBuf,
}

impl SocketListener {
    /// Binds the socket, replacing a stale one.
    pub fn bind(path: &Path) -> io::Result<SocketListener> {
        check_socket_path(path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A socket file is not removed when the process that bound it goes
        // away, so a daemon that was killed leaves one behind (spec section
        // 6.3).
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let name = path.to_path_buf().to_fs_name::<GenericFilePath>()?;
        let listener = ListenerOptions::new().name(name).create_sync()?;
        narrow(path)?;
        Ok(SocketListener {
            listener,
            path: path.to_path_buf(),
        })
    }

    /// Where it is listening.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Waits for the next connection.
    pub fn accept(&self) -> io::Result<Connection> {
        Ok(Connection::of(self.listener.accept()?))
    }
}

impl Drop for SocketListener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Narrows the socket file to the user alone.
#[cfg(unix)]
fn narrow(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Narrows the socket file to the user alone. Nothing to narrow here.
#[cfg(not(unix))]
fn narrow(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Connects to a daemon listening at this path.
pub fn connect(path: &Path) -> io::Result<Connection> {
    check_socket_path(path)?;
    let name = path.to_path_buf().to_fs_name::<GenericFilePath>()?;
    Ok(Connection::of(Stream::connect(name)?))
}

/// What the socket says about the peer: its user, its process and its audit
/// token.
///
/// The user comes from the credentials the socket carries. The process id and
/// the audit token do not: no portable interface answers them, and on macOS
/// they are two socket options of the Unix domain layer. A peer whose facts
/// cannot be read is left partly unknown rather than assumed, and the check
/// that reads them decides what to do about that.
fn read_peer(stream: &Stream) -> Peer {
    let uid = stream
        .peer_creds()
        .ok()
        .and_then(|credentials| credentials.euid())
        .unwrap_or(u32::MAX);
    let mut peer = Peer::of_user(uid);
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd;

        let Stream::UdSocket(socket) = stream;
        let fd = socket.as_fd();
        if let Some(pid) = macos::peer_pid(&fd) {
            peer = peer.with_pid(pid);
        }
        if let Some(token) = macos::peer_audit_token(&fd) {
            peer = peer.with_audit_token(token);
        }
    }
    peer
}

/// The two socket options of the Unix domain layer that name the peer.
///
/// `SOL_LOCAL`, `LOCAL_PEERPID` and `LOCAL_PEERTOKEN` are in `sys/un.h`. They
/// are read here rather than through a crate because none exposes them.
#[cfg(target_os = "macos")]
mod macos {
    use std::os::fd::{AsRawFd, BorrowedFd};

    /// The protocol level the options below sit at.
    const SOL_LOCAL: libc::c_int = 0;
    /// Retrieves the peer's process id.
    const LOCAL_PEERPID: libc::c_int = 0x002;
    /// Retrieves the peer's audit token.
    const LOCAL_PEERTOKEN: libc::c_int = 0x006;

    /// The process id on the other end, absent when the socket does not say.
    pub fn peer_pid(fd: &BorrowedFd<'_>) -> Option<i32> {
        let mut pid: libc::pid_t = 0;
        let mut length = size_of::<libc::pid_t>() as libc::socklen_t;
        // Safety: the buffer is exactly the size the option writes, and the
        // length is passed by pointer as the interface asks. `getsockopt`
        // writes nothing on failure.
        let answered = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                SOL_LOCAL,
                LOCAL_PEERPID,
                (&raw mut pid).cast::<libc::c_void>(),
                &raw mut length,
            )
        };
        (answered == 0 && length as usize == size_of::<libc::pid_t>()).then_some(pid)
    }

    /// The audit token of the process on the other end, which is what a
    /// signature check should ask about: a process id can be reused between
    /// being read and being looked up, and a token cannot.
    pub fn peer_audit_token(fd: &BorrowedFd<'_>) -> Option<[u32; 8]> {
        let mut token = [0u32; 8];
        let mut length = size_of::<[u32; 8]>() as libc::socklen_t;
        // Safety: as above. The option writes an `audit_token_t`, which is
        // eight 32-bit words.
        let answered = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                SOL_LOCAL,
                LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast::<libc::c_void>(),
                &raw mut length,
            )
        };
        (answered == 0 && length as usize == size_of::<[u32; 8]>()).then_some(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::peer::this_user;
    use crate::protocol::{Hello, Role};

    fn temporary_socket(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("agentsweep-ipc-{name}-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn the_socket_is_the_one_the_specification_names() {
        let path = default_socket_path();
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some(SOCKET_NAME)
        );
        assert_eq!(path.parent(), Some(std::env::temp_dir().as_path()));
        assert_eq!(SOCKET_NAME, format!("{}.sock", agentsweep_core::BUNDLE_ID));
    }

    /// A path too long for `sun_path` is refused before a bind rather than
    /// silently truncated by the operating system.
    #[test]
    fn a_socket_path_longer_than_the_operating_system_allows_is_refused() {
        let long = PathBuf::from(format!("/tmp/{}.sock", "x".repeat(SUN_PATH)));
        assert!(check_socket_path(&long).is_err());
        assert!(check_socket_path(&default_socket_path()).is_ok());
    }

    /// The daemon is the only thing that may be talked to, so the socket is
    /// the user's alone.
    #[cfg(unix)]
    #[test]
    fn the_socket_is_bound_for_the_user_alone() {
        use std::os::unix::fs::PermissionsExt;

        let path = temporary_socket("mode");
        let listener = SocketListener::bind(&path).expect("a bound socket");
        let mode = std::fs::metadata(&path)
            .expect("a socket file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{mode:o}");
        drop(listener);
        assert!(!path.exists(), "the socket goes away with the listener");
    }

    /// A daemon that was killed leaves its socket file behind, and the next
    /// one binds over it rather than refusing to start (spec section 6.3).
    #[test]
    fn a_stale_socket_is_unlinked_at_start() {
        let path = temporary_socket("stale");
        std::fs::write(&path, b"a stale socket").expect("a stale file");
        let listener = SocketListener::bind(&path).expect("a bound socket");
        assert_eq!(listener.path(), path);
        drop(listener);
    }

    /// The two ends talk in whole messages, and the server end learns which
    /// user is on the other side without being told.
    #[test]
    fn the_two_ends_exchange_messages_and_the_server_sees_the_peer() {
        let path = temporary_socket("exchange");
        let listener = SocketListener::bind(&path).expect("a bound socket");

        let client = std::thread::spawn({
            let path = path.clone();
            move || {
                let mut connection = connect(&path).expect("a connected client");
                connection
                    .send(&Message::Hello(Hello::of(Role::Cli)))
                    .expect("a sent handshake");
                connection.receive().expect("an answer")
            }
        });

        let mut served = listener.accept().expect("an accepted connection");
        assert_eq!(served.peer().uid, this_user());
        assert!(served.peer().pid.is_some(), "the socket names the process");
        match served.receive().expect("a handshake") {
            Some(Message::Hello(hello)) => assert_eq!(hello.role, Role::Cli),
            other => panic!("expected a handshake, got {other:?}"),
        }
        served
            .send(&crate::protocol::welcome())
            .expect("a sent welcome");

        match client.join().expect("the client thread") {
            Some(Message::Welcome { version, .. }) => {
                assert_eq!(version, agentsweep_core::VERSION);
            }
            other => panic!("expected a welcome, got {other:?}"),
        }
    }

    /// The vocabulary is closed on the wire as well as in the code: an object
    /// that is not a message of this protocol ends the connection.
    #[test]
    fn something_that_is_not_this_protocol_is_an_error_rather_than_ignored() {
        let path = temporary_socket("gibberish");
        let listener = SocketListener::bind(&path).expect("a bound socket");

        let client = std::thread::spawn({
            let path = path.clone();
            move || {
                let mut connection = connect(&path).expect("a connected client");
                write_frame(
                    &mut connection.stream,
                    &serde_json::json!({"type": "read-the-disk"}),
                )
                .expect("a sent object");
            }
        });

        let mut served = listener.accept().expect("an accepted connection");
        let error = served.receive().expect_err("not this protocol");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        client.join().expect("the client thread");
    }
}
