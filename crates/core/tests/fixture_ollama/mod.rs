//! A fixture Ollama for the tests: a listener on a loopback port of its own
//! that answers each path from a script and keeps every request and every
//! connection it saw. It runs no model.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

/// How the fixture answers one path.
#[derive(Clone, Debug)]
pub enum Behaviour {
    /// A JSON body with a `Content-Length`.
    Json(u16, Value),
    /// A body in chunks, as Go's server sends a long answer.
    Chunked(u16, String),
    /// These bytes and then the connection closes.
    Raw(Vec<u8>),
    /// Reads the request and never answers.
    Hang,
}

/// One request the fixture received.
#[derive(Clone, Debug)]
pub struct Received {
    /// The method.
    pub method: String,
    /// The path.
    pub path: String,
    /// The headers, lower-case names.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

pub struct FixtureOllama {
    address: SocketAddr,
    received: Arc<Mutex<Vec<Received>>>,
    connections: Arc<AtomicUsize>,
    stopping: Arc<AtomicBool>,
}

impl FixtureOllama {
    /// A fixture answering each listed path its way; any other path is a 404.
    pub fn start(script: Vec<(&'static str, Behaviour)>) -> FixtureOllama {
        let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        let address = listener.local_addr().expect("an address");
        listener.set_nonblocking(true).expect("non-blocking accept");
        let received = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let (seen, counted, stop) = (
            Arc::clone(&received),
            Arc::clone(&connections),
            Arc::clone(&stopping),
        );
        thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let script = script.clone();
                        let seen = Arc::clone(&seen);
                        let stop = Arc::clone(&stop);
                        thread::spawn(move || answer(stream, &script, &seen, &stop));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        FixtureOllama {
            address,
            received,
            connections,
            stopping,
        }
    }

    /// Where it listens.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Every request it received on one path, in order.
    pub fn received(&self, path: &str) -> Vec<Received> {
        self.received
            .lock()
            .expect("the record")
            .iter()
            .filter(|request| request.path == path)
            .cloned()
            .collect()
    }

    /// Every request it received.
    pub fn all_received(&self) -> Vec<Received> {
        self.received.lock().expect("the record").clone()
    }

    /// How many connections it accepted.
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for FixtureOllama {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        // Wait for the accept loop to notice, so the port is closed when the
        // fixture is gone.
        thread::sleep(Duration::from_millis(30));
    }
}

fn answer(
    mut stream: TcpStream,
    script: &[(&'static str, Behaviour)],
    seen: &Mutex<Vec<Received>>,
    stop: &AtomicBool,
) {
    stream.set_nonblocking(false).expect("blocking reads");
    let Some(request) = read_request(&mut stream) else {
        return;
    };
    let behaviour = script
        .iter()
        .find(|(path, _)| *path == request.path)
        .map(|(_, behaviour)| behaviour.clone());
    seen.lock().expect("the record").push(request);
    let bytes = match behaviour {
        None => response(404, "application/json", b"{\"error\":\"not found\"}"),
        Some(Behaviour::Json(status, value)) => {
            response(status, "application/json", value.to_string().as_bytes())
        }
        Some(Behaviour::Chunked(status, body)) => {
            let mut bytes = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
            )
            .into_bytes();
            for piece in body.as_bytes().chunks(7) {
                bytes.extend_from_slice(format!("{:x}\r\n", piece.len()).as_bytes());
                bytes.extend_from_slice(piece);
                bytes.extend_from_slice(b"\r\n");
            }
            bytes.extend_from_slice(b"0\r\n\r\n");
            bytes
        }
        Some(Behaviour::Raw(bytes)) => bytes,
        Some(Behaviour::Hang) => {
            while !stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(20));
            }
            return;
        }
    };
    let _ = stream.write_all(&bytes);
    let _ = stream.flush();
}

fn response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn read_request(stream: &mut TcpStream) -> Option<Received> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut received = Vec::new();
    let mut buffer = [0u8; 8192];
    let end = loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            return None;
        }
        received.extend_from_slice(&buffer[..read]);
    };
    let head = String::from_utf8_lossy(&received[..end]).to_string();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = received[end + 4..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut buffer).ok()?;
        if read == 0 {
            return None;
        }
        body.extend_from_slice(&buffer[..read]);
    }
    Some(Received {
        method,
        path,
        headers,
        body,
    })
}

/// A loopback port nothing listens on.
pub fn closed_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
    let address = listener.local_addr().expect("an address");
    drop(listener);
    address
}

/// An `/api/tags` answer listing these models by tag, parameter size and
/// digest.
pub fn tags(models: &[(&str, &str, &str)]) -> Value {
    json!({
        "models": models
            .iter()
            .map(|(name, size, digest)| json!({
                "name": name,
                "model": name,
                "modified_at": "2026-10-01T00:00:00Z",
                "size": 1_000_000,
                "digest": digest,
                "details": {
                    "format": "gguf",
                    "family": "fixture",
                    "parameter_size": size,
                    "quantization_level": "Q4_K_M",
                },
            }))
            .collect::<Vec<Value>>(),
    })
}
