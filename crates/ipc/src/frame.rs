//! The wire: length-prefixed JSON (spec section 6.3).
//!
//! One message is a four-byte big-endian length followed by that many bytes of
//! a JSON object. Nothing is line-delimited, so a value that happens to hold a
//! newline needs no escaping beyond JSON's own, and a reader always knows how
//! much is left to read.
//!
//! A frame is capped. A peer that announces more than [`MAX_FRAME`] is not
//! answered: the daemon holds the machine's file access and will not be talked
//! into allocating whatever a caller names.

use std::io::{self, Read, Write};

use serde_json::Value;

/// The largest message either side will send or accept, in bytes.
///
/// A status answer carries every open Finding with its plain sentence, so it
/// is not small; it is nowhere near this, and a frame that is says the peer is
/// not AgentSweep.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;

/// Writes one message and flushes it.
pub fn write_frame(out: &mut impl Write, message: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(message)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a message of {} bytes is too large to send", body.len()),
        ));
    }
    let length = u32::try_from(body.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the message length does not fit",
        )
    })?;
    out.write_all(&length.to_be_bytes())?;
    out.write_all(&body)?;
    out.flush()
}

/// Reads one message, or `None` when the peer closed the connection cleanly.
///
/// A connection that ends in the middle of a frame is an error rather than an
/// end: half a message is not a message.
pub fn read_frame(input: &mut impl Read) -> io::Result<Option<Value>> {
    let mut header = [0u8; 4];
    match read_exactly(input, &mut header)? {
        Filled::Closed => return Ok(None),
        Filled::Partial => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the connection ended inside a message header",
            ));
        }
        Filled::Whole => {}
    }
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("a message of {length} bytes is too large to accept"),
        ));
    }
    let mut body = vec![0u8; length];
    if read_exactly(input, &mut body)? != Filled::Whole {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "the connection ended inside a message",
        ));
    }
    let message: Value = serde_json::from_slice(&body)?;
    if !message.is_object() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a message is a JSON object",
        ));
    }
    Ok(Some(message))
}

/// How much of a buffer a read filled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Filled {
    /// Nothing at all: the peer closed the connection between messages.
    Closed,
    /// Some of it: the peer closed the connection inside a message.
    Partial,
    /// All of it.
    Whole,
}

fn read_exactly(input: &mut impl Read, buffer: &mut [u8]) -> io::Result<Filled> {
    if buffer.is_empty() {
        return Ok(Filled::Whole);
    }
    let mut filled = 0usize;
    while filled < buffer.len() {
        match input.read(&mut buffer[filled..]) {
            Ok(0) if filled == 0 => return Ok(Filled::Closed),
            Ok(0) => return Ok(Filled::Partial),
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(Filled::Whole)
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn a_message_comes_back_the_way_it_went_in() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &json!({"type": "hello", "version": "0.1.0"}))
            .expect("a written message");
        write_frame(&mut wire, &json!({"type": "request", "id": "1"})).expect("a second message");

        let mut read = wire.as_slice();
        assert_eq!(
            read_frame(&mut read).expect("a readable message"),
            Some(json!({"type": "hello", "version": "0.1.0"}))
        );
        assert_eq!(
            read_frame(&mut read).expect("a readable message"),
            Some(json!({"type": "request", "id": "1"}))
        );
        assert_eq!(read_frame(&mut read).expect("a clean end"), None);
    }

    /// The length is what a reader trusts, so the first four bytes are it, in
    /// the order every other length-prefixed protocol writes them.
    #[test]
    fn the_length_is_four_bytes_big_endian_before_the_object() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &json!({})).expect("a written message");
        assert_eq!(&wire[..4], &[0, 0, 0, 2]);
        assert_eq!(&wire[4..], b"{}");
    }

    #[test]
    fn a_frame_larger_than_the_cap_is_refused_rather_than_allocated() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&(MAX_FRAME as u32 + 1).to_be_bytes());
        let error = read_frame(&mut wire.as_slice()).expect_err("the cap holds");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_connection_that_ends_inside_a_message_is_an_error_and_not_an_end() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &json!({"type": "hello"})).expect("a written message");
        wire.truncate(wire.len() - 3);
        let error = read_frame(&mut wire.as_slice()).expect_err("half a message is not a message");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_message_that_is_not_an_object_is_refused() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &json!([1, 2, 3])).expect("a written array");
        let error = read_frame(&mut wire.as_slice()).expect_err("an array is not a message");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
