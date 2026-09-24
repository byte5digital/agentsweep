//! The record envelope both chains share.
//!
//! The Event Log and the Baseline are the same primitive: an append-only file
//! of one JSON record per line, each carrying the hash of the record before it
//! and an HMAC-SHA256 over itself under the key in the login Keychain (ADR
//! 0003, spec sections 5.5 and 4.6.6). One envelope, one verification routine,
//! one honest "records tampered" indicator.
//!
//! A record is written in exactly one form, so that any edited byte is caught:
//! keys sorted, no spaces, no trailing newline inside the line. The hash that
//! the next record links to is the SHA-256 of those bytes, and reading a
//! record insists on the same form.

use std::fmt;

use serde_json::{Map, Value};

use crate::item::sha256_hex;
use crate::keychain::ChainKey;

/// Which chain a record belongs to. Both use this envelope; the payload is
/// what differs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainId {
    /// `events.jsonl`, the source of truth. Never compacted.
    Events,
    /// `baseline.jsonl`, the accepted hash per Item. Compacted, and every
    /// compaction is anchored by an event in the Event Log.
    Baseline,
}

impl ChainId {
    /// The spelling the record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            ChainId::Events => "events",
            ChainId::Baseline => "baseline",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<ChainId> {
        match text {
            "events" => Some(ChainId::Events),
            "baseline" => Some(ChainId::Baseline),
            _ => None,
        }
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a record is there for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    /// A record of the chain's own payload: an event on the Event Log, a
    /// Baseline record on the Baseline.
    Entry,
    /// The first record of a new chain after the key went missing. It points
    /// at the old chain's last record, so the old head is witnessed by the new
    /// chain even though no key can verify the records before it.
    ChainRestart,
}

impl RecordKind {
    /// The spelling the record carries.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Entry => "entry",
            RecordKind::ChainRestart => "chain-restart",
        }
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<RecordKind> {
        match text {
            "entry" => Some(RecordKind::Entry),
            "chain-restart" => Some(RecordKind::ChainRestart),
            _ => None,
        }
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the first record of the first chain links to: no record at all.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// When a record was written, in UTC to the millisecond.
///
/// It is carried as `YYYY-MM-DDTHH:MM:SS.mmmZ`, which reads as a date in the
/// file and compares as a number in code.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The moment this is called.
    pub fn now() -> Timestamp {
        let since_epoch = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
        match since_epoch {
            Ok(elapsed) => Timestamp(elapsed.as_millis() as i64),
            Err(before) => Timestamp(-(before.duration().as_millis() as i64)),
        }
    }

    /// A moment given in milliseconds since the Unix epoch.
    pub fn from_unix_ms(milliseconds: i64) -> Timestamp {
        Timestamp(milliseconds)
    }

    /// The moment in milliseconds since the Unix epoch.
    pub fn as_unix_ms(self) -> i64 {
        self.0
    }

    /// The civil date alone, which is what a Drift Finding reads back
    /// ("changed since your last Scan on <date>").
    pub fn day(self) -> String {
        self.to_string()[..10].to_string()
    }

    /// Reads back the spelling a record carries.
    pub fn parse(text: &str) -> Option<Timestamp> {
        let bytes = text.as_bytes();
        if bytes.len() != 24 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
            return None;
        }
        if bytes[13] != b':' || bytes[16] != b':' || bytes[19] != b'.' || bytes[23] != b'Z' {
            return None;
        }
        let number = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
        let year = number(0, 4)?;
        let month = number(5, 7)?;
        let day = number(8, 10)?;
        let hour = number(11, 13)?;
        let minute = number(14, 16)?;
        let second = number(17, 19)?;
        let milli = number(20, 23)?;
        if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
            return None;
        }
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        let days = days_from_civil(year, month as u32, day as u32);
        Some(Timestamp(
            ((days * 86_400) + hour * 3_600 + minute * 60 + second) * 1_000 + milli,
        ))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let milliseconds = self.0.rem_euclid(1_000);
        let seconds = self.0.div_euclid(1_000);
        let days = seconds.div_euclid(86_400);
        let within_day = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{milliseconds:03}Z",
            within_day / 3_600,
            (within_day % 3_600) / 60,
            within_day % 60,
        )
    }
}

/// Howard Hinnant's `civil_from_days`: the civil date of a day count since the
/// Unix epoch, proleptic Gregorian, no leap seconds.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// The inverse of [`civil_from_days`].
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 } as i64;
    let day_of_year = (153 * shifted_month + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Why a line could not be read back as a record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// The line is not a record at all: not JSON, a field missing, a field of
    /// the wrong type.
    Malformed(String),
    /// The line is a record but not in the one form AgentSweep writes, so a
    /// byte of it was changed.
    NotCanonical,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::Malformed(detail) => write!(f, "the record is malformed: {detail}"),
            EnvelopeError::NotCanonical => {
                f.write_str("the record is not in the form AgentSweep writes")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// One record of a chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// Which chain the record belongs to.
    pub chain: ChainId,
    /// Which key generation authenticates it. A record of an earlier epoch
    /// cannot be verified with the key in hand and is read as unverified.
    pub epoch: u64,
    /// The record's position in the file, counted from zero.
    pub sequence: u64,
    /// When it was written.
    pub recorded_at: Timestamp,
    /// The hash of the record before it, or [`GENESIS`] for the very first.
    pub previous: String,
    /// What the record is there for.
    pub record: RecordKind,
    /// The chain's own payload.
    pub payload: Value,
    /// HMAC-SHA256 over everything above, lower-case hex.
    pub mac: String,
}

impl Envelope {
    /// Builds a record and seals it with the chain key.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        chain: ChainId,
        epoch: u64,
        sequence: u64,
        recorded_at: Timestamp,
        previous: &str,
        record: RecordKind,
        payload: Value,
        key: &ChainKey,
    ) -> Envelope {
        let mut sealed = Envelope {
            chain,
            epoch,
            sequence,
            recorded_at,
            previous: previous.to_string(),
            record,
            payload,
            mac: String::new(),
        };
        sealed.mac = hmac_sha256_hex(key, &canonical(&sealed.body()));
        sealed
    }

    /// Everything the MAC covers: the record without its MAC.
    fn body(&self) -> Value {
        let mut body = Map::new();
        body.insert("chain".to_string(), Value::from(self.chain.as_str()));
        body.insert("epoch".to_string(), Value::from(self.epoch));
        body.insert("payload".to_string(), self.payload.clone());
        body.insert("previous".to_string(), Value::from(self.previous.as_str()));
        body.insert("record".to_string(), Value::from(self.record.as_str()));
        body.insert(
            "recorded_at".to_string(),
            Value::from(self.recorded_at.to_string()),
        );
        body.insert("sequence".to_string(), Value::from(self.sequence));
        Value::Object(body)
    }

    /// The one form the record is written in: the line, without its newline.
    pub fn line(&self) -> Vec<u8> {
        let mut whole = match self.body() {
            Value::Object(map) => map,
            _ => Map::new(),
        };
        whole.insert("mac".to_string(), Value::from(self.mac.as_str()));
        canonical(&Value::Object(whole))
    }

    /// The hash the next record links to: the SHA-256 of [`Envelope::line`].
    pub fn hash(&self) -> String {
        sha256_hex(&self.line())
    }

    /// True when the MAC is the one this key produces over the record. The
    /// comparison is constant time.
    pub fn mac_matches(&self, key: &ChainKey) -> bool {
        let Some(expected) = hex_to_bytes(&self.mac) else {
            return false;
        };
        hmac_sha256_verify(key, &canonical(&self.body()), &expected)
    }

    /// Reads a line back, insisting on the one form AgentSweep writes.
    pub fn parse(line: &[u8]) -> Result<Envelope, EnvelopeError> {
        let value: Value = serde_json::from_slice(line)
            .map_err(|error| EnvelopeError::Malformed(error.to_string()))?;
        let Value::Object(map) = &value else {
            return Err(EnvelopeError::Malformed("not a JSON object".to_string()));
        };
        let missing = |field: &str| EnvelopeError::Malformed(format!("no {field}"));
        let text = |field: &str| -> Result<String, EnvelopeError> {
            map.get(field)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| missing(field))
        };
        let number = |field: &str| -> Result<u64, EnvelopeError> {
            map.get(field)
                .and_then(Value::as_u64)
                .ok_or_else(|| EnvelopeError::Malformed(format!("{field} is not a whole number")))
        };

        let chain = ChainId::parse(&text("chain")?)
            .ok_or_else(|| EnvelopeError::Malformed("unknown chain".to_string()))?;
        let record = RecordKind::parse(&text("record")?)
            .ok_or_else(|| EnvelopeError::Malformed("unknown record kind".to_string()))?;
        let recorded_at = Timestamp::parse(&text("recorded_at")?)
            .ok_or_else(|| EnvelopeError::Malformed("unreadable timestamp".to_string()))?;
        let previous = text("previous")?;
        let mac = text("mac")?;
        if !is_hash(&previous) || !is_hash(&mac) {
            return Err(EnvelopeError::Malformed(
                "a hash is not 64 hex characters".to_string(),
            ));
        }
        let parsed = Envelope {
            chain,
            epoch: number("epoch")?,
            sequence: number("sequence")?,
            recorded_at,
            previous,
            record,
            payload: map
                .get("payload")
                .cloned()
                .ok_or_else(|| missing("payload"))?,
            mac,
        };
        if parsed.line() != line {
            return Err(EnvelopeError::NotCanonical);
        }
        Ok(parsed)
    }
}

/// The one serialisation of a record: object keys in byte order, no spaces,
/// no newlines.
///
/// It is written out here rather than left to `serde_json` because the map
/// order of that crate follows whichever features the build happened to
/// enable. A hash chain cannot rest on that: the same record has to yield the
/// same bytes in every build, or an honest record would read as a tampered
/// one.
pub(crate) fn canonical(value: &Value) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_canonical(value, &mut bytes);
    bytes
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Value::String(text) => write_canonical_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_string(key, out);
                out.push(b':');
                write_canonical(&map[key.as_str()], out);
            }
            out.push(b'}');
        }
    }
}

/// A JSON string as `serde_json` writes one, which is the escaping every
/// reader of the file expects.
fn write_canonical_string(text: &str, out: &mut Vec<u8>) {
    match serde_json::to_vec(&Value::String(text.to_string())) {
        Ok(escaped) => out.extend_from_slice(&escaped),
        Err(_) => out.extend_from_slice(b"\"\""),
    }
}

fn is_hash(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

pub(crate) fn hex_to_bytes(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len() / 2)
        .map(|index| u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok())
        .collect()
}

/// HMAC-SHA256 over the bytes, lower-case hex.
pub(crate) fn hmac_sha256_hex(key: &ChainKey, bytes: &[u8]) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.bytes())
        .expect("HMAC takes a key of any length");
    mac.update(bytes);
    let tag = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(tag.len() * 2);
    for byte in tag {
        use fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// True when the tag is the one this key produces, compared in constant time.
pub(crate) fn hmac_sha256_verify(key: &ChainKey, bytes: &[u8], tag: &[u8]) -> bool {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.bytes())
        .expect("HMAC takes a key of any length");
    mac.update(bytes);
    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::ChainKey;

    fn key() -> ChainKey {
        ChainKey::from_bytes([9u8; 32])
    }

    fn sealed(payload: Value) -> Envelope {
        Envelope::seal(
            ChainId::Events,
            0,
            0,
            Timestamp::from_unix_ms(1_758_499_200_000),
            GENESIS,
            RecordKind::Entry,
            payload,
            &key(),
        )
    }

    #[test]
    fn a_record_is_written_with_sorted_keys_and_no_spaces() {
        let record = sealed(serde_json::json!({"b": 2, "a": 1}));
        let line = String::from_utf8(record.line()).expect("a text line");
        assert!(
            line.starts_with(r#"{"chain":"events","epoch":0,"mac":""#),
            "{line}"
        );
        assert!(line.contains(r#""payload":{"a":1,"b":2}"#), "{line}");
        assert!(!line.contains(", "), "{line}");
        assert!(!line.contains('\n'), "{line}");
    }

    #[test]
    fn the_written_form_does_not_depend_on_the_order_a_payload_was_built_in() {
        let one = sealed(serde_json::json!({"b": 2, "a": 1, "c": {"z": 1, "y": 2}}));
        let other = sealed(serde_json::json!({"c": {"y": 2, "z": 1}, "a": 1, "b": 2}));
        assert_eq!(one.line(), other.line());
        assert_eq!(one.mac, other.mac);
    }

    #[test]
    fn the_written_form_escapes_as_json_does() {
        let record = sealed(serde_json::json!({"path": "a\"b\\c\nd\te", "ü": "\u{1}"}));
        let line = String::from_utf8(record.line()).expect("a text line");
        assert!(line.contains(r#""a\"b\\c\nd\te""#), "{line}");
        assert!(line.contains(r#""\u0001""#), "{line}");
        assert_eq!(Envelope::parse(&record.line()), Ok(record));
    }

    #[test]
    fn a_record_round_trips_through_its_line() {
        let record = sealed(serde_json::json!({"action": "trust"}));
        let read = Envelope::parse(&record.line()).expect("a readable record");
        assert_eq!(read, record);
        assert!(read.mac_matches(&key()));
    }

    #[test]
    fn a_record_sealed_under_another_key_does_not_verify() {
        let record = sealed(serde_json::json!({"action": "trust"}));
        assert!(!record.mac_matches(&ChainKey::from_bytes([1u8; 32])));
    }

    #[test]
    fn changing_any_field_breaks_the_mac() {
        let record = sealed(serde_json::json!({"action": "trust"}));
        let mut edited = record.clone();
        edited.payload = serde_json::json!({"action": "untrust"});
        assert!(!edited.mac_matches(&key()));

        let mut moved = record.clone();
        moved.sequence = 1;
        assert!(!moved.mac_matches(&key()));

        let mut relinked = record;
        relinked.previous = "a".repeat(64);
        assert!(!relinked.mac_matches(&key()));
    }

    #[test]
    fn a_line_that_is_not_in_the_written_form_is_refused() {
        let record = sealed(serde_json::json!({"action": "trust"}));
        let line = String::from_utf8(record.line()).expect("a text line");
        let spaced = line.replace(r#"{"chain""#, r#"{ "chain""#);
        assert_eq!(
            Envelope::parse(spaced.as_bytes()),
            Err(EnvelopeError::NotCanonical)
        );
    }

    #[test]
    fn a_line_that_is_not_a_record_is_malformed() {
        assert!(matches!(
            Envelope::parse(b"{\"chain\":\"events\"}"),
            Err(EnvelopeError::Malformed(_))
        ));
        assert!(matches!(
            Envelope::parse(b"{\"chain\":\"even"),
            Err(EnvelopeError::Malformed(_))
        ));
    }

    #[test]
    fn the_hash_is_the_sha256_of_the_line() {
        let record = sealed(serde_json::json!({"action": "trust"}));
        assert_eq!(record.hash(), sha256_hex(&record.line()));
        assert_eq!(record.hash().len(), 64);
    }

    #[test]
    fn a_timestamp_prints_and_reads_back_as_utc() {
        for milliseconds in [0i64, 1_758_499_200_000, 1_709_164_800_000, 951_782_400_123] {
            let stamp = Timestamp::from_unix_ms(milliseconds);
            assert_eq!(Timestamp::parse(&stamp.to_string()), Some(stamp));
        }
        assert_eq!(
            Timestamp::from_unix_ms(0).to_string(),
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            Timestamp::from_unix_ms(1_709_164_800_000).to_string(),
            "2024-02-29T00:00:00.000Z"
        );
        assert_eq!(
            Timestamp::from_unix_ms(1_758_499_200_000).to_string(),
            "2025-09-22T00:00:00.000Z"
        );
    }

    #[test]
    fn a_timestamp_that_is_not_the_written_form_is_refused() {
        for text in [
            "2025-09-22T00:00:00Z",
            "2025-09-22 00:00:00.000Z",
            "2025-13-22T00:00:00.000Z",
            "",
        ] {
            assert_eq!(Timestamp::parse(text), None, "{text}");
        }
    }

    #[test]
    fn both_chains_share_the_one_envelope() {
        for chain in [ChainId::Events, ChainId::Baseline] {
            assert_eq!(ChainId::parse(chain.as_str()), Some(chain));
        }
        for record in [RecordKind::Entry, RecordKind::ChainRestart] {
            assert_eq!(RecordKind::parse(record.as_str()), Some(record));
        }
    }

    #[test]
    fn the_genesis_link_is_sixty_four_zeroes() {
        assert_eq!(GENESIS.len(), 64);
        assert!(GENESIS.bytes().all(|byte| byte == b'0'));
        assert!(is_hash(GENESIS));
    }
}
