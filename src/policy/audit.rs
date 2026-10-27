//! Hash-chained audit log for every authorization decision.
//!
//! The point of the log is to answer "what did this tool send, and was it
//! allowed?" after the fact, without trusting the operator's memory. Each line is
//! a JSON object whose `hash` is `sha256(previous_hash || payload)`, so editing,
//! reordering or deleting a line in the middle is detectable by
//! [`verify`].
//!
//! Honest limitations, stated up front:
//!
//! - **Tail truncation is not detectable from the file alone.** Removing the last
//!   N lines yields a shorter but internally consistent chain. Detecting that
//!   needs an external anchor (a signed bundle header, a CI log, a timestamp).
//! - The chain proves *integrity*, not *authorship*: anyone who can write the file
//!   can rewrite the whole chain. Signing is a later layer.
//! - Writes are buffered and flushed every [`FLUSH_EVERY`] entries and on drop, so
//!   a hard kill can lose the tail that truncation would hide anyway.

use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The hash a chain starts from: 64 zeros, not a valid digest of anything.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const FLUSH_EVERY: u32 = 32;

/// One decision to be written to the log.
#[derive(Debug, Clone, Copy)]
pub struct AuditRecord<'a> {
    /// `allow`, `deny` or `halt`.
    pub action: &'a str,
    /// `proxied`, `generated` or `system`.
    pub traffic: &'a str,
    pub method: &'a str,
    pub uri: &'a str,
    pub reason: Option<&'a str>,
    pub envelope_id: Option<&'a str>,
}

impl<'a> AuditRecord<'a> {
    pub fn allow(traffic: &'a str, method: &'a str, uri: &'a str) -> Self {
        Self {
            action: "allow",
            traffic,
            method,
            uri,
            reason: None,
            envelope_id: None,
        }
    }

    pub fn deny(traffic: &'a str, method: &'a str, uri: &'a str, reason: &'a str) -> Self {
        Self {
            action: "deny",
            traffic,
            method,
            uri,
            reason: Some(reason),
            envelope_id: None,
        }
    }

    pub fn with_envelope(mut self, envelope_id: Option<&'a str>) -> Self {
        self.envelope_id = envelope_id;
        self
    }
}

struct State {
    seq: u64,
    prev: String,
    writer: Option<BufWriter<File>>,
    pending: u32,
    entries: u64,
    failures: u64,
}

/// Append-only, hash-chained log. Cheap to clone behind an `Arc`; never panics on
/// I/O failure (failures are counted so the UI can surface them instead).
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<State>,
}

impl AuditLog {
    /// Open (or create) the log and resume its chain, so appending cannot fork it.
    /// An existing log whose chain does not verify is a hard error: refusing to
    /// append is the only way to avoid laundering tampered history.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
            }
        }

        let (seq, prev) = read_chain(&path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|error| format!("failed to open {}: {error}", path.display()))?;

        Ok(Self {
            path,
            state: Mutex::new(State {
                seq,
                prev,
                writer: Some(BufWriter::new(file)),
                pending: 0,
                entries: seq,
                failures: 0,
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one decision. Chain state only advances when the write succeeds, so a
    /// transient I/O error cannot desynchronise the in-memory chain from the file.
    pub fn record(&self, record: AuditRecord<'_>) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            // A poisoned lock means another thread panicked mid-write. The file is
            // the source of truth; keep appending rather than silently stopping.
            Err(poisoned) => poisoned.into_inner(),
        };

        let seq = state.seq + 1;
        let payload = json!({
            "seq": seq,
            "ts": Utc::now().to_rfc3339(),
            "action": record.action,
            "traffic": record.traffic,
            "method": record.method,
            "uri": record.uri,
            "reason": record.reason,
            "envelope": record.envelope_id,
        });
        let hash = hash_of(&state.prev, &payload.to_string());

        let mut line = payload;
        line["hash"] = Value::String(hash.clone());

        let written = match state.writer.as_mut() {
            Some(writer) => writeln!(writer, "{line}"),
            None => return,
        };
        if written.is_err() {
            state.failures += 1;
            return;
        }

        state.seq = seq;
        state.prev = hash;
        state.entries += 1;
        state.pending += 1;
        if state.pending >= FLUSH_EVERY {
            let flushed = match state.writer.as_mut() {
                Some(writer) => writer.flush().is_ok(),
                None => false,
            };
            if flushed {
                state.pending = 0;
            }
        }
    }

    pub fn flush(&self) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        let flushed = match state.writer.as_mut() {
            Some(writer) => writer.flush().is_ok(),
            None => false,
        };
        if flushed {
            state.pending = 0;
        }
    }

    pub fn entries(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => state.entries,
            Err(poisoned) => poisoned.into_inner().entries,
        }
    }

    pub fn failures(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => state.failures,
            Err(poisoned) => poisoned.into_inner().failures,
        }
    }
}

impl Drop for AuditLog {
    fn drop(&mut self) {
        if let Ok(state) = self.state.get_mut() {
            if let Some(writer) = state.writer.as_mut() {
                let _ = writer.flush();
            }
        }
    }
}

/// Recompute the chain and return the number of entries.
pub fn verify(path: impl AsRef<Path>) -> Result<u64, String> {
    read_chain(path.as_ref()).map(|(entries, _)| entries)
}

fn read_chain(path: &Path) -> Result<(u64, String), String> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, GENESIS.to_string()))
        }
        Err(error) => return Err(format!("failed to read {}: {error}", path.display())),
    };

    let mut prev = GENESIS.to_string();
    let mut seq = 0u64;

    for (index, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let number = index + 1;
        let value: Value =
            serde_json::from_str(line).map_err(|error| format!("line {number}: invalid JSON: {error}"))?;
        let object = value
            .as_object()
            .ok_or_else(|| format!("line {number}: entry is not a JSON object"))?;

        let recorded_seq = object
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("line {number}: missing seq"))?;
        if recorded_seq != seq + 1 {
            return Err(format!(
                "line {number}: expected seq {}, found {recorded_seq} (entries removed or reordered)",
                seq + 1
            ));
        }

        let recorded_hash = object
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("line {number}: missing hash"))?
            .to_string();

        let mut payload = value.clone();
        payload
            .as_object_mut()
            .expect("checked above")
            .remove("hash");
        if hash_of(&prev, &payload.to_string()) != recorded_hash {
            return Err(format!(
                "line {number}: hash mismatch (entry was modified after it was written)"
            ));
        }

        prev = recorded_hash;
        seq = recorded_seq;
    }

    Ok((seq, prev))
}

fn hash_of(previous: &str, payload: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous.as_bytes());
    hasher.update(b"\n");
    hasher.update(payload.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "proxima-audit-{}-{}-{name}.log",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ))
    }

    fn record_n(log: &AuditLog, count: usize) {
        for index in 0..count {
            log.record(
                AuditRecord::allow("proxied", "GET", &format!("https://example.test/{index}"))
                    .with_envelope(Some("engagement-1")),
            );
        }
    }

    #[test]
    fn entries_chain_and_verify() {
        let path = temp_log("chain");
        let log = AuditLog::open(&path).expect("open");
        record_n(&log, 5);
        assert_eq!(log.failures(), 0);
        log.flush();
        assert_eq!(verify(&path).expect("valid chain"), 5);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reopening_continues_the_same_chain() {
        let path = temp_log("resume");
        {
            let log = AuditLog::open(&path).expect("open");
            record_n(&log, 2);
        }
        {
            let log = AuditLog::open(&path).expect("reopen");
            record_n(&log, 3);
        }
        assert_eq!(verify(&path).expect("valid chain"), 5);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn modification_is_detected() {
        let path = temp_log("tamper");
        {
            let log = AuditLog::open(&path).expect("open");
            record_n(&log, 3);
        }
        let content = fs::read_to_string(&path).expect("read");
        let tampered = content.replacen("/0", "/9", 1);
        fs::write(&path, tampered).expect("write");
        let error = verify(&path).unwrap_err();
        assert!(error.contains("hash mismatch"), "{error}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn removing_a_middle_entry_is_detected() {
        let path = temp_log("delete");
        {
            let log = AuditLog::open(&path).expect("open");
            record_n(&log, 4);
        }
        let content = fs::read_to_string(&path).expect("read");
        let mut lines: Vec<&str> = content.lines().collect();
        lines.remove(1);
        fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write");
        let error = verify(&path).unwrap_err();
        assert!(error.contains("seq"), "{error}");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn reordering_entries_is_detected() {
        let path = temp_log("reorder");
        {
            let log = AuditLog::open(&path).expect("open");
            record_n(&log, 3);
        }
        let content = fs::read_to_string(&path).expect("read");
        let mut lines: Vec<&str> = content.lines().collect();
        lines.swap(1, 2);
        fs::write(&path, format!("{}\n", lines.join("\n"))).expect("write");
        assert!(verify(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    /// Cross-implementation check: this fixture was written by
    /// `tools/verify_audit_log.py`, so the canonical serialisation of an entry is
    /// pinned by something other than this file's own writer. If `verify` starts
    /// rejecting it, the on-disk format changed and every existing log became
    /// unreadable.
    #[test]
    fn verifies_a_log_written_by_another_implementation() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/audit-sample.jsonl");
        let entries = verify(&path).expect("fixture chain verifies");
        assert_eq!(entries, 3);
    }

    #[test]
    fn tail_truncation_is_a_known_blind_spot() {
        // Documented limitation: dropping the last entries leaves a consistent
        // chain. An external anchor (bundle header, CI log) is required to catch
        // this; the test asserts the limitation rather than pretending otherwise.
        let path = temp_log("truncate");
        {
            let log = AuditLog::open(&path).expect("open");
            record_n(&log, 4);
        }
        let content = fs::read_to_string(&path).expect("read");
        let kept: Vec<&str> = content.lines().take(2).collect();
        fs::write(&path, format!("{}\n", kept.join("\n"))).expect("write");
        assert_eq!(verify(&path).expect("truncated log still verifies"), 2);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn append_refuses_to_extend_a_broken_chain() {
        let path = temp_log("broken");
        {
            let log = AuditLog::open(&path).expect("open");
            record_n(&log, 2);
        }
        let content = fs::read_to_string(&path).expect("read");
        fs::write(&path, content.replacen("allow", "deny", 1)).expect("write");
        assert!(AuditLog::open(&path).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn opening_a_missing_file_starts_from_genesis() {
        let path = temp_log("fresh");
        let _ = fs::remove_file(&path);
        let log = AuditLog::open(&path).expect("open");
        log.record(AuditRecord::deny("proxied", "DELETE", "https://example.test/x", "denied"));
        log.flush();
        assert_eq!(verify(&path).expect("valid chain"), 1);
        let _ = fs::remove_file(&path);
    }
}
