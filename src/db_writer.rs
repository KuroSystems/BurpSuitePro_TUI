//! Background persistence for captured flows.
//!
//! The proxy can emit flows faster than a disk can fsync them. Writing on the UI
//! thread means a slow or contended disk freezes the interface, so flow writes are
//! handed to a dedicated thread holding its own SQLite connection (WAL, so multiple
//! connections to one project file are expected).
//!
//! Durability contract: [`DbWriter::flush`] waits until every queued write has been
//! applied. Callers MUST flush before copying the database (`save_as`) or quitting.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Sender},
    },
    thread::{self, JoinHandle},
};

use color_eyre::eyre::{Context, Result};
use tracing::{debug, error};

use crate::{db::Database, models::flow::HttpFlow};

enum DbJob {
    SaveFlow(Box<HttpFlow>),
    Flush(Sender<()>),
    Shutdown(Sender<()>),
}

/// Handle to the persistence thread. Dropping it flushes and joins.
pub struct DbWriter {
    tx: Sender<DbJob>,
    failures: Arc<AtomicU64>,
    written: Arc<AtomicU64>,
    path: PathBuf,
    handle: Option<JoinHandle<()>>,
}

impl DbWriter {
    /// Open a second connection to `path` and start the writer thread.
    ///
    /// The connection is opened on the caller's thread so a bad path or a locked
    /// project fails loudly at startup instead of silently dropping flows later.
    pub fn spawn(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let database = Database::open(&path)?;
        let (tx, rx) = mpsc::channel::<DbJob>();
        let failures = Arc::new(AtomicU64::new(0));
        let written = Arc::new(AtomicU64::new(0));

        let thread_failures = Arc::clone(&failures);
        let thread_written = Arc::clone(&written);
        let handle = thread::Builder::new()
            .name("proxima-db-writer".to_string())
            .spawn(move || {
                // The loop owns the only handle to `database`, so writes are serialized.
                for job in rx {
                    match job {
                        DbJob::SaveFlow(flow) => match database.save_flow(&*flow) {
                            Ok(_) => {
                                thread_written.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(error) => {
                                thread_failures.fetch_add(1, Ordering::Relaxed);
                                error!(flow_id = flow.id, %error, "failed to persist flow");
                            }
                        },
                        DbJob::Flush(ack) => {
                            let _ = ack.send(());
                        }
                        DbJob::Shutdown(ack) => {
                            let _ = ack.send(());
                            break;
                        }
                    }
                }
                debug!("database writer stopped");
            })
            .wrap_err("failed to start database writer thread")?;

        Ok(Self {
            tx,
            failures,
            written,
            path,
            handle: Some(handle),
        })
    }

    /// Queue a flow for persistence. Never blocks and never fails the caller.
    pub fn save_flow(&self, flow: &HttpFlow) {
        if self.tx.send(DbJob::SaveFlow(Box::new(flow.clone()))).is_err() {
            self.failures.fetch_add(1, Ordering::Relaxed);
            error!(flow_id = flow.id, "database writer is gone; flow not persisted");
        }
    }

    /// Wait until every queued write has been applied. Returns false on timeout/disconnect.
    pub fn flush(&self) -> bool {
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.tx.send(DbJob::Flush(ack_tx)).is_err() {
            return false;
        }
        ack_rx.recv().is_ok()
    }

    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for DbWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DbWriter")
            .field("path", &self.path)
            .field("written", &self.written())
            .field("failures", &self.failures())
            .finish()
    }
}

impl Drop for DbWriter {
    fn drop(&mut self) {
        let (ack_tx, ack_rx) = mpsc::channel();
        if self.tx.send(DbJob::Shutdown(ack_tx)).is_ok() {
            // Wait for the queued writes ahead of the shutdown marker to finish.
            let _ = ack_rx.recv();
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Local;
    use hyper::HeaderMap;

    fn temp_project(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "proxima-dbwriter-{}-{}-{name}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn sample_flow(id: u64) -> HttpFlow {
        HttpFlow {
            id,
            timestamp: Local::now(),
            method: "GET".to_string(),
            uri: format!("https://example.test/{id}"),
            status: Some(200),
            request_headers: HeaderMap::new(),
            request_body: bytes::Bytes::new(),
            response_headers: Some(HeaderMap::new()),
            response_body: Some(bytes::Bytes::from_static(b"ok")),
            duration_ms: Some(1),
        }
    }

    #[test]
    fn writes_are_persisted_and_readable_after_flush() {
        let path = temp_project("persist");
        let writer = DbWriter::spawn(&path).expect("writer starts");
        for id in 1..=25 {
            writer.save_flow(&sample_flow(id));
        }
        assert!(writer.flush());
        assert_eq!(writer.failures(), 0);
        assert_eq!(writer.written(), 25);

        let database = Database::open(&path).expect("reopen");
        let flows = database.load_flows(100, 0).expect("load");
        assert_eq!(flows.len(), 25);
        drop(writer);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn flush_is_a_barrier_for_queued_writes() {
        let path = temp_project("barrier");
        {
            let writer = DbWriter::spawn(&path).expect("writer starts");
            writer.save_flow(&sample_flow(7));
            assert!(writer.flush());
            // A reader on another connection sees the write immediately after flush.
            let database = Database::open(&path).expect("reopen");
            assert_eq!(database.load_flows(10, 0).unwrap().len(), 1);
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn drop_drains_pending_writes() {
        let path = temp_project("drop");
        {
            let writer = DbWriter::spawn(&path).expect("writer starts");
            for id in 1..=10 {
                writer.save_flow(&sample_flow(id));
            }
            // No explicit flush: Drop must behave like one.
        }
        let database = Database::open(&path).expect("reopen");
        assert_eq!(database.load_flows(100, 0).unwrap().len(), 10);
        let _ = std::fs::remove_file(&path);
    }
}
