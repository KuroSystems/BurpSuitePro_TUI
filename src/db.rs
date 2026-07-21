use std::{fs, path::{Path, PathBuf}};

use bytes::Bytes;
use chrono::{DateTime, Local};
use color_eyre::eyre::{Context, Result};
use hyper::HeaderMap;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::{
    models::{
        flow::HttpFlow,
        intruder::IntruderResult,
        repeater::RepeaterTab,
        scope::{ScopeRule, ScopeRuleType},
    },
    scanner::{Confidence, Finding, Severity},
};

pub struct Database {
    path: PathBuf,
    connection: Connection,
}

#[derive(Debug, Serialize, Deserialize)]
struct MessageBlob {
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create project directory {}", parent.display()))?;
        }
        let connection = Connection::open(&path)
            .with_context(|| format!("failed to open project database {}", path.display()))?;
        let database = Self { path, connection };
        database.init_schema()?;
        let _ = write_last_project_marker(&database.path);
        Ok(database)
    }

    pub fn open_default() -> Result<Self> {
        let path = std::env::var_os("PROXIMA_PROJECT")
            .map(PathBuf::from)
            .or_else(read_last_project_marker)
            .filter(|path| path.exists())
            .unwrap_or_else(|| std::env::temp_dir().join("proxima-tui-untitled.db"));
        Self::open(path)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn init_schema(&self) -> Result<()> {
        self.connection.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL,
                method TEXT NOT NULL,
                uri TEXT NOT NULL,
                status INTEGER,
                request_blob BLOB NOT NULL,
                response_blob BLOB
            );
            CREATE TABLE IF NOT EXISTS repeater_tabs (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                request_text TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scope_rules (
                id INTEGER PRIMARY KEY,
                pattern TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                enabled INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS intruder_results (
                id INTEGER PRIMARY KEY,
                payload TEXT NOT NULL,
                status INTEGER,
                length INTEGER NOT NULL,
                time_ms INTEGER NOT NULL,
                error TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id INTEGER NOT NULL,
                issue_id TEXT NOT NULL,
                issue_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                url TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                UNIQUE(flow_id, issue_id)
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn save_flow(&self, flow: &HttpFlow) -> Result<i64> {
        let request_blob = encode_blob(&flow.request_headers, &flow.request_body)?;
        let response_blob = match (&flow.response_headers, &flow.response_body) {
            (Some(headers), Some(body)) => Some(encode_blob(headers, body)?),
            _ => None,
        };

        self.connection.execute(
            r#"
            INSERT OR REPLACE INTO flows
                (id, timestamp, method, uri, status, request_blob, response_blob)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                flow.id as i64,
                flow.timestamp.to_rfc3339(),
                &flow.method,
                &flow.uri,
                flow.status.map(|status| status as i64),
                request_blob,
                response_blob,
            ],
        )?;
        Ok(flow.id as i64)
    }

    pub fn delete_flow(&self, flow_id: u64) -> Result<()> {
        self.connection.execute("DELETE FROM flows WHERE id = ?1", params![flow_id as i64])?;
        self.connection.execute("DELETE FROM findings WHERE flow_id = ?1", params![flow_id as i64])?;
        Ok(())
    }

    pub fn load_flows(&self, limit: usize, offset: usize) -> Result<Vec<HttpFlow>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT id, timestamp, method, uri, status, request_blob, response_blob
            FROM flows
            ORDER BY id ASC
            LIMIT ?1 OFFSET ?2
            "#,
        )?;
        let rows = statement.query_map(params![limit as i64, offset as i64], |row| {
            let id: i64 = row.get(0)?;
            let timestamp: String = row.get(1)?;
            let method: String = row.get(2)?;
            let uri: String = row.get(3)?;
            let status: Option<i64> = row.get(4)?;
            let request_blob: Vec<u8> = row.get(5)?;
            let response_blob: Option<Vec<u8>> = row.get(6)?;

            let request = decode_blob(&request_blob).map_err(to_sql_error)?;
            let response = response_blob
                .as_deref()
                .map(decode_blob)
                .transpose()
                .map_err(to_sql_error)?;
            let timestamp = DateTime::parse_from_rfc3339(&timestamp)
                .map_err(to_sql_error)?
                .with_timezone(&Local);

            Ok(HttpFlow {
                id: id as u64,
                timestamp,
                method,
                uri,
                status: status.map(|status| status as u16),
                request_headers: request.headers,
                request_body: request.body,
                response_headers: response.as_ref().map(|message| message.headers.clone()),
                response_body: response.map(|message| message.body),
                duration_ms: None,
            })
        })?;

        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn save_repeater_tabs(&mut self, tabs: &[RepeaterTab]) -> Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM repeater_tabs", [])?;
        for tab in tabs {
            transaction.execute(
                r#"
                INSERT INTO repeater_tabs (id, name, request_text, created_at)
                VALUES (?1, ?2, ?3, ?4)
                "#,
                params![tab.id as i64, &tab.name, &tab.request_text, Local::now().to_rfc3339()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_repeater_tabs(&self) -> Result<Vec<RepeaterTab>> {
        let mut statement = self.connection.prepare(
            "SELECT id, name, request_text FROM repeater_tabs ORDER BY id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let id: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            let request_text: String = row.get(2)?;
            Ok(RepeaterTab::new(id as usize, name, request_text))
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn save_scope_rules(&mut self, rules: &[ScopeRule]) -> Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM scope_rules", [])?;
        for rule in rules {
            transaction.execute(
                r#"
                INSERT INTO scope_rules (id, pattern, rule_type, enabled)
                VALUES (?1, ?2, ?3, ?4)
                "#,
                params![
                    rule.id,
                    &rule.pattern,
                    rule.rule_type.as_str(),
                    if rule.enabled { 1_i64 } else { 0_i64 },
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_scope_rules(&self) -> Result<Vec<ScopeRule>> {
        let mut statement = self.connection.prepare(
            "SELECT id, pattern, rule_type, enabled FROM scope_rules ORDER BY id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let rule_type: String = row.get(2)?;
            let enabled: i64 = row.get(3)?;
            Ok(ScopeRule {
                id: row.get(0)?,
                pattern: row.get(1)?,
                rule_type: ScopeRuleType::from_str(&rule_type),
                enabled: enabled != 0,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn save_intruder_results(&mut self, results: &[IntruderResult]) -> Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM intruder_results", [])?;
        for result in results {
            transaction.execute(
                r#"
                INSERT INTO intruder_results (id, payload, status, length, time_ms, error)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    result.id as i64,
                    &result.payload_label,
                    result.status.map(|status| status as i64),
                    result.length as i64,
                    result.time_ms as i64,
                    &result.error,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn load_intruder_results(&self) -> Result<Vec<IntruderResult>> {
        let mut statement = self.connection.prepare(
            "SELECT id, payload, status, length, time_ms, error FROM intruder_results ORDER BY id ASC",
        )?;
        let rows = statement.query_map([], |row| {
            let status: Option<i64> = row.get(2)?;
            Ok(IntruderResult {
                id: row.get::<_, i64>(0)? as u64,
                payload_label: row.get(1)?,
                status: status.map(|status| status as u16),
                length: row.get::<_, i64>(3)? as usize,
                time_ms: row.get::<_, i64>(4)? as u64,
                error: row.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn save_finding(&self, finding: &Finding) -> Result<i64> {
        self.connection.execute(
            r#"
            INSERT OR IGNORE INTO findings
                (flow_id, issue_id, issue_name, severity, confidence, url, evidence_json, timestamp)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                finding.flow_id as i64,
                &finding.issue_id,
                &finding.issue_name,
                finding.severity.as_str(),
                finding.confidence.as_str(),
                &finding.url,
                &finding.evidence_json,
                finding.timestamp.to_rfc3339(),
            ],
        )?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn load_findings(&self) -> Result<Vec<Finding>> {
        let mut statement = self.connection.prepare(
            r#"
            SELECT id, flow_id, issue_id, issue_name, severity, confidence, url, evidence_json, timestamp
            FROM findings
            ORDER BY severity DESC, id DESC
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            let timestamp: String = row.get(8)?;
            let timestamp = DateTime::parse_from_rfc3339(&timestamp)
                .map_err(to_sql_error)?
                .with_timezone(&Local);
            let severity: String = row.get(4)?;
            let confidence: String = row.get(5)?;
            Ok(Finding {
                id: row.get(0)?,
                flow_id: row.get::<_, i64>(1)? as u64,
                issue_id: row.get(2)?,
                issue_name: row.get(3)?,
                severity: Severity::from_str(&severity),
                confidence: Confidence::from_str(&confidence),
                url: row.get(6)?,
                evidence_json: row.get(7)?,
                timestamp,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(Into::into)
    }

    pub fn save_setting(&self, key: &str, value: &str) -> Result<()> {
        self.connection.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn load_setting(&self, key: &str) -> Result<Option<String>> {
        self.connection
            .query_row("SELECT value FROM settings WHERE key = ?1", params![key], |row| row.get(0))
            .optional()
            .map_err(Into::into)
    }

    pub fn save_as(&self, destination: impl AsRef<Path>) -> Result<PathBuf> {
        let destination = destination.as_ref().to_path_buf();
        if destination == self.path {
            self.connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            let _ = write_last_project_marker(&destination);
            return Ok(destination);
        }
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create project directory {}", parent.display()))?;
        }
        self.connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        fs::copy(&self.path, &destination).with_context(|| {
            format!(
                "failed to copy project {} to {}",
                self.path.display(),
                destination.display()
            )
        })?;
        let _ = write_last_project_marker(&destination);
        Ok(destination)
    }
}

fn last_project_marker_path() -> PathBuf {
    std::env::temp_dir().join("proxima-tui-last-project.txt")
}

fn read_last_project_marker() -> Option<PathBuf> {
    fs::read_to_string(last_project_marker_path())
        .ok()
        .map(|path| PathBuf::from(path.trim()))
}

fn write_last_project_marker(path: &Path) -> std::io::Result<()> {
    fs::write(last_project_marker_path(), path.display().to_string())
}

impl std::fmt::Debug for Database {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Database").field("path", &self.path).finish()
    }
}

struct DecodedMessage {
    headers: HeaderMap,
    body: Bytes,
}

fn encode_blob(headers: &HeaderMap, body: &Bytes) -> Result<Vec<u8>> {
    let blob = MessageBlob {
        headers: headers
            .iter()
            .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
            .collect(),
        body: body.to_vec(),
    };
    rmp_serde::to_vec_named(&blob).map_err(Into::into)
}

fn decode_blob(bytes: &[u8]) -> Result<DecodedMessage> {
    let blob: MessageBlob = rmp_serde::from_slice(bytes)?;
    let mut headers = HeaderMap::new();
    for (name, value) in blob.headers {
        let name = hyper::header::HeaderName::from_bytes(name.as_bytes())?;
        let value = hyper::header::HeaderValue::from_bytes(&value)?;
        headers.insert(name, value);
    }
    Ok(DecodedMessage {
        headers,
        body: Bytes::from(blob.body),
    })
}

fn to_sql_error<E>(error: E) -> rusqlite::Error
where
    E: std::fmt::Display,
{
    rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        error.to_string(),
    )))
}
