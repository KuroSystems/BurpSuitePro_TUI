use std::{path::PathBuf, sync::Arc, time::Instant};

use bytes::Bytes;
use hyper::HeaderMap;
use serde::{Deserialize, Serialize};
use tokio::{sync::{mpsc, Semaphore}, time::{self, Duration}};

use crate::policy::{Decision, Policy, Traffic};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    Sniper,
    BatteringRam,
    Pitchfork,
    ClusterBomb,
}

impl AttackType {
    pub const ALL: [Self; 4] = [Self::Sniper, Self::BatteringRam, Self::Pitchfork, Self::ClusterBomb];

    pub fn label(self) -> &'static str {
        match self {
            Self::Sniper => "Sniper",
            Self::BatteringRam => "Battering Ram",
            Self::Pitchfork => "Pitchfork",
            Self::ClusterBomb => "Cluster Bomb",
        }
    }

    pub fn next(self) -> Self {
        let index = Self::ALL.iter().position(|value| *value == self).unwrap_or(0);
        Self::ALL[(index + 1) % Self::ALL.len()]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Position {
    pub start: usize,
    pub end: usize,
    pub placeholder: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PayloadSource {
    SimpleList(Vec<String>),
    File(PathBuf),
    Numbers { start: i64, end: i64, step: i64 },
    Custom(Vec<String>),
}

impl PayloadSource {
    pub fn values(&self) -> Vec<String> {
        match self {
            Self::SimpleList(values) | Self::Custom(values) => values.clone(),
            Self::File(path) => std::fs::read_to_string(path)
                .map(|content| content.lines().map(ToOwned::to_owned).collect())
                .unwrap_or_default(),
            Self::Numbers { start, end, step } => {
                let step = if *step == 0 { 1 } else { *step };
                let mut values = Vec::new();
                let mut current = *start;
                if step > 0 {
                    while current <= *end {
                        values.push(current.to_string());
                        current += step;
                    }
                } else {
                    while current >= *end {
                        values.push(current.to_string());
                        current += step;
                    }
                }
                values
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadSet {
    pub name: String,
    pub source: PayloadSource,
}

impl PayloadSet {
    pub fn simple(name: impl Into<String>, payloads: Vec<String>) -> Self {
        Self { name: name.into(), source: PayloadSource::SimpleList(payloads) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackConfig {
    pub target_request: String,
    pub positions: Vec<Position>,
    pub payload_sets: Vec<PayloadSet>,
    pub attack_type: AttackType,
    pub concurrency: usize,
    pub rps: u32,
}

impl AttackConfig {
    pub fn total_requests(&self) -> usize {
        generate_payload_assignments(self).len()
    }
}

#[derive(Debug, Clone)]
pub struct IntruderResult {
    pub id: u64,
    pub payload_label: String,
    pub status: Option<u16>,
    pub length: usize,
    pub time_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum IntruderEvent {
    Result(IntruderResult),
    Finished,
}

pub fn parse_positions(request: &str) -> Vec<Position> {
    let mut positions = Vec::new();
    let mut cursor = 0;
    while let Some(relative_start) = request[cursor..].find('§') {
        let start_marker = cursor + relative_start;
        let content_start = start_marker + '§'.len_utf8();
        let Some(relative_end) = request[content_start..].find('§') else {
            break;
        };
        let end_marker = content_start + relative_end;
        let end = end_marker + '§'.len_utf8();
        positions.push(Position {
            start: start_marker,
            end,
            placeholder: request[content_start..end_marker].to_string(),
        });
        cursor = end;
    }
    positions
}

pub fn strip_markers(request: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    for position in parse_positions(request) {
        output.push_str(&request[cursor..position.start]);
        output.push_str(&position.placeholder);
        cursor = position.end;
    }
    output.push_str(&request[cursor..]);
    output
}

pub fn generate_payload_assignments(config: &AttackConfig) -> Vec<Vec<String>> {
    let position_count = config.positions.len();
    if position_count == 0 || config.payload_sets.is_empty() {
        return Vec::new();
    }
    let sets = config.payload_sets.iter().map(|set| set.source.values()).collect::<Vec<_>>();
    match config.attack_type {
        AttackType::Sniper => {
            let payloads = sets.first().cloned().unwrap_or_default();
            let mut output = Vec::new();
            for pos in 0..position_count {
                for payload in &payloads {
                    let mut assignment = config.positions.iter().map(|p| p.placeholder.clone()).collect::<Vec<_>>();
                    assignment[pos] = payload.clone();
                    output.push(assignment);
                }
            }
            output
        }
        AttackType::BatteringRam => sets.first().cloned().unwrap_or_default().into_iter().map(|payload| vec![payload; position_count]).collect(),
        AttackType::Pitchfork => {
            let min = (0..position_count)
                .filter_map(|index| sets.get(index).map(Vec::len))
                .min()
                .unwrap_or(0);
            (0..min)
                .map(|row| (0..position_count).map(|pos| sets.get(pos).and_then(|set| set.get(row)).cloned().unwrap_or_default()).collect())
                .collect()
        }
        AttackType::ClusterBomb => {
            fn recurse(sets: &[Vec<String>], pos: usize, current: &mut Vec<String>, output: &mut Vec<Vec<String>>) {
                if pos == sets.len() {
                    output.push(current.clone());
                    return;
                }
                for value in &sets[pos] {
                    current.push(value.clone());
                    recurse(sets, pos + 1, current, output);
                    current.pop();
                }
            }
            let mut normalized = Vec::new();
            for index in 0..position_count {
                normalized.push(sets.get(index).cloned().unwrap_or_default());
            }
            let mut output = Vec::new();
            recurse(&normalized, 0, &mut Vec::new(), &mut output);
            output
        }
    }
}

pub fn substitute_positions(request: &str, positions: &[Position], payloads: &[String]) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    for (index, position) in positions.iter().enumerate() {
        output.push_str(&request[cursor..position.start]);
        output.push_str(payloads.get(index).map(String::as_str).unwrap_or(&position.placeholder));
        cursor = position.end;
    }
    output.push_str(&request[cursor..]);
    output
}

pub struct IntruderEngine;

impl IntruderEngine {
    pub fn spawn(
        config: AttackConfig,
        tx: mpsc::Sender<IntruderEvent>,
        policy: Arc<Policy>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let assignments = generate_payload_assignments(&config);
            let semaphore = Arc::new(Semaphore::new(config.concurrency.max(1)));
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build();
            let Ok(client) = client else {
                let _ = tx.send(IntruderEvent::Finished).await;
                return;
            };
            let delay = if config.rps == 0 {
                Duration::from_millis(0)
            } else {
                Duration::from_millis((1000 / config.rps.max(1)) as u64)
            };
            // The engagement envelope's ceiling wins over the attack's own setting:
            // per-tab configuration must not be able to exceed the authorization.
            let delay = match policy.min_delay() {
                Some(minimum) => delay.max(minimum),
                None => delay,
            };
            let mut throttle = time::interval(delay.max(Duration::from_millis(1)));
            let mut handles = Vec::new();

            for (index, payloads) in assignments.into_iter().enumerate() {
                throttle.tick().await;
                let permit = semaphore.clone().acquire_owned().await;
                let Ok(permit) = permit else { break; };
                let raw_request = substitute_positions(&config.target_request, &config.positions, &payloads);
                let payload_label = payloads.join(", ");

                // Check the envelope before spawning: a denied payload is reported as
                // a result row so the blast radius is visible, not silently skipped.
                let blocked = match ParsedRequest::parse(&raw_request) {
                    Ok(parsed) => match policy.authorize(Traffic::Generated, &parsed.method, &parsed.url) {
                        Decision::Allow => None,
                        Decision::Deny(reason) => Some(reason.to_string()),
                    },
                    Err(error) => Some(format!("invalid request: {error}")),
                };
                if let Some(reason) = blocked {
                    let _ = tx
                        .send(IntruderEvent::Result(IntruderResult {
                            id: index as u64 + 1,
                            payload_label,
                            status: None,
                            length: 0,
                            time_ms: 0,
                            error: Some(format!("blocked: {reason}")),
                        }))
                        .await;
                    continue;
                }

                let client = client.clone();
                let tx = tx.clone();
                let policy = Arc::clone(&policy);
                handles.push(tokio::spawn(async move {
                    let _permit = permit;
                    let result = send_attack_request(index as u64 + 1, payload_label, raw_request, client).await;
                    if let Some(status) = result.status {
                        policy.observe(status);
                    }
                    let _ = tx.send(IntruderEvent::Result(result)).await;
                }));
            }

            for handle in handles {
                let _ = handle.await;
            }
            let _ = tx.send(IntruderEvent::Finished).await;
        })
    }
}

async fn send_attack_request(id: u64, payload_label: String, raw: String, client: reqwest::Client) -> IntruderResult {
    let started = Instant::now();
    match ParsedRequest::parse(&raw).and_then(|parsed| parsed.into_builder(&client)) {
        Ok(builder) => match builder.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.bytes().await.unwrap_or_else(|_| Bytes::new());
                IntruderResult { id, payload_label, status: Some(status), length: body.len(), time_ms: started.elapsed().as_millis() as u64, error: None }
            }
            Err(error) => IntruderResult { id, payload_label, status: None, length: 0, time_ms: started.elapsed().as_millis() as u64, error: Some(error.to_string()) },
        },
        Err(error) => IntruderResult { id, payload_label, status: None, length: 0, time_ms: started.elapsed().as_millis() as u64, error: Some(error) },
    }
}

struct ParsedRequest {
    method: String,
    url: String,
    headers: HeaderMap,
    body: Bytes,
}

impl ParsedRequest {
    fn parse(raw: &str) -> Result<Self, String> {
        let normalized = raw.replace("\r\n", "\n");
        let (head, body) = normalized.split_once("\n\n").unwrap_or((normalized.as_str(), ""));
        let mut lines = head.lines();
        let request_line = lines.next().ok_or_else(|| "missing request line".to_string())?;
        let parts = request_line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            return Err("request line must be METHOD PATH HTTP/VERSION".to_string());
        }
        let mut headers = HeaderMap::new();
        let mut host = None;
        for line in lines {
            if line.trim().is_empty() { continue; }
            let (name, value) = line.split_once(':').ok_or_else(|| format!("invalid header line: {line}"))?;
            let name = hyper::header::HeaderName::from_bytes(name.trim().as_bytes()).map_err(|e| e.to_string())?;
            let value = hyper::header::HeaderValue::from_str(value.trim()).map_err(|e| e.to_string())?;
            if name.as_str().eq_ignore_ascii_case("host") {
                host = Some(value.to_str().unwrap_or_default().to_string());
            }
            headers.insert(name, value);
        }
        let target = parts[1];
        let url = if target.starts_with("http://") || target.starts_with("https://") {
            target.to_string()
        } else {
            format!("http://{}{}", host.ok_or_else(|| "origin-form request requires Host header".to_string())?, target)
        };
        Ok(Self { method: parts[0].to_string(), url, headers, body: Bytes::copy_from_slice(body.as_bytes()) })
    }

    fn into_builder(self, client: &reqwest::Client) -> Result<reqwest::RequestBuilder, String> {
        let method = reqwest::Method::from_bytes(self.method.as_bytes()).map_err(|e| e.to_string())?;
        let mut builder = client.request(method, self.url);
        for (name, value) in self.headers.iter() {
            if name.as_str().eq_ignore_ascii_case("host") { continue; }
            builder = builder.header(name, value);
        }
        Ok(builder.body(self.body))
    }
}
