use std::{future::Future, pin::Pin, sync::Arc};

use chrono::Local;
use reqwest::{Client, Url};
use tokio::time::{self, Duration};

use crate::policy::{Decision, Policy, Traffic};
use crate::scanner::issue::{Confidence, Finding, Severity};

pub trait ActiveCheck: Send + Sync {
    fn id(&self) -> &'static str;
    fn name(&self) -> &'static str;
    fn is_safe(&self) -> bool {
        true
    }
    fn run<'a>(
        &'a self,
        target: &'a Url,
        client: &'a Client,
        policy: &'a Policy,
    ) -> Pin<Box<dyn Future<Output = Vec<Finding>> + Send + 'a>>;
}

/// Every probe asks the envelope about the exact request it is about to send, not
/// about the target it started from: a probe that appends a path or a query is a
/// different request, and may land outside scope or on an excluded path.
fn permitted(policy: &Policy, method: &str, url: &Url) -> bool {
    matches!(
        policy.authorize(Traffic::Generated, method, url.as_str()),
        Decision::Allow
    )
}

#[derive(Debug, Clone)]
pub struct ActiveScanTarget {
    pub url: Url,
    pub confirmed: bool,
    pub completed: usize,
    pub total: usize,
    pub running: bool,
}

#[derive(Debug, Clone)]
pub enum ActiveScannerEvent {
    Finding(Finding),
    /// The engagement envelope refused the target; the scan stopped before sending.
    Blocked { target: String, reason: String },
    Progress { target: String, completed: usize, total: usize },
    Finished { target: String },
}

pub struct PathTraversalProbe;
pub struct ReflectedXssProbe;
pub struct VerbTamperingProbe;

impl ActiveCheck for PathTraversalProbe {
    fn id(&self) -> &'static str { "active-path-traversal-probe" }
    fn name(&self) -> &'static str { "Path traversal probe" }
    fn run<'a>(&'a self, target: &'a Url, client: &'a Client, policy: &'a Policy) -> Pin<Box<dyn Future<Output = Vec<Finding>> + Send + 'a>> {
        Box::pin(async move {
            let mut url = target.clone();
            url.set_path("/../../../etc/passwd");
            if !permitted(policy, "GET", &url) {
                return Vec::new();
            }
            match client.get(url.clone()).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    let body = response.text().await.unwrap_or_default();
                    if status == 200 && body.contains("root:") {
                        vec![active_finding(0, self.id(), self.name(), Severity::High, Confidence::Firm, url.as_str(), "passwd-like content returned")]
                    } else { Vec::new() }
                }
                Err(_) => Vec::new(),
            }
        })
    }
}

impl ActiveCheck for ReflectedXssProbe {
    fn id(&self) -> &'static str { "active-reflected-marker-probe" }
    fn name(&self) -> &'static str { "Reflected marker probe" }
    fn run<'a>(&'a self, target: &'a Url, client: &'a Client, policy: &'a Policy) -> Pin<Box<dyn Future<Output = Vec<Finding>> + Send + 'a>> {
        Box::pin(async move {
            let mut url = target.clone();
            url.query_pairs_mut().append_pair("proxima_probe", "<proxima-test>");
            if !permitted(policy, "GET", &url) {
                return Vec::new();
            }
            match client.get(url.clone()).send().await {
                Ok(response) => {
                    let body = response.text().await.unwrap_or_default();
                    if body.contains("<proxima-test>") {
                        vec![active_finding(0, self.id(), self.name(), Severity::Medium, Confidence::Tentative, url.as_str(), "probe marker reflected in response")]
                    } else { Vec::new() }
                }
                Err(_) => Vec::new(),
            }
        })
    }
}

impl ActiveCheck for VerbTamperingProbe {
    fn id(&self) -> &'static str { "active-verb-tampering-probe" }
    fn name(&self) -> &'static str { "Verb tampering probe" }
    fn run<'a>(&'a self, target: &'a Url, client: &'a Client, policy: &'a Policy) -> Pin<Box<dyn Future<Output = Vec<Finding>> + Send + 'a>> {
        Box::pin(async move {
            if !permitted(policy, "GET", target) || !permitted(policy, "POST", target) {
                return Vec::new();
            }
            let get = client.get(target.clone()).send().await;
            let post = client.post(target.clone()).send().await;
            match (get, post) {
                (Ok(get), Ok(post)) if get.status().as_u16() == 200 && post.status().as_u16() == 200 => {
                    let get_len = get.bytes().await.map(|b| b.len()).unwrap_or_default();
                    let post_len = post.bytes().await.map(|b| b.len()).unwrap_or_default();
                    let delta = get_len.abs_diff(post_len);
                    if delta < 16 {
                        vec![active_finding(0, self.id(), self.name(), Severity::Low, Confidence::Tentative, target.as_str(), "GET and POST produced near-identical successful responses")]
                    } else { Vec::new() }
                }
                _ => Vec::new(),
            }
        })
    }
}

pub fn default_active_checks() -> Vec<Box<dyn ActiveCheck>> {
    vec![Box::new(PathTraversalProbe), Box::new(ReflectedXssProbe), Box::new(VerbTamperingProbe)]
}

pub async fn run_safe_active_scan(
    target: Url,
    tx: tokio::sync::mpsc::Sender<ActiveScannerEvent>,
    policy: Arc<Policy>,
) {
    let client = match Client::builder().redirect(reqwest::redirect::Policy::none()).build() {
        Ok(client) => client,
        Err(_) => return,
    };
    let checks = default_active_checks();
    let total = checks.len();
    // 10 req/s per target by default, never faster than the envelope allows.
    let spacing = match policy.min_delay() {
        Some(minimum) => Duration::from_millis(100).max(minimum),
        None => Duration::from_millis(100),
    };
    let mut interval = time::interval(spacing);
    for (index, check) in checks.iter().enumerate() {
        interval.tick().await;
        // Re-checked per probe: the envelope can expire or trip a halt mid-scan.
        if let Decision::Deny(reason) = policy.authorize(Traffic::Generated, "GET", target.as_str()) {
            let _ = tx
                .send(ActiveScannerEvent::Blocked {
                    target: target.to_string(),
                    reason: reason.to_string(),
                })
                .await;
            return;
        }
        if check.is_safe() {
            for finding in check.run(&target, &client, &policy).await {
                let _ = tx.send(ActiveScannerEvent::Finding(finding)).await;
            }
        }
        let _ = tx.send(ActiveScannerEvent::Progress { target: target.to_string(), completed: index + 1, total }).await;
    }
    let _ = tx.send(ActiveScannerEvent::Finished { target: target.to_string() }).await;
}

fn active_finding(
    flow_id: u64,
    issue_id: &str,
    issue_name: &str,
    severity: Severity,
    confidence: Confidence,
    url: &str,
    evidence: &str,
) -> Finding {
    Finding {
        id: 0,
        flow_id,
        issue_id: issue_id.to_string(),
        issue_name: issue_name.to_string(),
        severity,
        confidence,
        url: url.to_string(),
        evidence_json: serde_json::json!({ "active": true, "evidence": evidence }).to_string(),
        timestamp: Local::now(),
    }
}
