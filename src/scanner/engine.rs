use std::{fs, path::Path};

use chrono::Local;
use color_eyre::eyre::{Context, Result};
use hyper::HeaderMap;
use regex::Regex;
use serde_json::json;

use crate::{
    models::flow::HttpFlow,
    scanner::issue::{Finding, IssueDefinition, PassiveCheck},
};

#[derive(Debug, Clone)]
pub struct PassiveScanner {
    pub definitions: Vec<IssueDefinition>,
}

impl PassiveScanner {
    pub fn load_definitions(path: &Path) -> Result<Vec<IssueDefinition>> {
        let mut definitions = Vec::new();
        if !path.exists() {
            return Ok(default_definitions());
        }

        for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))? {
            let entry = entry?;
            let path = entry.path();
            let is_definition = path
                .extension()
                .and_then(|extension| extension.to_str())
                .map(|extension| matches!(extension, "yaml" | "yml" | "json"))
                .unwrap_or(false);
            if !is_definition {
                continue;
            }
            let content = fs::read_to_string(&path)
                .with_context(|| format!("failed to read scanner definition {}", path.display()))?;
            let definition = if path.extension().and_then(|e| e.to_str()) == Some("json") {
                serde_json::from_str::<IssueDefinition>(&content)?
            } else {
                serde_yaml::from_str::<IssueDefinition>(&content)?
            };
            definitions.push(definition);
        }

        if definitions.is_empty() {
            Ok(default_definitions())
        } else {
            Ok(definitions)
        }
    }

    pub fn load_default() -> Self {
        let path = std::env::var_os("PROXIMA_PASSIVE_DEFS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("resources/passive"));
        Self {
            definitions: Self::load_definitions(&path).unwrap_or_else(|_| default_definitions()),
        }
    }

    pub fn scan_flow(&self, flow: &HttpFlow) -> Vec<Finding> {
        let mut findings = Vec::new();
        for definition in self.definitions.iter().filter(|definition| definition.enabled) {
            let mut evidence = Vec::new();
            let mut matched_any = false;
            for check in &definition.passive_checks {
                if let Some(item) = evaluate_check(flow, check) {
                    matched_any = true;
                    evidence.push(item);
                }
            }
            if matched_any {
                findings.push(Finding {
                    id: 0,
                    flow_id: flow.id,
                    issue_id: definition.id.clone(),
                    issue_name: definition.name.clone(),
                    severity: definition.severity,
                    confidence: definition.confidence,
                    url: flow.uri.clone(),
                    evidence_json: serde_json::to_string(&evidence).unwrap_or_else(|_| "[]".to_string()),
                    timestamp: Local::now(),
                });
            }
        }
        findings
    }
}

fn evaluate_check(flow: &HttpFlow, check: &PassiveCheck) -> Option<serde_json::Value> {
    let response_headers = flow.response_headers.as_ref().unwrap_or(&flow.request_headers);
    // Checks must run against decoded bytes: a gzip/br body would otherwise never
    // match a body regex, which silently turns every passive check into a no-op.
    let decoded = flow.response_view();
    let response_body = decoded
        .as_ref()
        .map(|view| &view.body)
        .unwrap_or(&flow.request_body);

    match check {
        PassiveCheck::HeaderMissing { name } => {
            (!headers_contains(response_headers, name)).then(|| {
                json!({ "check": "header_missing", "header": name, "message": format!("Missing header {name}") })
            })
        }
        PassiveCheck::HeaderContains { name, value_regex } => {
            let regex = Regex::new(value_regex).ok()?;
            response_headers
                .iter()
                .find(|(header_name, value)| {
                    header_name.as_str().eq_ignore_ascii_case(name)
                        && value.to_str().map(|value| regex.is_match(value)).unwrap_or(false)
                })
                .map(|(_, value)| json!({ "check": "header_contains", "header": name, "value": value.to_str().unwrap_or("<binary>") }))
        }
        PassiveCheck::BodyRegex { pattern } => {
            let regex = Regex::new(pattern).ok()?;
            let body = String::from_utf8_lossy(response_body);
            regex.find(&body).map(|matched| {
                json!({ "check": "body_regex", "pattern": pattern, "match": matched.as_str() })
            })
        }
        PassiveCheck::StatusCode { codes } => flow
            .status
            .filter(|status| codes.contains(status))
            .map(|status| json!({ "check": "status_code", "status": status })),
    }
}

fn headers_contains(headers: &HeaderMap, name: &str) -> bool {
    headers
        .keys()
        .any(|header_name| header_name.as_str().eq_ignore_ascii_case(name))
}

fn default_definitions() -> Vec<IssueDefinition> {
    serde_yaml::from_str::<Vec<IssueDefinition>>(DEFAULT_DEFINITIONS).unwrap_or_default()
}

const DEFAULT_DEFINITIONS: &str = r#"
- id: missing-hsts
  name: Strict-Transport-Security header missing
  severity: medium
  confidence: firm
  passive_checks:
    - type: header_missing
      name: strict-transport-security
  references:
    - https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security
- id: missing-csp
  name: Content-Security-Policy header missing
  severity: low
  confidence: firm
  passive_checks:
    - type: header_missing
      name: content-security-policy
- id: missing-x-frame-options
  name: X-Frame-Options header missing
  severity: low
  confidence: firm
  passive_checks:
    - type: header_missing
      name: x-frame-options
- id: server-disclosure
  name: Server version banner disclosure
  severity: info
  confidence: firm
  passive_checks:
    - type: header_contains
      name: server
      value_regex: '(?i)(apache|nginx|iis|express|jetty|tomcat|gunicorn|uvicorn|php|openresty)[/ ]?[0-9]'
- id: stack-trace-disclosure
  name: Stack trace disclosure
  severity: medium
  confidence: tentative
  passive_checks:
    - type: body_regex
      pattern: '(?i)(stack trace|traceback \(most recent call last\)|exception in thread|at [a-z0-9_.$]+\([^)]*\.java:[0-9]+\))'
- id: reflected-xss-markers
  name: Reflected script marker
  severity: high
  confidence: tentative
  passive_checks:
    - type: body_regex
      pattern: '(?i)<script[^>]*>|javascript:|onerror='
"#;
