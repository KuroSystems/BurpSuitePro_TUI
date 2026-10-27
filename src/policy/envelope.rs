//! The engagement envelope: authorization, scope and limits as a file the tool
//! enforces instead of a rule the operator is trusted to remember.
//!
//! Everything that leaves Proxima — proxied traffic, Repeater sends, Intruder
//! payloads, active-scan probes — must pass through [`crate::policy::Policy::authorize`].
//! The module is deliberately dependency-light (regex + serde) so the check is
//! cheap enough to run per request.
//!
//! Parsing is strict: unknown fields are rejected. Silently ignoring a typo in
//! `deny_methods` would turn a safety control into decoration.

use std::{fs, path::Path};

use chrono::{DateTime, FixedOffset};
use regex::Regex;
use serde::{Deserialize, Serialize};

pub const API_VERSION: &str = "proxima.dev/v1alpha1";
pub const KIND: &str = "Engagement";

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub scope: Scope,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub id: String,
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub authorization: Option<Authorization>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    #[serde(default)]
    pub reference: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Anchored patterns; at least one is required, so an "empty" scope cannot
    /// accidentally mean "everything".
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default)]
    pub window: Option<Window>,
    /// Ceiling for generated traffic (Intruder, active checks, Repeater).
    /// Proxied browser traffic is never rate limited by the tool.
    #[serde(default)]
    pub max_rps: Option<u32>,
    #[serde(default)]
    pub max_requests_total: Option<u64>,
    /// Allow-list. `None` means "any method not in `deny_methods`".
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub deny_methods: Option<Vec<String>>,
    #[serde(default)]
    pub halt_on: Option<HaltOn>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Window {
    #[serde(default)]
    pub from: Option<DateTime<FixedOffset>>,
    #[serde(default)]
    pub to: Option<DateTime<FixedOffset>>,
}

/// Conditions that stop the engagement without a human having to notice a
/// dashboard. Counted over responses observed by the policy layer.
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HaltOn {
    /// Halt after this many `429 Too Many Requests` responses.
    #[serde(default)]
    pub status_429: Option<u32>,
    /// Halt when the fraction of `5xx` responses exceeds this rate, after a
    /// minimum sample so a cold start cannot trip it.
    #[serde(default)]
    pub status_5xx_rate: Option<f64>,
    /// Number of observations required before `status_5xx_rate` is evaluated.
    #[serde(default)]
    pub min_samples: Option<u64>,
}

#[derive(Debug, Default, Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Defaults to `.proxima/audit.log` when an envelope is loaded.
    #[serde(default)]
    pub log: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl AuditConfig {
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }

    pub fn log_path(&self) -> std::path::PathBuf {
        self.log
            .as_deref()
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(".proxima/audit.log"))
    }
}

/// A parsed and compiled envelope. Construction validates every pattern, so the
/// request path never has to deal with a bad regex halfway through an engagement.
#[derive(Debug)]
pub struct CompiledEnvelope {
    pub envelope: Envelope,
    include: Vec<Regex>,
    exclude: Vec<Regex>,
    methods: Option<Vec<String>>,
    deny_methods: Vec<String>,
}

impl CompiledEnvelope {
    pub fn parse(source: &str) -> Result<Self, String> {
        let envelope: Envelope =
            serde_yaml::from_str(source).map_err(|error| format!("invalid YAML: {error}"))?;
        Self::from_envelope(envelope)
    }

    pub fn from_path(path: &Path) -> Result<Self, String> {
        let source = fs::read_to_string(path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        Self::parse(&source)
    }

    pub fn from_envelope(envelope: Envelope) -> Result<Self, String> {
        if envelope.api_version != API_VERSION {
            return Err(format!(
                "unsupported apiVersion {:?} (expected {API_VERSION})",
                envelope.api_version
            ));
        }
        if envelope.kind != KIND {
            return Err(format!("unsupported kind {:?} (expected {KIND})", envelope.kind));
        }
        if envelope.metadata.id.trim().is_empty() {
            return Err("metadata.id must not be empty".to_string());
        }
        if envelope.scope.include.is_empty() {
            return Err(
                "scope.include must list at least one pattern; an empty scope is not \
                 interpreted as \"everything\""
                    .to_string(),
            );
        }

        let include = compile_all(&envelope.scope.include, "scope.include")?;
        let exclude = compile_all(&envelope.scope.exclude, "scope.exclude")?;

        let deny_methods = envelope
            .limits
            .deny_methods
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|method| method.to_ascii_uppercase())
            .collect();
        let methods = envelope
            .limits
            .methods
            .clone()
            .map(|methods| methods.into_iter().map(|m| m.to_ascii_uppercase()).collect());
        if let Some(methods) = &methods {
            if methods.is_empty() {
                return Err("limits.methods must not be empty when present".to_string());
            }
        }

        if let Some(rps) = envelope.limits.max_rps {
            if rps == 0 {
                return Err("limits.max_rps must be greater than zero".to_string());
            }
        }
        if let Some(window) = &envelope.limits.window {
            if let (Some(from), Some(to)) = (window.from, window.to) {
                if from >= to {
                    return Err("limits.window.from must be before limits.window.to".to_string());
                }
            }
        }

        Ok(Self {
            envelope,
            include,
            exclude,
            methods,
            deny_methods,
        })
    }

    /// True when `uri` matches an include pattern and no exclude pattern.
    /// Exclusions win: a broad include cannot re-open a closed path.
    pub fn matches_scope(&self, uri: &str) -> bool {
        let (include, exclude) = (self.include.iter().any(|re| re.is_match(uri)), self.exclude.iter().any(|re| re.is_match(uri)));
        self.scope_verdict(include, exclude) == ScopeVerdict::Included
    }

    fn scope_verdict(&self, include: bool, exclude: bool) -> ScopeVerdict {
        if exclude {
            ScopeVerdict::Excluded
        } else if include {
            ScopeVerdict::Included
        } else {
            ScopeVerdict::OutOfScope
        }
    }

    pub fn scope_of(&self, uri: &str) -> ScopeVerdict {
        let include = self.include.iter().any(|re| re.is_match(uri));
        let exclude = self.exclude.iter().any(|re| re.is_match(uri));
        self.scope_verdict(include, exclude)
    }

    pub fn method_allowed(&self, method: &str) -> MethodVerdict {
        let method = method.to_ascii_uppercase();
        if self.deny_methods.iter().any(|denied| *denied == method) {
            return MethodVerdict::Denied;
        }
        match &self.methods {
            Some(allowed) if !allowed.iter().any(|item| *item == method) => MethodVerdict::NotInAllowList,
            _ => MethodVerdict::Allowed,
        }
    }

    pub fn id(&self) -> &str {
        &self.envelope.metadata.id
    }

    pub fn authorization_reference(&self) -> Option<&str> {
        self.envelope
            .metadata
            .authorization
            .as_ref()
            .and_then(|authorization| authorization.reference.as_deref())
    }

    pub fn min_delay(&self) -> Option<std::time::Duration> {
        self.envelope
            .limits
            .max_rps
            .filter(|rps| *rps > 0)
            .map(|rps| std::time::Duration::from_millis((1000 / u64::from(rps)).max(1)))
    }

    pub fn summary(&self) -> String {
        let limits = &self.envelope.limits;
        let mut parts = Vec::new();
        if let Some(rps) = limits.max_rps {
            parts.push(format!("max {rps} req/s"));
        }
        if let Some(total) = limits.max_requests_total {
            parts.push(format!("max {total} requests"));
        }
        if let Some(window) = &limits.window {
            match (window.from, window.to) {
                (Some(from), Some(to)) => parts.push(format!(
                    "window {} → {}",
                    from.to_rfc3339(),
                    to.to_rfc3339()
                )),
                _ => parts.push("window bounded".to_string()),
            }
        }
        if let Some(methods) = &limits.methods {
            parts.push(format!("methods {}", methods.join(",")));
        }
        if let Some(denied) = &limits.deny_methods {
            if !denied.is_empty() {
                parts.push(format!("deny {}", denied.join(",")));
            }
        }
        if parts.is_empty() {
            format!("envelope {} (no limits)", self.id())
        } else {
            format!("envelope {} ({})", self.id(), parts.join(", "))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeVerdict {
    Included,
    Excluded,
    OutOfScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodVerdict {
    Allowed,
    Denied,
    NotInAllowList,
}

fn compile_all(patterns: &[String], field: &str) -> Result<Vec<Regex>, String> {
    patterns
        .iter()
        .map(|pattern| {
            Regex::new(pattern).map_err(|error| format!("{field}: invalid regex {pattern:?}: {error}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
apiVersion: proxima.dev/v1alpha1
kind: Engagement
metadata:
  id: test-engagement
  operator: alice@example.test
  authorization:
    reference: SOW-1
scope:
  include: ['^https://staging\.example\.test(/|$)']
"#;

    #[test]
    fn minimal_envelope_parses() {
        let compiled = CompiledEnvelope::parse(MINIMAL).expect("valid envelope");
        assert_eq!(compiled.id(), "test-engagement");
        assert_eq!(compiled.authorization_reference(), Some("SOW-1"));
        assert!(compiled.min_delay().is_none());
    }

    #[test]
    fn wrong_api_version_is_rejected() {
        let source = MINIMAL.replace("proxima.dev/v1alpha1", "proxima.dev/v0");
        let error = CompiledEnvelope::parse(&source).unwrap_err();
        assert!(error.contains("apiVersion"), "{error}");
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let source = MINIMAL.replace("kind: Engagement", "kind: ConfigMap");
        let error = CompiledEnvelope::parse(&source).unwrap_err();
        assert!(error.contains("kind"), "{error}");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        // A typo in a safety control must fail loudly, not be ignored.
        let source = format!("{MINIMAL}\nlimits:\n  deny_method: [DELETE]\n");
        let error = CompiledEnvelope::parse(&source).unwrap_err();
        assert!(error.contains("invalid YAML"), "{error}");
    }

    #[test]
    fn empty_scope_is_rejected() {
        let source = MINIMAL.replace(
            "  include: ['^https://staging\\.example\\.test(/|$)']",
            "  include: []",
        );
        let error = CompiledEnvelope::parse(&source).unwrap_err();
        assert!(error.contains("scope.include"), "{error}");
    }

    #[test]
    fn invalid_regex_is_rejected_with_the_field_name() {
        let source = MINIMAL.replace("'^https://staging\\.example\\.test(/|$)'", "'([a-z'");
        let error = CompiledEnvelope::parse(&source).unwrap_err();
        assert!(error.contains("scope.include"), "{error}");
    }

    #[test]
    fn scope_matching_honours_includes_and_excludes() {
        let source = format!(
            "{MINIMAL}  exclude: ['/logout', '/admin']\n"
        );
        let compiled = CompiledEnvelope::parse(&source).expect("valid envelope");
        assert_eq!(
            compiled.scope_of("https://staging.example.test/api/users"),
            ScopeVerdict::Included
        );
        assert_eq!(
            compiled.scope_of("https://staging.example.test/logout"),
            ScopeVerdict::Excluded
        );
        assert_eq!(
            compiled.scope_of("https://staging.example.test/admin/users"),
            ScopeVerdict::Excluded
        );
        assert_eq!(
            compiled.scope_of("https://prod.example.test/api"),
            ScopeVerdict::OutOfScope
        );
    }

    #[test]
    fn exclusions_win_over_a_broad_include() {
        let source = MINIMAL.replace(
            "  include: ['^https://staging\\.example\\.test(/|$)']",
            "  include: ['.*']\n  exclude: ['/billing']",
        );
        let compiled = CompiledEnvelope::parse(&source).expect("valid envelope");
        assert_eq!(compiled.scope_of("https://any.test/x"), ScopeVerdict::Included);
        assert_eq!(
            compiled.scope_of("https://any.test/billing/invoice"),
            ScopeVerdict::Excluded
        );
    }

    #[test]
    fn deny_methods_beat_allow_list_and_are_case_insensitive() {
        let source = format!(
            "{MINIMAL}\nlimits:\n  methods: [GET, POST, DELETE]\n  deny_methods: [delete]\n"
        );
        let compiled = CompiledEnvelope::parse(&source).expect("valid envelope");
        assert_eq!(compiled.method_allowed("get"), MethodVerdict::Allowed);
        assert_eq!(compiled.method_allowed("DELETE"), MethodVerdict::Denied);
        assert_eq!(compiled.method_allowed("PATCH"), MethodVerdict::NotInAllowList);
    }

    #[test]
    fn max_rps_becomes_a_per_request_delay() {
        let source = format!("{MINIMAL}\nlimits:\n  max_rps: 5\n");
        let compiled = CompiledEnvelope::parse(&source).expect("valid envelope");
        assert_eq!(
            compiled.min_delay(),
            Some(std::time::Duration::from_millis(200))
        );
    }

    #[test]
    fn zero_rps_is_rejected() {
        let source = format!("{MINIMAL}\nlimits:\n  max_rps: 0\n");
        assert!(CompiledEnvelope::parse(&source).is_err());
    }

    #[test]
    fn inverted_window_is_rejected() {
        let source = format!(
            "{MINIMAL}\nlimits:\n  window:\n    from: 2026-11-10T00:00:00Z\n    to: 2026-10-01T00:00:00Z\n"
        );
        let error = CompiledEnvelope::parse(&source).unwrap_err();
        assert!(error.contains("window"), "{error}");
    }

    #[test]
    fn summary_mentions_the_limits() {
        let source = format!("{MINIMAL}\nlimits:\n  max_rps: 5\n  deny_methods: [DELETE]\n");
        let compiled = CompiledEnvelope::parse(&source).expect("valid envelope");
        let summary = compiled.summary();
        assert!(summary.contains("test-engagement"), "{summary}");
        assert!(summary.contains("5 req/s"), "{summary}");
        assert!(summary.contains("DELETE"), "{summary}");
    }
}
