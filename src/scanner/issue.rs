use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Info => "Info",
            Self::Low => "Low",
            Self::Medium => "Medium",
            Self::High => "High",
            Self::Critical => "Critical",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Tentative,
    Firm,
    Certain,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::Tentative => "Tentative",
            Self::Firm => "Firm",
            Self::Certain => "Certain",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tentative => "tentative",
            Self::Firm => "firm",
            Self::Certain => "certain",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value {
            "certain" => Self::Certain,
            "firm" => Self::Firm,
            _ => Self::Tentative,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueDefinition {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    #[serde(default)]
    pub passive_checks: Vec<PassiveCheck>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PassiveCheck {
    HeaderMissing { name: String },
    HeaderContains { name: String, value_regex: String },
    BodyRegex { pattern: String },
    StatusCode { codes: Vec<u16> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: i64,
    pub flow_id: u64,
    pub issue_id: String,
    pub issue_name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub url: String,
    pub evidence_json: String,
    pub timestamp: DateTime<Local>,
}
