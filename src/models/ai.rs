use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiRole {
    User,
    Assistant,
    System,
}

impl AiRole {
    pub fn label(self) -> &'static str {
        match self {
            Self::User => "You",
            Self::Assistant => "AI",
            Self::System => "System",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AiMessage {
    pub role: AiRole,
    pub content: String,
    pub timestamp: DateTime<Local>,
}

impl AiMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: AiRole::User,
            content: content.into(),
            timestamp: Local::now(),
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: AiRole::Assistant,
            content: content.into(),
            timestamp: Local::now(),
        }
    }

    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: AiRole::System,
            content: content.into(),
            timestamp: Local::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AiContext {
    pub title: String,
    pub summary: String,
    pub redacted_raw: String,
}

#[derive(Debug, Clone)]
pub struct AiSettings {
    pub ollama_url: String,
    pub model: String,
    pub temperature: f32,
    pub redaction_enabled: bool,
    pub max_context_chars: usize,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            ollama_url: std::env::var("PROXIMA_OLLAMA_URL")
                .unwrap_or_else(|_| "http://localhost:11434".to_string()),
            model: std::env::var("PROXIMA_OLLAMA_MODEL")
                .unwrap_or_else(|_| "qwen2.5-coder:7b".to_string()),
            temperature: 0.2,
            redaction_enabled: true,
            max_context_chars: 12_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AiPanelState {
    pub settings: AiSettings,
    pub messages: Vec<AiMessage>,
    pub input: String,
    pub attached_context: Option<AiContext>,
    pub is_waiting: bool,
    pub status: String,
    pub selected_quick_prompt: usize,
}

impl Default for AiPanelState {
    fn default() -> Self {
        Self {
            settings: AiSettings::default(),
            messages: vec![AiMessage::system(
                "Proxima AI Analyst ready. Attach a flow or ask a question about traffic, findings, payloads, or next safe steps.",
            )],
            input: String::new(),
            attached_context: None,
            is_waiting: false,
            status: "disconnected until first prompt".to_string(),
            selected_quick_prompt: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub enum AiEvent {
    Complete(Result<String, String>),
    FlowExplanationComplete {
        flow_id: u64,
        result: Result<FlowExplanation, String>,
    },
    FindingTriageComplete {
        finding_id: i64,
        result: Result<FindingTriage, String>,
    },
    RepeaterDraftComplete {
        tab_id: usize,
        result: Result<RepeaterAiDraft, String>,
    },
    IntruderPayloadsComplete {
        result: Result<IntruderPayloadSuggestion, String>,
    },
    IntruderAttackPlanComplete {
        result: Result<IntruderAttackPlan, String>,
    },
    ScopeRulesComplete {
        result: Result<ScopeRuleProposal, String>,
    },
    DecoderChainComplete {
        result: Result<DecoderChainSuggestion, String>,
    },
    ComparerSummaryComplete {
        result: Result<ComparerSummary, String>,
    },
    PassiveRuleDraftComplete {
        result: Result<PassiveRuleDraft, String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FlowExplanation {
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub request_summary: String,
    #[serde(default)]
    pub headers_meaning: Vec<HeaderMeaning>,
    #[serde(default)]
    pub cookies_session_tokens: String,
    #[serde(default)]
    pub suspicious_parameters: Vec<ParameterObservation>,
    #[serde(default)]
    pub interesting_endpoints: Vec<EndpointObservation>,
    #[serde(default)]
    pub auth_observations: String,
    #[serde(default)]
    pub response_tech_hints: Vec<String>,
    #[serde(default)]
    pub risk_notes: String,
    #[serde(default)]
    pub safe_next_steps: Vec<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderMeaning {
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub meaning: String,
    #[serde(default)]
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParameterObservation {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EndpointObservation {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub enum FlowExplanationState {
    Loading,
    Ready(FlowExplanation),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingTriage {
    #[serde(default)]
    pub priority: String,
    #[serde(default)]
    pub priority_label: String,
    #[serde(default)]
    pub real_risk: String,
    #[serde(default)]
    pub false_positive_likelihood: String,
    #[serde(default)]
    pub false_positive_reason: String,
    #[serde(default)]
    pub exploitability: String,
    #[serde(default)]
    pub proof_explanation: String,
    #[serde(default)]
    pub impact: String,
    #[serde(default)]
    pub remediation: String,
    #[serde(default)]
    pub report_summary: String,
    #[serde(default)]
    pub safe_validation_steps: Vec<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_text: Option<String>,
}

#[derive(Debug, Clone)]
pub enum FindingTriageState {
    Loading,
    Ready(FindingTriage),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepeaterAiDraft {
    #[serde(default)]
    pub modified_request: String,
    #[serde(default)]
    pub change_summary: Vec<String>,
    #[serde(default)]
    pub safety_notes: Vec<String>,
    #[serde(default)]
    pub preserved_sensitive_items: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_text: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RepeaterAiDraftState {
    Loading,
    Ready(RepeaterAiDraft),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntruderPayloadSuggestion {
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub safe_only: bool,
    #[serde(default)]
    pub target_parameter_hint: String,
    #[serde(default)]
    pub payloads: Vec<String>,
    #[serde(default)]
    pub blocked_payloads: Vec<String>,
    #[serde(default)]
    pub rationale: Vec<String>,
    #[serde(default)]
    pub safety_notes: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub recommended_attack_type: Option<String>,
    #[serde(default)]
    pub recommended_rps: Option<u32>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_text: Option<String>,
}

#[derive(Debug, Clone)]
pub enum IntruderPayloadSuggestionState {
    Loading,
    Ready(IntruderPayloadSuggestion),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntruderAttackPlan {
    #[serde(default)]
    pub plan_name: String,
    #[serde(default)]
    pub marked_request: String,
    #[serde(default)]
    pub detected_parameters: Vec<IntruderDetectedParameter>,
    #[serde(default)]
    pub recommended_attack_type: String,
    #[serde(default)]
    pub attack_type_reason: String,
    #[serde(default)]
    pub payload_sets: Vec<IntruderPlanPayloadSet>,
    #[serde(default)]
    pub expected_result_columns: Vec<String>,
    #[serde(default)]
    pub success_indicators: Vec<String>,
    #[serde(default)]
    pub safety_notes: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub recommended_rps: Option<u32>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntruderDetectedParameter {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub risk_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntruderPlanPayloadSet {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub position_hint: String,
    #[serde(default)]
    pub payloads: Vec<String>,
    #[serde(default)]
    pub blocked_payloads: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum IntruderAttackPlanState {
    Loading,
    Ready(IntruderAttackPlan),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScopeRuleProposal {
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub rules: Vec<ScopeRuleDraft>,
    #[serde(default)]
    pub test_cases: Vec<ScopeTestCase>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub replace_existing: bool,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScopeRuleDraft {
    #[serde(default)]
    pub rule_type: String,
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScopeTestCase {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub expected_in_scope: bool,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum ScopeRuleProposalState {
    Loading,
    Ready(ScopeRuleProposal),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecoderChainSuggestion {
    #[serde(default)]
    pub detected_type: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub suggested_chain: Vec<DecoderTransformSuggestion>,
    #[serde(default)]
    pub expected_output: String,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DecoderTransformSuggestion {
    #[serde(default)]
    pub transform: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone)]
pub enum DecoderChainSuggestionState {
    Loading,
    Ready(DecoderChainSuggestion),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComparerSummary {
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub high_signal_changes: Vec<ComparerChange>,
    #[serde(default)]
    pub likely_noise: Vec<String>,
    #[serde(default)]
    pub security_interpretation: String,
    #[serde(default)]
    pub suggested_next_steps: Vec<String>,
    #[serde(default)]
    pub risk_hint: String,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ComparerChange {
    #[serde(default)]
    pub change: String,
    #[serde(default)]
    pub security_relevance: String,
    #[serde(default)]
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub enum ComparerSummaryState {
    Loading,
    Ready(ComparerSummary),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PassiveRuleDraft {
    #[serde(default)]
    pub rule_id: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub yaml: String,
    #[serde(default)]
    pub explanation: String,
    #[serde(default)]
    pub test_examples: Vec<PassiveRuleTestExample>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub validation_errors: Vec<String>,
    #[serde(default)]
    pub validation_warnings: Vec<String>,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub raw_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PassiveRuleTestExample {
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub response_headers: String,
    #[serde(default)]
    pub response_body: String,
    #[serde(default)]
    pub expected_match: bool,
}

#[derive(Debug, Clone)]
pub enum PassiveRuleDraftState {
    Loading,
    Ready(PassiveRuleDraft),
    Error(String),
}

#[derive(Debug, Serialize)]
pub struct OllamaChatRequest {
    pub model: String,
    pub stream: bool,
    pub messages: Vec<OllamaMessage>,
    pub options: OllamaOptions,
}

#[derive(Debug, Serialize)]
pub struct OllamaOptions {
    pub temperature: f32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OllamaMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct OllamaChatResponse {
    pub message: Option<OllamaMessage>,
    pub error: Option<String>,
}

pub const QUICK_PROMPTS: [&str; 6] = [
    "Explain the attached flow in simple security terms.",
    "Find potential vulnerabilities or risk signals in the attached context. Be careful about uncertainty.",
    "Suggest the safest next manual testing steps. Do not send traffic automatically.",
    "Generate a Repeater test idea for this endpoint while preserving authorization.",
    "Generate safe Intruder payload ideas for the most interesting parameter.",
    "Write a concise report-style note for the attached finding or flow.",
];
