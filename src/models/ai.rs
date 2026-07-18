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
