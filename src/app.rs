use std::{collections::HashMap, time::Instant};

use bytes::Bytes;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use hyper::HeaderMap;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    db::Database,
    events::{Event, ProxyEvent, RepeaterEvent},
    models::{
        ai::{
            AiContext, AiEvent, AiMessage, AiPanelState, ComparerSummary, ComparerSummaryState,
            DecoderChainSuggestion, DecoderChainSuggestionState, FindingTriage, FindingTriageState, FlowExplanation,
            FlowExplanationState, IntruderAttackPlan, IntruderAttackPlanState,
            IntruderPayloadSuggestion, IntruderPayloadSuggestionState, IntruderPlanPayloadSet,
            OllamaChatRequest, OllamaChatResponse, OllamaMessage, OllamaOptions, PassiveRuleDraft,
            PassiveRuleDraftState, RepeaterAiDraft, RepeaterAiDraftState, ScopeRuleProposal,
            ScopeRuleProposalState, QUICK_PROMPTS,
        },
        comparer::CompareMode,
        decoder::DecoderTransform,
        flow::HttpFlow,
        intruder::{parse_positions, AttackConfig, AttackType, IntruderEngine, IntruderEvent, IntruderResult, PayloadSet},
        repeater::{HttpResponse, RepeaterTab, SendHistoryEntry},
        scope::{ScopeEngine, ScopeRule, ScopeRuleType},
    },
    plugins::PluginManager,
    proxy::{run_proxy, LoggingHandler, ProxyConfig},
    scanner::{run_safe_active_scan, ActiveScanTarget, ActiveScannerEvent, Confidence, Finding, IssueDefinition, PassiveCheck, PassiveScanner, Severity},
    store::FlowStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Proxy,
    Ai,
    Repeater,
    Scope,
    Intruder,
    Decoder,
    Comparer,
    Scanner,
    Active,
    WebSockets,
    Plugins,
    Settings,
}

impl Tab {
    pub const ALL: [Self; 12] = [
        Self::Proxy,
        Self::Ai,
        Self::Repeater,
        Self::Scope,
        Self::Intruder,
        Self::Decoder,
        Self::Comparer,
        Self::Scanner,
        Self::Active,
        Self::WebSockets,
        Self::Plugins,
        Self::Settings,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Proxy => "Proxy",
            Self::Ai => "AI",
            Self::Repeater => "Repeater",
            Self::Scope => "Scope",
            Self::Intruder => "Intruder",
            Self::Decoder => "Decoder",
            Self::Comparer => "Comparer",
            Self::Scanner => "Scanner",
            Self::Active => "Active",
            Self::WebSockets => "WebSockets",
            Self::Plugins => "Plugins",
            Self::Settings => "Settings",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|tab| *tab == self).unwrap_or(0)
    }

    fn from_index(index: usize) -> Self {
        Self::ALL[index % Self::ALL.len()]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyStatus {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyDetailMode {
    AiBrief,
    RawEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerDetailMode {
    AiTriage,
    Evidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerAiMode {
    None,
    RulePrompt,
    RulePreview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComparerDetailMode {
    RawDiff,
    AiSummary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeAiMode {
    Editing,
    Prompt,
    ProposalPreview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderAiMode {
    Editing,
    SuggestionPreview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepeaterAiMode {
    Editing,
    Prompt,
    DraftPreview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntruderAiMode {
    Editing,
    PayloadPrompt,
    PayloadSuggestionPreview,
    PlannerPrompt,
    PlanPreview,
}

impl ProxyStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Running => "running",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug)]
pub struct App {
    pub current_tab: Tab,
    pub should_quit: bool,
    pub tick_count: u64,
    pub proxy_config: ProxyConfig,
    pub proxy_status: ProxyStatus,
    pub proxy_message: String,
    pub flow_store: FlowStore,
    pub selected_flow: Option<usize>,
    pub request_scroll: u16,
    pub response_scroll: u16,
    pub proxy_detail_mode: ProxyDetailMode,
    pub search_mode: bool,
    pub search_query: String,
    pub terminal_size: (u16, u16),
    pub repeater_tabs: Vec<RepeaterTab>,
    pub active_repeater: usize,
    pub repeater_cursor: usize,
    pub repeater_response_scroll: u16,
    pub repeater_ai_mode: RepeaterAiMode,
    pub repeater_ai_input: String,
    pub repeater_ai_drafts: HashMap<usize, RepeaterAiDraftState>,
    pub renaming_repeater: bool,
    pub rename_buffer: String,
    pub database: Database,
    pub project_message: String,
    pub local_clipboard: String,
    pub scope_engine: ScopeEngine,
    pub selected_scope_rule: usize,
    pub scope_input_mode: Option<ScopeInputMode>,
    pub scope_buffer: String,
    pub scope_test_url: String,
    pub last_scope_test_result: Option<bool>,
    pub scope_ai_mode: ScopeAiMode,
    pub scope_ai_input: String,
    pub scope_ai_proposal: Option<ScopeRuleProposalState>,
    pub intruder_request_text: String,
    pub intruder_attack_type: AttackType,
    pub intruder_payloads_text: String,
    pub intruder_ai_mode: IntruderAiMode,
    pub intruder_ai_input: String,
    pub intruder_ai_suggestion: Option<IntruderPayloadSuggestionState>,
    pub intruder_ai_plan: Option<IntruderAttackPlanState>,
    pub intruder_plan_payload_sets: Vec<IntruderPlanPayloadSet>,
    pub intruder_concurrency: usize,
    pub intruder_rps: u32,
    pub intruder_results: Vec<IntruderResult>,
    pub intruder_running: bool,
    pub intruder_paused: bool,
    pub intruder_total: usize,
    pub intruder_selected_result: usize,
    pub intruder_sort_desc: bool,
    pub intruder_filter_status: Option<u16>,
    pub decoder_input: String,
    pub decoder_chain: Vec<DecoderTransform>,
    pub selected_decoder_transform: usize,
    pub decoder_insert_index: usize,
    pub decoder_ai_mode: DecoderAiMode,
    pub decoder_ai_suggestion: Option<DecoderChainSuggestionState>,
    pub comparer_left: String,
    pub comparer_right: String,
    pub comparer_mode: CompareMode,
    pub comparer_focus_right: bool,
    pub comparer_marked_flows: Vec<usize>,
    pub comparer_detail_mode: ComparerDetailMode,
    pub comparer_ai_summary: Option<ComparerSummaryState>,
    pub passive_scanner: PassiveScanner,
    pub findings: Vec<Finding>,
    pub selected_finding: usize,
    pub scanner_detail_mode: ScannerDetailMode,
    pub scanner_ai_mode: ScannerAiMode,
    pub scanner_ai_input: String,
    pub scanner_rule_draft: Option<PassiveRuleDraftState>,
    pub scanner_severity_filter: Option<Severity>,
    pub scanner_confidence_filter: Option<Confidence>,
    pub selected_scanner_check: usize,
    pub active_scanning_enabled: bool,
    pub active_scan_targets: Vec<ActiveScanTarget>,
    pub selected_active_target: usize,
    pub websocket_selected_frame: usize,
    pub plugin_manager: PluginManager,
    pub selected_plugin: usize,
    pub ai_panel: AiPanelState,
    pub flow_ai_explanations: HashMap<u64, FlowExplanationState>,
    pub finding_triage: HashMap<i64, FindingTriageState>,
    pub ollama_models: Vec<String>,
    pub ai_model_presets: Vec<String>,
    pub selected_ai_model: usize,
    pub ollama_status: String,
    pub ollama_auto_refreshed: bool,
    next_repeater_id: usize,
    repeater_tx: mpsc::Sender<RepeaterEvent>,
    intruder_tx: mpsc::Sender<IntruderEvent>,
    active_scanner_tx: mpsc::Sender<ActiveScannerEvent>,
    ai_tx: mpsc::Sender<AiEvent>,
    active_scan_task: Option<JoinHandle<()>>,
    intruder_task: Option<JoinHandle<()>>,
    proxy_task: Option<JoinHandle<Result<(), color_eyre::eyre::Report>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeInputMode {
    Add,
    Edit,
    Test,
}

impl App {
    pub fn new(
        flow_store: FlowStore,
        repeater_tx: mpsc::Sender<RepeaterEvent>,
        intruder_tx: mpsc::Sender<IntruderEvent>,
        active_scanner_tx: mpsc::Sender<ActiveScannerEvent>,
        ai_tx: mpsc::Sender<AiEvent>,
    ) -> Self {
        let mut proxy_config = ProxyConfig::default();
        let database = Database::open_default().expect("failed to open default project database");
        if let Ok(Some(listen_addr)) = database.load_setting("proxy.listen_addr") {
            if let Ok(listen_addr) = listen_addr.parse() {
                proxy_config.listen_addr = listen_addr;
            }
        }
        let loaded_flows = database.load_flows(10_000, 0).unwrap_or_default();
        flow_store.set_flows(loaded_flows);
        let loaded_repeater_tabs = database.load_repeater_tabs().unwrap_or_default();
        let repeater_tabs = if loaded_repeater_tabs.is_empty() {
            vec![RepeaterTab::new(1, "Request 1", default_repeater_request())]
        } else {
            loaded_repeater_tabs
        };
        let repeater_cursor = repeater_tabs
            .first()
            .map(|tab| tab.request_text.len())
            .unwrap_or_default();
        let next_repeater_id = repeater_tabs.iter().map(|tab| tab.id).max().unwrap_or(0) + 1;
        let scope_rules = database.load_scope_rules().unwrap_or_default();
        let intruder_results = database.load_intruder_results().unwrap_or_default();
        let findings = database.load_findings().unwrap_or_default();
        let project_message = format!("Project: {}", database.path().display());
        Self {
            current_tab: Tab::Proxy,
            should_quit: false,
            tick_count: 0,
            proxy_status: ProxyStatus::Stopped,
            proxy_message: format!("Proxy ready on {}", proxy_config.listen_addr),
            proxy_config,
            flow_store,
            selected_flow: None,
            request_scroll: 0,
            response_scroll: 0,
            proxy_detail_mode: ProxyDetailMode::AiBrief,
            search_mode: false,
            search_query: String::new(),
            terminal_size: (120, 40),
            repeater_tabs,
            active_repeater: 0,
            repeater_cursor,
            repeater_response_scroll: 0,
            repeater_ai_mode: RepeaterAiMode::Editing,
            repeater_ai_input: String::new(),
            repeater_ai_drafts: HashMap::new(),
            renaming_repeater: false,
            rename_buffer: String::new(),
            database,
            project_message,
            local_clipboard: String::new(),
            scope_engine: ScopeEngine::new(scope_rules),
            selected_scope_rule: 0,
            scope_input_mode: None,
            scope_buffer: String::new(),
            scope_test_url: "https://example.com/".to_string(),
            last_scope_test_result: None,
            scope_ai_mode: ScopeAiMode::Editing,
            scope_ai_input: String::new(),
            scope_ai_proposal: None,
            intruder_request_text: default_intruder_request(),
            intruder_attack_type: AttackType::Sniper,
            intruder_payloads_text: "admin\ntest\npassword\n123456".to_string(),
            intruder_ai_mode: IntruderAiMode::Editing,
            intruder_ai_input: String::new(),
            intruder_ai_suggestion: None,
            intruder_ai_plan: None,
            intruder_plan_payload_sets: Vec::new(),
            intruder_concurrency: 4,
            intruder_rps: 10,
            intruder_results,
            intruder_running: false,
            intruder_paused: false,
            intruder_total: 0,
            intruder_selected_result: 0,
            intruder_sort_desc: false,
            intruder_filter_status: None,
            decoder_input: "SGVsbG8lMjBXb3JsZA==".to_string(),
            decoder_chain: vec![DecoderTransform::Base64Decode, DecoderTransform::UrlDecode],
            selected_decoder_transform: 0,
            decoder_insert_index: 0,
            decoder_ai_mode: DecoderAiMode::Editing,
            decoder_ai_suggestion: None,
            comparer_left: String::new(),
            comparer_right: String::new(),
            comparer_mode: CompareMode::Line,
            comparer_focus_right: false,
            comparer_marked_flows: Vec::new(),
            comparer_detail_mode: ComparerDetailMode::RawDiff,
            comparer_ai_summary: None,
            passive_scanner: PassiveScanner::load_default(),
            findings,
            selected_finding: 0,
            scanner_detail_mode: ScannerDetailMode::AiTriage,
            scanner_ai_mode: ScannerAiMode::None,
            scanner_ai_input: String::new(),
            scanner_rule_draft: None,
            scanner_severity_filter: None,
            scanner_confidence_filter: None,
            selected_scanner_check: 0,
            active_scanning_enabled: false,
            active_scan_targets: Vec::new(),
            selected_active_target: 0,
            websocket_selected_frame: 0,
            plugin_manager: PluginManager::load_default(),
            selected_plugin: 0,
            ai_panel: AiPanelState::default(),
            flow_ai_explanations: HashMap::new(),
            finding_triage: HashMap::new(),
            ollama_models: Vec::new(),
            ai_model_presets: configured_ai_model_presets(),
            selected_ai_model: 0,
            ollama_status: "auto-refreshing local Ollama models...".to_string(),
            ollama_auto_refreshed: false,
            next_repeater_id,
            repeater_tx,
            intruder_tx,
            active_scanner_tx,
            ai_tx,
            active_scan_task: None,
            intruder_task: None,
            proxy_task: None,
        }
    }

    pub fn active_repeater_tab(&self) -> Option<&RepeaterTab> {
        self.repeater_tabs.get(self.active_repeater)
    }

    pub fn handle_event(&mut self, event: Event) {
        match event {
            Event::Tick => self.tick(),
            Event::Key(key) => self.handle_key_event(key),
            Event::Mouse(mouse) => self.handle_mouse_event(mouse),
            Event::Paste(text) => self.handle_paste(text),
            Event::Resize(width, height) => self.terminal_size = (width, height),
            Event::ProxyEvent(event) => self.handle_proxy_event(event),
            Event::RepeaterEvent(event) => self.handle_repeater_event(event),
            Event::IntruderEvent(event) => self.handle_intruder_event(event),
            Event::ActiveScannerEvent(event) => self.handle_active_scanner_event(event),
            Event::AiEvent(event) => self.handle_ai_event(event),
            Event::Render => {}
        }
    }

    pub fn filtered_flow_indices(&self) -> Vec<usize> {
        self.flow_store
            .snapshot()
            .iter()
            .enumerate()
            .filter_map(|(index, flow)| flow.matches_query(&self.search_query).then_some(index))
            .collect()
    }

    pub fn selected_filtered_position(&self) -> Option<usize> {
        let selected = self.selected_flow?;
        self.filtered_flow_indices()
            .iter()
            .position(|index| *index == selected)
    }

    fn tick(&mut self) {
        self.tick_count = self.tick_count.saturating_add(1);
        if !self.ollama_auto_refreshed {
            self.ollama_auto_refreshed = true;
            self.refresh_ollama_models();
        }
        if self
            .proxy_task
            .as_ref()
            .map(|task| task.is_finished())
            .unwrap_or(false)
        {
            self.proxy_status = ProxyStatus::Failed;
            self.proxy_message = "Proxy task exited; see logs/proxima-tui.log".to_string();
            self.proxy_task = None;
        }
        if self.tick_count % 120 == 0 {
            self.autosave_project();
        }
    }

    fn handle_proxy_event(&mut self, event: ProxyEvent) {
        match event {
            ProxyEvent::NewFlow(id) => {
                if self.selected_flow.is_none() {
                    self.selected_flow = self.flow_store.len().checked_sub(1);
                }
                if let Some(flow) = self.flow_store.get_by_id(id) {
                    if let Err(error) = self.database.save_flow(&flow) {
                        self.project_message = format!("Failed to save flow: {error}");
                    }
                    self.scan_and_store_flow(&flow);
                    for mut finding in self.plugin_manager.on_new_flow(&flow) {
                        if let Ok(id) = self.database.save_finding(&finding) {
                            finding.id = id;
                        }
                        self.findings.push(finding);
                    }
                }
            }
            ProxyEvent::NewWebSocketFrame(_) => {}
        }
    }

    fn handle_repeater_event(&mut self, event: RepeaterEvent) {
        match event {
            RepeaterEvent::SendComplete { tab_id, response } => {
                if let Some(tab) = self.repeater_tabs.iter_mut().find(|tab| tab.id == tab_id) {
                    tab.is_sending = false;
                    match response {
                        Ok(response) => {
                            tab.error = None;
                            tab.history.push(SendHistoryEntry {
                                status: Some(response.status),
                                duration_ms: Some(response.duration_ms),
                                body_len: response.body_len(),
                                error: None,
                            });
                            tab.response = Some(response);
                        }
                        Err(error) => {
                            tab.error = Some(error.clone());
                            tab.history.push(SendHistoryEntry {
                                status: None,
                                duration_ms: None,
                                body_len: 0,
                                error: Some(error),
                            });
                        }
                    }
                    self.repeater_response_scroll = 0;
                    self.persist_repeater_tabs();
                }
            }
        }
    }

    fn handle_intruder_event(&mut self, event: IntruderEvent) {
        match event {
            IntruderEvent::Result(result) => {
                self.intruder_results.push(result);
                self.sort_intruder_results();
                let _ = self.database.save_intruder_results(&self.intruder_results);
            }
            IntruderEvent::Finished => {
                self.intruder_running = false;
                self.intruder_paused = false;
                self.intruder_task = None;
                let _ = self.database.save_intruder_results(&self.intruder_results);
            }
        }
    }

    fn handle_active_scanner_event(&mut self, event: ActiveScannerEvent) {
        match event {
            ActiveScannerEvent::Finding(mut finding) => {
                if let Ok(id) = self.database.save_finding(&finding) {
                    finding.id = id;
                }
                self.findings.push(finding);
            }
            ActiveScannerEvent::Progress { target, completed, total } => {
                if let Some(item) = self.active_scan_targets.iter_mut().find(|item| item.url.as_str() == target.as_str()) {
                    item.completed = completed;
                    item.total = total;
                    item.running = true;
                }
            }
            ActiveScannerEvent::Finished { target } => {
                if let Some(item) = self.active_scan_targets.iter_mut().find(|item| item.url.as_str() == target.as_str()) {
                    item.running = false;
                    item.completed = item.total;
                }
                self.active_scan_task = None;
            }
        }
    }

    fn handle_ai_event(&mut self, event: AiEvent) {
        match event {
            AiEvent::Complete(Ok(answer)) => {
                self.ai_panel.is_waiting = false;
                self.ai_panel.status = "complete".to_string();
                self.ai_panel.messages.push(AiMessage::assistant(answer));
            }
            AiEvent::Complete(Err(error)) => {
                self.ai_panel.is_waiting = false;
                self.ai_panel.status = format!("error: {error}");
                self.ai_panel
                    .messages
                    .push(AiMessage::assistant(format!("AI request failed: {error}")));
            }
            AiEvent::FlowExplanationComplete { flow_id, result } => match result {
                Ok(explanation) => {
                    self.flow_ai_explanations
                        .insert(flow_id, FlowExplanationState::Ready(explanation));
                    self.project_message = format!("AI Flow Brief ready for flow #{flow_id}");
                }
                Err(error) => {
                    self.flow_ai_explanations
                        .insert(flow_id, FlowExplanationState::Error(error.clone()));
                    self.project_message = format!("AI Flow Brief failed for flow #{flow_id}: {error}");
                }
            },
            AiEvent::FindingTriageComplete { finding_id, result } => match result {
                Ok(triage) => {
                    self.finding_triage
                        .insert(finding_id, FindingTriageState::Ready(triage));
                    if let Some(position) = self
                        .filtered_findings()
                        .iter()
                        .position(|finding| finding.id == finding_id)
                    {
                        self.selected_finding = position;
                    }
                    self.project_message = format!("AI triage ready for finding #{finding_id}");
                }
                Err(error) => {
                    self.finding_triage
                        .insert(finding_id, FindingTriageState::Error(error.clone()));
                    if let Some(position) = self
                        .filtered_findings()
                        .iter()
                        .position(|finding| finding.id == finding_id)
                    {
                        self.selected_finding = position;
                    }
                    self.project_message = format!("AI triage failed for finding #{finding_id}: {error}");
                }
            },
            AiEvent::RepeaterDraftComplete { tab_id, result } => match result {
                Ok(draft) => {
                    self.repeater_ai_drafts
                        .insert(tab_id, RepeaterAiDraftState::Ready(draft));
                    if self.active_repeater_tab().map(|tab| tab.id) == Some(tab_id) {
                        self.repeater_ai_mode = RepeaterAiMode::DraftPreview;
                    }
                    self.project_message = format!("AI request draft ready for repeater tab #{tab_id}");
                }
                Err(error) => {
                    self.repeater_ai_drafts
                        .insert(tab_id, RepeaterAiDraftState::Error(error.clone()));
                    if self.active_repeater_tab().map(|tab| tab.id) == Some(tab_id) {
                        self.repeater_ai_mode = RepeaterAiMode::DraftPreview;
                    }
                    self.project_message = format!("AI request builder failed for tab #{tab_id}: {error}");
                }
            },
            AiEvent::IntruderPayloadsComplete { result } => match result {
                Ok(suggestion) => {
                    let count = suggestion.payloads.len();
                    self.intruder_ai_suggestion = Some(IntruderPayloadSuggestionState::Ready(suggestion));
                    self.intruder_ai_mode = IntruderAiMode::PayloadSuggestionPreview;
                    self.project_message = format!("AI generated {count} safe Intruder payloads");
                }
                Err(error) => {
                    self.intruder_ai_suggestion = Some(IntruderPayloadSuggestionState::Error(error.clone()));
                    self.intruder_ai_mode = IntruderAiMode::PayloadSuggestionPreview;
                    self.project_message = format!("AI payload generation failed: {error}");
                }
            },
            AiEvent::IntruderAttackPlanComplete { result } => match result {
                Ok(plan) => {
                    let positions = parse_positions(&plan.marked_request).len();
                    self.intruder_ai_plan = Some(IntruderAttackPlanState::Ready(plan));
                    self.intruder_ai_mode = IntruderAiMode::PlanPreview;
                    self.project_message = format!("AI attack plan ready with {positions} marked positions");
                }
                Err(error) => {
                    self.intruder_ai_plan = Some(IntruderAttackPlanState::Error(error.clone()));
                    self.intruder_ai_mode = IntruderAiMode::PlanPreview;
                    self.project_message = format!("AI attack planner failed: {error}");
                }
            },
            AiEvent::ScopeRulesComplete { result } => match result {
                Ok(proposal) => {
                    let count = proposal.rules.len();
                    self.scope_ai_proposal = Some(ScopeRuleProposalState::Ready(proposal));
                    self.scope_ai_mode = ScopeAiMode::ProposalPreview;
                    self.project_message = format!("AI scope proposal ready with {count} rules");
                }
                Err(error) => {
                    self.scope_ai_proposal = Some(ScopeRuleProposalState::Error(error.clone()));
                    self.scope_ai_mode = ScopeAiMode::ProposalPreview;
                    self.project_message = format!("AI scope assistant failed: {error}");
                }
            },
            AiEvent::DecoderChainComplete { result } => match result {
                Ok(suggestion) => {
                    let count = suggestion.suggested_chain.len();
                    self.decoder_ai_suggestion = Some(DecoderChainSuggestionState::Ready(suggestion));
                    self.decoder_ai_mode = DecoderAiMode::SuggestionPreview;
                    self.project_message = format!("AI decoder suggestion ready with {count} transforms");
                }
                Err(error) => {
                    self.decoder_ai_suggestion = Some(DecoderChainSuggestionState::Error(error.clone()));
                    self.decoder_ai_mode = DecoderAiMode::SuggestionPreview;
                    self.project_message = format!("AI decoder assistant failed: {error}");
                }
            },
            AiEvent::ComparerSummaryComplete { result } => match result {
                Ok(summary) => {
                    self.comparer_ai_summary = Some(ComparerSummaryState::Ready(summary));
                    self.comparer_detail_mode = ComparerDetailMode::AiSummary;
                    self.project_message = "AI comparer summary ready".to_string();
                }
                Err(error) => {
                    self.comparer_ai_summary = Some(ComparerSummaryState::Error(error.clone()));
                    self.comparer_detail_mode = ComparerDetailMode::AiSummary;
                    self.project_message = format!("AI comparer summary failed: {error}");
                }
            },
            AiEvent::PassiveRuleDraftComplete { result } => match result {
                Ok(draft) => {
                    let valid = draft.validation_errors.is_empty();
                    self.scanner_rule_draft = Some(PassiveRuleDraftState::Ready(draft));
                    self.scanner_ai_mode = ScannerAiMode::RulePreview;
                    self.project_message = if valid {
                        "AI passive scanner rule draft ready".to_string()
                    } else {
                        "AI passive scanner rule draft has validation errors".to_string()
                    };
                }
                Err(error) => {
                    self.scanner_rule_draft = Some(PassiveRuleDraftState::Error(error.clone()));
                    self.scanner_ai_mode = ScannerAiMode::RulePreview;
                    self.project_message = format!("AI passive rule generator failed: {error}");
                }
            },
            AiEvent::OllamaModelsComplete { result } => match result {
                Ok(models) => {
                    self.ollama_models = models;
                    self.refresh_ai_model_selection();
                    self.ollama_status = if self.ollama_models.is_empty() {
                        "Ollama reachable, but no downloaded models found".to_string()
                    } else {
                        format!("found {} local Ollama models", self.ollama_models.len())
                    };
                }
                Err(error) => {
                    self.ollama_status = format!("Ollama refresh failed: {error}");
                }
            },
        }
    }

    fn handle_key_event(&mut self, key: KeyEvent) {
        if self.search_mode {
            match key.code {
                KeyCode::Esc | KeyCode::Enter => self.search_mode = false,
                KeyCode::Backspace => {
                    self.search_query.pop();
                    self.ensure_selected_matches_filter();
                }
                KeyCode::Char(char) => {
                    self.search_query.push(char);
                    self.ensure_selected_matches_filter();
                }
                _ => {}
            }
            return;
        }

        if self.handle_local_clipboard_key(key) {
            return;
        }

        if self.current_tab == Tab::Settings && self.handle_settings_key(key) {
            return;
        }

        if self.current_tab == Tab::Proxy && self.handle_proxy_key(key) {
            return;
        }

        if self.current_tab == Tab::Ai && self.handle_ai_key(key) {
            return;
        }

        if self.current_tab == Tab::Plugins && self.handle_plugin_key(key) {
            return;
        }

        if self.current_tab == Tab::Active && self.handle_active_key(key) {
            return;
        }

        if self.current_tab == Tab::WebSockets && self.handle_websocket_key(key) {
            return;
        }

        if self.current_tab == Tab::Scanner && self.handle_scanner_key(key) {
            return;
        }

        if self.current_tab == Tab::Decoder && self.handle_decoder_key(key) {
            return;
        }

        if self.current_tab == Tab::Comparer && self.handle_comparer_key(key) {
            return;
        }

        if self.current_tab == Tab::Intruder && self.handle_intruder_key(key) {
            return;
        }

        if self.current_tab == Tab::Scope && self.handle_scope_key(key) {
            return;
        }

        if self.current_tab == Tab::Repeater && self.handle_repeater_key(key) {
            return;
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => self.quit(),
            (KeyCode::Esc, _) | (KeyCode::Char('q'), _) => self.quit(),
            (KeyCode::Char('t'), KeyModifiers::CONTROL) => self.new_repeater_from_selection(),
            (KeyCode::Char('d'), KeyModifiers::CONTROL) => self.send_selection_to_decoder(),
            (KeyCode::Char('m'), KeyModifiers::CONTROL) => self.mark_selection_for_comparer(),
            (KeyCode::Right | KeyCode::Tab, _) => self.next_tab(),
            (KeyCode::Left | KeyCode::BackTab, _) => self.previous_tab(),
            (KeyCode::Char('s'), KeyModifiers::CONTROL) if self.current_tab == Tab::Settings => self.save_project_as_env(),
            (KeyCode::Char('o'), KeyModifiers::CONTROL) if self.current_tab == Tab::Settings => self.open_project_from_env(),
            (KeyCode::Char('s'), _) if self.current_tab == Tab::Settings => self.start_proxy(),
            (KeyCode::Char('x'), _) if self.current_tab == Tab::Settings => self.stop_proxy(),
            (KeyCode::Down | KeyCode::Char('j'), _) if self.current_tab == Tab::Proxy => self.select_next_flow(),
            (KeyCode::Up | KeyCode::Char('k'), _) if self.current_tab == Tab::Proxy => self.select_previous_flow(),
            (KeyCode::Char('g'), _) if self.current_tab == Tab::Proxy => self.select_first_flow(),
            (KeyCode::Char('G'), _) if self.current_tab == Tab::Proxy => self.select_last_flow(),
            (KeyCode::Char('/'), _) if self.current_tab == Tab::Proxy => self.search_mode = true,
            _ => {}
        }
    }

    fn handle_local_clipboard_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::ALT) => {
                if let Some(text) = self.active_editable_text() {
                    self.local_clipboard = text;
                    self.project_message = format!("Copied {} bytes to internal clipboard", self.local_clipboard.len());
                } else {
                    self.project_message = "No editable box selected to copy".to_string();
                }
                true
            }
            (KeyCode::Char('v'), KeyModifiers::ALT) => {
                if self.local_clipboard.is_empty() {
                    self.project_message = "Internal clipboard is empty".to_string();
                } else {
                    self.handle_paste(self.local_clipboard.clone());
                    self.project_message = "Pasted from internal clipboard".to_string();
                }
                true
            }
            _ => false,
        }
    }

    fn active_editable_text(&self) -> Option<String> {
        match self.current_tab {
            Tab::Ai => Some(self.ai_panel.input.clone()),
            Tab::Repeater => {
                if self.renaming_repeater {
                    Some(self.rename_buffer.clone())
                } else if self.repeater_ai_mode == RepeaterAiMode::Prompt {
                    Some(self.repeater_ai_input.clone())
                } else {
                    self.active_repeater_tab().map(|tab| tab.request_text.clone())
                }
            }
            Tab::Intruder => {
                if matches!(self.intruder_ai_mode, IntruderAiMode::PayloadPrompt | IntruderAiMode::PlannerPrompt) {
                    Some(self.intruder_ai_input.clone())
                } else {
                    Some(self.intruder_request_text.clone())
                }
            }
            Tab::Decoder => Some(self.decoder_input.clone()),
            Tab::Comparer => Some(if self.comparer_focus_right { self.comparer_right.clone() } else { self.comparer_left.clone() }),
            Tab::Scope => {
                if self.scope_ai_mode == ScopeAiMode::Prompt {
                    Some(self.scope_ai_input.clone())
                } else if self.scope_input_mode.is_some() {
                    Some(self.scope_buffer.clone())
                } else {
                    None
                }
            }
            Tab::Scanner if self.scanner_ai_mode == ScannerAiMode::RulePrompt => Some(self.scanner_ai_input.clone()),
            _ => None,
        }
    }

    fn handle_settings_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('s'), KeyModifiers::CONTROL) => {
                self.save_project_as_env();
                true
            }
            (KeyCode::Char('o'), KeyModifiers::CONTROL) => {
                self.open_project_from_env();
                true
            }
            (KeyCode::Char('s'), _) | (KeyCode::F(5), _) => {
                self.start_proxy();
                true
            }
            (KeyCode::Char('x'), _) | (KeyCode::F(7), _) => {
                self.stop_proxy();
                true
            }
            (KeyCode::Char('o'), _) | (KeyCode::Char('r'), _) => {
                self.refresh_ollama_models();
                true
            }
            (KeyCode::Down | KeyCode::Char('j'), _) => {
                self.select_next_ai_model();
                true
            }
            (KeyCode::Up | KeyCode::Char('k'), _) => {
                self.select_previous_ai_model();
                true
            }
            (KeyCode::Enter, _) => {
                self.apply_selected_ai_model();
                true
            }
            _ => false,
        }
    }

    pub fn ai_model_options(&self) -> Vec<String> {
        let mut models = Vec::new();
        for model in self.ollama_models.iter().chain(self.ai_model_presets.iter()) {
            if !model.trim().is_empty() && !models.iter().any(|existing: &String| existing == model) {
                models.push(model.clone());
            }
        }
        if !models.iter().any(|model| model == &self.ai_panel.settings.model) {
            models.insert(0, self.ai_panel.settings.model.clone());
        }
        models
    }

    fn refresh_ai_model_selection(&mut self) {
        let models = self.ai_model_options();
        self.selected_ai_model = models
            .iter()
            .position(|model| model == &self.ai_panel.settings.model)
            .unwrap_or(0);
    }

    fn select_next_ai_model(&mut self) {
        let count = self.ai_model_options().len().max(1);
        self.selected_ai_model = (self.selected_ai_model + 1).min(count.saturating_sub(1));
    }

    fn select_previous_ai_model(&mut self) {
        self.selected_ai_model = self.selected_ai_model.saturating_sub(1);
    }

    fn apply_selected_ai_model(&mut self) {
        let models = self.ai_model_options();
        let Some(model) = models.get(self.selected_ai_model.min(models.len().saturating_sub(1))).cloned() else {
            self.project_message = "No AI model selected".to_string();
            return;
        };
        self.ai_panel.settings.model = model.clone();
        self.ai_panel.status = format!("model set to {model}");
        self.project_message = format!("AI model set to {model}");
    }

    fn refresh_ollama_models(&mut self) {
        self.ollama_status = format!("refreshing {}", self.ai_panel.settings.ollama_url);
        let settings = self.ai_panel.settings.clone();
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = fetch_ollama_models(settings).await;
            let _ = tx.send(AiEvent::OllamaModelsComplete { result }).await;
        });
    }

    fn handle_proxy_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('e'), KeyModifiers::NONE) => {
                self.explain_selected_flow();
                true
            }
            (KeyCode::Char('r'), KeyModifiers::NONE) => {
                self.proxy_detail_mode = match self.proxy_detail_mode {
                    ProxyDetailMode::AiBrief => ProxyDetailMode::RawEvidence,
                    ProxyDetailMode::RawEvidence => ProxyDetailMode::AiBrief,
                };
                self.reset_detail_scroll();
                true
            }
            _ => false,
        }
    }

    fn handle_repeater_key(&mut self, key: KeyEvent) -> bool {
        if self.renaming_repeater {
            match key.code {
                KeyCode::Enter => {
                    if !self.rename_buffer.trim().is_empty() {
                        if let Some(tab) = self.repeater_tabs.get_mut(self.active_repeater) {
                            tab.name = self.rename_buffer.trim().to_string();
                        }
                        self.persist_repeater_tabs();
                    }
                    self.rename_buffer.clear();
                    self.renaming_repeater = false;
                }
                KeyCode::Esc => {
                    self.rename_buffer.clear();
                    self.renaming_repeater = false;
                }
                KeyCode::Backspace => {
                    self.rename_buffer.pop();
                }
                KeyCode::Char(char) => self.rename_buffer.push(char),
                _ => {}
            }
            return true;
        }

        if self.repeater_ai_mode == RepeaterAiMode::Prompt {
            return self.handle_repeater_ai_prompt_key(key);
        }

        if self.repeater_ai_mode == RepeaterAiMode::DraftPreview {
            return self.handle_repeater_ai_draft_key(key);
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.open_repeater_ai_builder();
                true
            }
            (KeyCode::Enter, KeyModifiers::CONTROL) => {
                self.send_active_repeater();
                true
            }
            (KeyCode::Char('t'), KeyModifiers::CONTROL) => {
                self.new_repeater_from_selection();
                true
            }
            (KeyCode::Char('w'), KeyModifiers::CONTROL) => {
                self.close_active_repeater();
                true
            }
            (KeyCode::F(2), _) => {
                self.renaming_repeater = true;
                self.rename_buffer = self
                    .repeater_tabs
                    .get(self.active_repeater)
                    .map(|tab| tab.name.clone())
                    .unwrap_or_default();
                true
            }
            (KeyCode::Right, KeyModifiers::CONTROL) => {
                self.next_repeater_tab();
                true
            }
            (KeyCode::Left, KeyModifiers::CONTROL) => {
                self.previous_repeater_tab();
                true
            }
            (KeyCode::PageDown, _) => {
                self.repeater_response_scroll = self.repeater_response_scroll.saturating_add(10);
                true
            }
            (KeyCode::PageUp, _) => {
                self.repeater_response_scroll = self.repeater_response_scroll.saturating_sub(10);
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                self.insert_repeater_char(char);
                true
            }
            (KeyCode::Enter, _) => {
                self.insert_repeater_char('\n');
                true
            }
            (KeyCode::Backspace, _) => {
                self.backspace_repeater_char();
                true
            }
            (KeyCode::Delete, _) => {
                self.delete_repeater_char();
                true
            }
            // Let plain Left/Right bubble to the global tab navigation handler.
            // Repeater sub-tabs still use Ctrl+Left/Ctrl+Right above.
            _ => false,
        }
    }

    fn handle_repeater_ai_prompt_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Esc, _) => {
                self.repeater_ai_input.clear();
                self.repeater_ai_mode = RepeaterAiMode::Editing;
                true
            }
            (KeyCode::Enter, _) => {
                self.submit_repeater_ai_prompt();
                true
            }
            (KeyCode::Backspace, _) => {
                self.repeater_ai_input.pop();
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                self.repeater_ai_input.push(char);
                true
            }
            _ => true,
        }
    }

    fn handle_repeater_ai_draft_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.open_repeater_ai_builder();
                true
            }
            (KeyCode::Char('a'), KeyModifiers::NONE) => {
                self.apply_repeater_ai_draft();
                true
            }
            (KeyCode::Char('n'), KeyModifiers::NONE) => {
                self.new_repeater_tab_from_ai_draft();
                true
            }
            (KeyCode::Char('d'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
                self.discard_repeater_ai_draft();
                true
            }
            (KeyCode::Enter, KeyModifiers::CONTROL) => {
                self.project_message = "Apply the AI draft before sending it".to_string();
                true
            }
            (KeyCode::Right | KeyCode::Tab, _) | (KeyCode::Left | KeyCode::BackTab, _) => false,
            _ => true,
        }
    }

    fn handle_ai_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Enter, KeyModifiers::CONTROL) => {
                self.submit_ai_prompt();
                true
            }
            (KeyCode::Char('a'), KeyModifiers::CONTROL) => {
                self.attach_selected_flow_to_ai();
                true
            }
            (KeyCode::Char(char @ '1'..='6'), KeyModifiers::ALT) => {
                let index = (char as u8 - b'1') as usize;
                if let Some(prompt) = QUICK_PROMPTS.get(index) {
                    self.ai_panel.input = (*prompt).to_string();
                    self.ai_panel.selected_quick_prompt = index;
                }
                true
            }
            (KeyCode::Backspace, _) => {
                self.ai_panel.input.pop();
                true
            }
            (KeyCode::Enter, _) => {
                self.ai_panel.input.push('\n');
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                self.ai_panel.input.push(char);
                true
            }
            _ => false,
        }
    }

    fn explain_selected_flow(&mut self) {
        let Some(flow) = self
            .selected_flow
            .and_then(|index| self.flow_store.snapshot().get(index).cloned())
        else {
            self.project_message = "Select a proxy flow before asking for an AI Flow Brief".to_string();
            return;
        };

        if matches!(
            self.flow_ai_explanations.get(&flow.id),
            Some(FlowExplanationState::Loading)
        ) {
            return;
        }

        let flow_id = flow.id;
        self.proxy_detail_mode = ProxyDetailMode::AiBrief;
        self.reset_detail_scroll();
        self.project_message = format!("Asking {} to explain flow #{flow_id}", self.ai_panel.settings.model);
        self.flow_ai_explanations
            .insert(flow_id, FlowExplanationState::Loading);

        let settings = self.ai_panel.settings.clone();
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = explain_flow_with_ollama(settings, flow).await;
            let _ = tx
                .send(AiEvent::FlowExplanationComplete { flow_id, result })
                .await;
        });
    }

    fn attach_selected_flow_to_ai(&mut self) {
        let Some(flow) = self
            .selected_flow
            .and_then(|index| self.flow_store.snapshot().get(index).cloned())
        else {
            self.ai_panel.status = "no selected flow to attach".to_string();
            return;
        };
        self.ai_panel.attached_context = Some(ai_context_from_flow(
            &flow,
            self.ai_panel.settings.redaction_enabled,
            self.ai_panel.settings.max_context_chars,
        ));
        self.ai_panel.status = format!("attached flow #{}", flow.id);
        self.current_tab = Tab::Ai;
    }

    fn submit_ai_prompt(&mut self) {
        if self.ai_panel.is_waiting {
            return;
        }
        let prompt = self.ai_panel.input.trim().to_string();
        if prompt.is_empty() {
            return;
        }
        self.ai_panel.input.clear();
        self.ai_panel.messages.push(AiMessage::user(prompt.clone()));
        self.ai_panel.is_waiting = true;
        self.ai_panel.status = format!("asking {}", self.ai_panel.settings.model);

        let settings = self.ai_panel.settings.clone();
        let context = self.ai_panel.attached_context.clone();
        let history = self.ai_panel.messages.clone();
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = ask_ollama(settings, context, history, prompt).await;
            let _ = tx.send(AiEvent::Complete(result)).await;
        });
    }

    fn handle_plugin_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('r'), _) => {
                self.plugin_manager.reload();
                self.selected_plugin = 0;
                true
            }
            (KeyCode::Char('e'), _) | (KeyCode::Char(' '), _) => {
                self.plugin_manager.toggle(self.selected_plugin);
                true
            }
            (KeyCode::Down | KeyCode::Char('j'), _) => {
                self.selected_plugin = (self.selected_plugin + 1)
                    .min(self.plugin_manager.plugins.len().saturating_sub(1));
                true
            }
            (KeyCode::Up | KeyCode::Char('k'), _) => {
                self.selected_plugin = self.selected_plugin.saturating_sub(1);
                true
            }
            _ => false,
        }
    }

    fn handle_active_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('e'), _) => {
                self.active_scanning_enabled = !self.active_scanning_enabled;
                true
            }
            (KeyCode::Char('a'), _) => {
                self.enqueue_selected_flow_for_active_scan();
                true
            }
            (KeyCode::F(5), _) => {
                self.start_active_scan();
                true
            }
            (KeyCode::F(7), _) => {
                if let Some(task) = self.active_scan_task.take() {
                    task.abort();
                }
                if let Some(target) = self.active_scan_targets.get_mut(self.selected_active_target) {
                    target.running = false;
                }
                true
            }
            (KeyCode::Down | KeyCode::Char('j'), _) => {
                self.selected_active_target = (self.selected_active_target + 1)
                    .min(self.active_scan_targets.len().saturating_sub(1));
                true
            }
            (KeyCode::Up | KeyCode::Char('k'), _) => {
                self.selected_active_target = self.selected_active_target.saturating_sub(1);
                true
            }
            _ => false,
        }
    }

    fn handle_websocket_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Down | KeyCode::Char('j'), _) => {
                self.websocket_selected_frame = (self.websocket_selected_frame + 1)
                    .min(self.flow_store.websocket_snapshot().len().saturating_sub(1));
                true
            }
            (KeyCode::Up | KeyCode::Char('k'), _) => {
                self.websocket_selected_frame = self.websocket_selected_frame.saturating_sub(1);
                true
            }
            _ => false,
        }
    }

    fn handle_scanner_key(&mut self, key: KeyEvent) -> bool {
        if self.scanner_ai_mode == ScannerAiMode::RulePrompt {
            return self.handle_scanner_rule_prompt_key(key);
        }

        if self.scanner_ai_mode == ScannerAiMode::RulePreview {
            return self.handle_scanner_rule_preview_key(key);
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.open_passive_rule_generator();
                true
            }
            (KeyCode::Down | KeyCode::Char('j'), _) => {
                self.selected_finding = (self.selected_finding + 1)
                    .min(self.filtered_findings().len().saturating_sub(1));
                true
            }
            (KeyCode::Up | KeyCode::Char('k'), _) => {
                self.selected_finding = self.selected_finding.saturating_sub(1);
                true
            }
            (KeyCode::PageDown | KeyCode::Char(']'), _) => {
                self.selected_scanner_check = (self.selected_scanner_check + 1)
                    .min(self.passive_scanner.definitions.len().saturating_sub(1));
                true
            }
            (KeyCode::PageUp | KeyCode::Char('['), _) => {
                self.selected_scanner_check = self.selected_scanner_check.saturating_sub(1);
                true
            }
            (KeyCode::Enter, _) => {
                let findings = self.filtered_findings();
                if let Some(finding) = findings.get(self.selected_finding.min(findings.len().saturating_sub(1))) {
                    if let Some(index) = self
                        .flow_store
                        .snapshot()
                        .iter()
                        .position(|flow| flow.id == finding.flow_id)
                    {
                        self.selected_flow = Some(index);
                        self.current_tab = Tab::Proxy;
                    }
                }
                true
            }
            (KeyCode::Char('t'), KeyModifiers::NONE) => {
                self.triage_selected_finding();
                true
            }
            (KeyCode::Char('v'), KeyModifiers::NONE) => {
                self.scanner_detail_mode = match self.scanner_detail_mode {
                    ScannerDetailMode::AiTriage => ScannerDetailMode::Evidence,
                    ScannerDetailMode::Evidence => ScannerDetailMode::AiTriage,
                };
                self.reset_detail_scroll();
                true
            }
            (KeyCode::Char('0'), KeyModifiers::NONE) => {
                self.scanner_severity_filter = None;
                self.scanner_confidence_filter = None;
                true
            }
            (KeyCode::Char('i'), KeyModifiers::NONE) => {
                self.scanner_severity_filter = Some(Severity::Info);
                true
            }
            (KeyCode::Char('l'), KeyModifiers::NONE) => {
                self.scanner_severity_filter = Some(Severity::Low);
                true
            }
            (KeyCode::Char('m'), KeyModifiers::NONE) => {
                self.scanner_severity_filter = Some(Severity::Medium);
                true
            }
            (KeyCode::Char('h'), KeyModifiers::NONE) => {
                self.scanner_severity_filter = Some(Severity::High);
                true
            }
            (KeyCode::Char('c'), KeyModifiers::NONE) => {
                self.scanner_severity_filter = Some(Severity::Critical);
                true
            }
            (KeyCode::Char('1'), KeyModifiers::NONE) => {
                self.scanner_confidence_filter = Some(Confidence::Tentative);
                true
            }
            (KeyCode::Char('2'), KeyModifiers::NONE) => {
                self.scanner_confidence_filter = Some(Confidence::Firm);
                true
            }
            (KeyCode::Char('3'), KeyModifiers::NONE) => {
                self.scanner_confidence_filter = Some(Confidence::Certain);
                true
            }
            (KeyCode::Char('e'), KeyModifiers::NONE) => {
                self.toggle_scanner_check();
                true
            }
            (KeyCode::Char('r'), KeyModifiers::NONE) => {
                self.reload_scanner_definitions();
                true
            }
            (KeyCode::Char('x'), KeyModifiers::NONE) => {
                self.export_findings_reports();
                true
            }
            _ => false,
        }
    }

    fn handle_scanner_rule_prompt_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Esc, _) => {
                self.scanner_ai_input.clear();
                self.scanner_ai_mode = ScannerAiMode::None;
                true
            }
            (KeyCode::Enter, _) => {
                self.submit_passive_rule_prompt();
                true
            }
            (KeyCode::Backspace, _) => {
                self.scanner_ai_input.pop();
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                self.scanner_ai_input.push(char);
                true
            }
            _ => true,
        }
    }

    fn handle_scanner_rule_preview_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.open_passive_rule_generator();
                true
            }
            (KeyCode::Char('a'), KeyModifiers::NONE) => {
                self.save_passive_rule_draft();
                true
            }
            (KeyCode::Char('d'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
                self.discard_passive_rule_draft();
                true
            }
            _ => true,
        }
    }

    fn open_passive_rule_generator(&mut self) {
        self.scanner_ai_input.clear();
        self.scanner_rule_draft = None;
        self.scanner_ai_mode = ScannerAiMode::RulePrompt;
        self.project_message = "AI Passive Rule Generator prompt opened".to_string();
    }

    fn submit_passive_rule_prompt(&mut self) {
        let instruction = self.scanner_ai_input.trim().to_string();
        if instruction.is_empty() {
            return;
        }
        let existing_ids = self
            .passive_scanner
            .definitions
            .iter()
            .map(|definition| definition.id.clone())
            .collect::<Vec<_>>();
        self.scanner_ai_input.clear();
        self.scanner_ai_mode = ScannerAiMode::RulePreview;
        self.scanner_rule_draft = Some(PassiveRuleDraftState::Loading);
        self.project_message = format!("Asking {} to generate passive scanner rule", self.ai_panel.settings.model);

        let settings = self.ai_panel.settings.clone();
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = generate_passive_rule_with_ollama(settings, instruction, existing_ids).await;
            let _ = tx.send(AiEvent::PassiveRuleDraftComplete { result }).await;
        });
    }

    fn save_passive_rule_draft(&mut self) {
        let Some(PassiveRuleDraftState::Ready(draft)) = self.scanner_rule_draft.clone() else {
            self.project_message = "No ready passive rule draft to save".to_string();
            return;
        };
        if !draft.validation_errors.is_empty() {
            self.project_message = format!("Cannot save invalid rule: {}", draft.validation_errors.join("; "));
            return;
        }
        let rule_id = sanitize_passive_rule_id(&draft.rule_id);
        if rule_id.is_empty() {
            self.project_message = "Cannot save rule with empty/unsafe id".to_string();
            return;
        }
        if self.passive_scanner.definitions.iter().any(|definition| definition.id == rule_id) {
            self.project_message = format!("Scanner rule id already exists: {rule_id}");
            return;
        }
        let dir = std::env::var_os("PROXIMA_PASSIVE_DEFS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("resources/passive"));
        if let Err(error) = std::fs::create_dir_all(&dir) {
            self.project_message = format!("Failed to create passive rule directory: {error}");
            return;
        }
        let path = dir.join(format!("{rule_id}.yaml"));
        if path.exists() {
            self.project_message = format!("Passive rule file already exists: {}", path.display());
            return;
        }
        if let Err(error) = std::fs::write(&path, draft.yaml.trim_end().to_string() + "\n") {
            self.project_message = format!("Failed to save passive rule: {error}");
            return;
        }
        self.passive_scanner = PassiveScanner::load_default();
        self.scanner_rule_draft = None;
        self.scanner_ai_mode = ScannerAiMode::None;
        self.selected_scanner_check = self
            .passive_scanner
            .definitions
            .iter()
            .position(|definition| definition.id == rule_id)
            .unwrap_or(0);
        self.project_message = format!("Saved {} and reloaded scanner definitions", path.display());
    }

    fn discard_passive_rule_draft(&mut self) {
        self.scanner_rule_draft = None;
        self.scanner_ai_input.clear();
        self.scanner_ai_mode = ScannerAiMode::None;
        self.project_message = "Discarded passive rule draft".to_string();
    }

    pub fn filtered_findings(&self) -> Vec<Finding> {
        let mut findings = self
            .findings
            .iter()
            .filter(|finding| {
                self.scanner_severity_filter
                    .map(|severity| finding.severity == severity)
                    .unwrap_or(true)
                    && self
                        .scanner_confidence_filter
                        .map(|confidence| finding.confidence == confidence)
                        .unwrap_or(true)
            })
            .cloned()
            .collect::<Vec<_>>();
        findings.sort_by(|a, b| {
            self.finding_priority_rank(a)
                .cmp(&self.finding_priority_rank(b))
                .then_with(|| b.severity.cmp(&a.severity))
                .then_with(|| b.confidence.cmp(&a.confidence))
                .then_with(|| b.id.cmp(&a.id))
        });
        findings
    }

    fn finding_priority_rank(&self, finding: &Finding) -> u8 {
        let Some(FindingTriageState::Ready(triage)) = self.finding_triage.get(&finding.id) else {
            return 90;
        };
        priority_rank(&triage.priority).min(priority_rank(&triage.priority_label))
    }

    fn triage_selected_finding(&mut self) {
        let findings = self.filtered_findings();
        let Some(finding) = findings
            .get(self.selected_finding.min(findings.len().saturating_sub(1)))
            .cloned()
        else {
            self.project_message = "No scanner finding selected for AI triage".to_string();
            return;
        };

        if matches!(
            self.finding_triage.get(&finding.id),
            Some(FindingTriageState::Loading)
        ) {
            return;
        }

        let finding_id = finding.id;
        let flow = self
            .flow_store
            .snapshot()
            .into_iter()
            .find(|flow| flow.id == finding.flow_id);
        let definition_context = self
            .passive_scanner
            .definitions
            .iter()
            .find(|definition| definition.id == finding.issue_id)
            .and_then(|definition| serde_json::to_string(definition).ok())
            .unwrap_or_else(|| "scanner definition unavailable".to_string());

        self.scanner_detail_mode = ScannerDetailMode::AiTriage;
        self.reset_detail_scroll();
        self.project_message = format!("Asking {} to triage finding #{finding_id}", self.ai_panel.settings.model);
        self.finding_triage
            .insert(finding_id, FindingTriageState::Loading);

        let settings = self.ai_panel.settings.clone();
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = triage_finding_with_ollama(settings, finding, flow, definition_context).await;
            let _ = tx
                .send(AiEvent::FindingTriageComplete { finding_id, result })
                .await;
        });
    }

    fn handle_decoder_key(&mut self, key: KeyEvent) -> bool {
        if self.decoder_ai_mode == DecoderAiMode::SuggestionPreview {
            return self.handle_decoder_ai_suggestion_key(key);
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.suggest_decoder_chain();
                true
            }
            (KeyCode::Char(char @ '1'..='9'), _) => {
                let index = (char as u8 - b'1') as usize;
                self.decoder_chain.push(DecoderTransform::from_index(index));
                self.selected_decoder_transform = self.decoder_chain.len().saturating_sub(1);
                true
            }
            (KeyCode::Char('0'), KeyModifiers::NONE) => {
                self.decoder_chain.push(DecoderTransform::JwtDecode);
                self.selected_decoder_transform = self.decoder_chain.len().saturating_sub(1);
                true
            }
            (KeyCode::Char('p'), _) => {
                self.decoder_chain.push(DecoderTransform::JsonPrettyPrint);
                self.selected_decoder_transform = self.decoder_chain.len().saturating_sub(1);
                true
            }
            (KeyCode::Up, KeyModifiers::ALT) => {
                if self.selected_decoder_transform > 0 {
                    self.decoder_chain.swap(self.selected_decoder_transform, self.selected_decoder_transform - 1);
                    self.selected_decoder_transform -= 1;
                }
                true
            }
            (KeyCode::Down, KeyModifiers::ALT) => {
                if self.selected_decoder_transform + 1 < self.decoder_chain.len() {
                    self.decoder_chain.swap(self.selected_decoder_transform, self.selected_decoder_transform + 1);
                    self.selected_decoder_transform += 1;
                }
                true
            }
            (KeyCode::Char('j'), _) | (KeyCode::Down, _) => {
                self.selected_decoder_transform = (self.selected_decoder_transform + 1)
                    .min(self.decoder_chain.len().saturating_sub(1));
                true
            }
            (KeyCode::Char('k'), _) | (KeyCode::Up, _) => {
                self.selected_decoder_transform = self.selected_decoder_transform.saturating_sub(1);
                true
            }
            (KeyCode::Delete, _) => {
                if !self.decoder_chain.is_empty() {
                    self.decoder_chain.remove(self.selected_decoder_transform.min(self.decoder_chain.len() - 1));
                    self.selected_decoder_transform = self.selected_decoder_transform.min(self.decoder_chain.len().saturating_sub(1));
                }
                true
            }
            (KeyCode::Backspace, _) => {
                self.decoder_input.pop();
                true
            }
            (KeyCode::Enter, _) => {
                self.decoder_input.push('\n');
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                self.decoder_input.push(char);
                true
            }
            _ => false,
        }
    }

    fn handle_decoder_ai_suggestion_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.suggest_decoder_chain();
                true
            }
            (KeyCode::Char('a'), KeyModifiers::NONE) => {
                self.apply_decoder_ai_chain(true);
                true
            }
            (KeyCode::Char('n'), KeyModifiers::NONE) => {
                self.apply_decoder_ai_chain(false);
                true
            }
            (KeyCode::Char('d'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
                self.discard_decoder_ai_suggestion();
                true
            }
            (KeyCode::Right | KeyCode::Tab, _) | (KeyCode::Left | KeyCode::BackTab, _) => false,
            _ => true,
        }
    }

    fn suggest_decoder_chain(&mut self) {
        if self.decoder_input.trim().is_empty() {
            self.project_message = "Decoder input is empty".to_string();
            return;
        }
        self.decoder_ai_mode = DecoderAiMode::SuggestionPreview;
        self.decoder_ai_suggestion = Some(DecoderChainSuggestionState::Loading);
        self.project_message = format!("Asking {} to suggest a decoder chain", self.ai_panel.settings.model);

        let settings = self.ai_panel.settings.clone();
        let input = self.decoder_input.clone();
        let current_chain = self
            .decoder_chain
            .iter()
            .map(|transform| transform.label().to_string())
            .collect::<Vec<_>>()
            .join(" -> ");
        let heuristics = decoder_heuristic_summary(&self.decoder_input);
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = suggest_decoder_chain_with_ollama(settings, input, current_chain, heuristics).await;
            let _ = tx.send(AiEvent::DecoderChainComplete { result }).await;
        });
    }

    fn apply_decoder_ai_chain(&mut self, replace: bool) {
        let Some(DecoderChainSuggestionState::Ready(suggestion)) = self.decoder_ai_suggestion.clone() else {
            self.project_message = "No ready AI decoder chain to apply".to_string();
            return;
        };
        let transforms = suggestion
            .suggested_chain
            .iter()
            .filter_map(|item| parse_decoder_transform_label(&item.transform))
            .collect::<Vec<_>>();
        if transforms.is_empty() {
            self.project_message = "AI suggestion has no valid decoder transforms".to_string();
            return;
        }
        if replace {
            self.decoder_chain = transforms;
        } else {
            self.decoder_chain.extend(transforms);
        }
        self.selected_decoder_transform = self.decoder_chain.len().saturating_sub(1);
        self.decoder_ai_suggestion = None;
        self.decoder_ai_mode = DecoderAiMode::Editing;
        self.project_message = if replace {
            "Applied AI decoder chain".to_string()
        } else {
            "Appended AI decoder chain".to_string()
        };
    }

    fn discard_decoder_ai_suggestion(&mut self) {
        self.decoder_ai_suggestion = None;
        self.decoder_ai_mode = DecoderAiMode::Editing;
        self.project_message = "Discarded AI decoder suggestion".to_string();
    }

    fn handle_comparer_key(&mut self, key: KeyEvent) -> bool {
        if self.comparer_detail_mode == ComparerDetailMode::AiSummary {
            match (key.code, key.modifiers) {
                (KeyCode::Char('c'), KeyModifiers::CONTROL) => return false,
                (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                    self.summarize_comparer_diff();
                    return true;
                }
                (KeyCode::Char('d'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
                    self.discard_comparer_ai_summary();
                    return true;
                }
                _ => {}
            }
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.summarize_comparer_diff();
                true
            }
            (KeyCode::F(3), _) | (KeyCode::Char('w'), _) => {
                self.comparer_mode = self.comparer_mode.next();
                true
            }
            (KeyCode::Tab, _) => {
                self.comparer_focus_right = !self.comparer_focus_right;
                true
            }
            (KeyCode::Backspace, _) => {
                if self.comparer_focus_right {
                    self.comparer_right.pop();
                } else {
                    self.comparer_left.pop();
                }
                self.comparer_ai_summary = None;
                self.comparer_detail_mode = ComparerDetailMode::RawDiff;
                true
            }
            (KeyCode::Enter, _) => {
                if self.comparer_focus_right {
                    self.comparer_right.push('\n');
                } else {
                    self.comparer_left.push('\n');
                }
                self.comparer_ai_summary = None;
                self.comparer_detail_mode = ComparerDetailMode::RawDiff;
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                if self.comparer_focus_right {
                    self.comparer_right.push(char);
                } else {
                    self.comparer_left.push(char);
                }
                self.comparer_ai_summary = None;
                self.comparer_detail_mode = ComparerDetailMode::RawDiff;
                true
            }
            _ => false,
        }
    }

    fn summarize_comparer_diff(&mut self) {
        if self.comparer_left.trim().is_empty() || self.comparer_right.trim().is_empty() {
            self.project_message = "Comparer needs both left and right inputs for AI summary".to_string();
            return;
        }
        self.comparer_detail_mode = ComparerDetailMode::AiSummary;
        self.comparer_ai_summary = Some(ComparerSummaryState::Loading);
        self.project_message = format!("Asking {} to summarize comparer diff", self.ai_panel.settings.model);

        let settings = self.ai_panel.settings.clone();
        let left = self.comparer_left.clone();
        let right = self.comparer_right.clone();
        let mode = self.comparer_mode;
        let heuristics = comparer_heuristic_summary(&left, &right);
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = summarize_comparer_with_ollama(settings, left, right, mode, heuristics).await;
            let _ = tx.send(AiEvent::ComparerSummaryComplete { result }).await;
        });
    }

    fn discard_comparer_ai_summary(&mut self) {
        self.comparer_ai_summary = None;
        self.comparer_detail_mode = ComparerDetailMode::RawDiff;
        self.project_message = "Discarded AI comparer summary".to_string();
    }

    fn handle_intruder_key(&mut self, key: KeyEvent) -> bool {
        if matches!(self.intruder_ai_mode, IntruderAiMode::PayloadPrompt | IntruderAiMode::PlannerPrompt) {
            return self.handle_intruder_ai_prompt_key(key);
        }

        if self.intruder_ai_mode == IntruderAiMode::PayloadSuggestionPreview {
            return self.handle_intruder_ai_suggestion_key(key);
        }

        if self.intruder_ai_mode == IntruderAiMode::PlanPreview {
            return self.handle_intruder_ai_plan_key(key);
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.open_intruder_ai_payload_generator();
                true
            }
            (KeyCode::Char('p'), KeyModifiers::CONTROL) => {
                self.open_intruder_ai_attack_planner();
                true
            }
            (KeyCode::F(5), _) => {
                self.start_intruder_attack();
                true
            }
            (KeyCode::F(6), _) => {
                if self.intruder_running {
                    if let Some(task) = self.intruder_task.take() {
                        task.abort();
                    }
                    self.intruder_running = false;
                    self.intruder_paused = true;
                }
                true
            }
            (KeyCode::F(7), _) => {
                self.stop_intruder_attack();
                true
            }
            (KeyCode::F(8), _) => {
                self.intruder_attack_type = self.intruder_attack_type.next();
                true
            }
            (KeyCode::F(9), _) => {
                self.export_intruder_csv();
                true
            }
            (KeyCode::Down | KeyCode::Char('j'), _) => {
                self.intruder_selected_result = (self.intruder_selected_result + 1)
                    .min(self.filtered_intruder_results().len().saturating_sub(1));
                true
            }
            (KeyCode::Up | KeyCode::Char('k'), _) => {
                self.intruder_selected_result = self.intruder_selected_result.saturating_sub(1);
                true
            }
            (KeyCode::Char('s'), _) => {
                self.intruder_sort_desc = !self.intruder_sort_desc;
                self.sort_intruder_results();
                true
            }
            (KeyCode::Char('0'), KeyModifiers::NONE) => {
                self.intruder_filter_status = None;
                true
            }
            (KeyCode::Char('2'), KeyModifiers::NONE) => {
                self.intruder_filter_status = Some(200);
                true
            }
            (KeyCode::Char('4'), _) => {
                self.intruder_filter_status = Some(400);
                true
            }
            (KeyCode::Char('5'), _) => {
                self.intruder_filter_status = Some(500);
                true
            }
            (KeyCode::Enter, _) => {
                self.intruder_request_text.push('\n');
                self.intruder_plan_payload_sets.clear();
                true
            }
            (KeyCode::Backspace, _) => {
                self.intruder_request_text.pop();
                self.intruder_plan_payload_sets.clear();
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                self.intruder_request_text.push(char);
                self.intruder_plan_payload_sets.clear();
                true
            }
            _ => false,
        }
    }

    fn handle_intruder_ai_prompt_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Esc, _) => {
                self.intruder_ai_input.clear();
                self.intruder_ai_mode = IntruderAiMode::Editing;
                true
            }
            (KeyCode::Enter, _) => {
                match self.intruder_ai_mode {
                    IntruderAiMode::PayloadPrompt => self.submit_intruder_ai_payload_prompt(),
                    IntruderAiMode::PlannerPrompt => self.submit_intruder_ai_plan_prompt(),
                    _ => {}
                }
                true
            }
            (KeyCode::Backspace, _) => {
                self.intruder_ai_input.pop();
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                self.intruder_ai_input.push(char);
                true
            }
            _ => true,
        }
    }

    fn handle_intruder_ai_suggestion_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.open_intruder_ai_payload_generator();
                true
            }
            (KeyCode::Char('p'), KeyModifiers::CONTROL) => {
                self.open_intruder_ai_attack_planner();
                true
            }
            (KeyCode::Char('a'), KeyModifiers::NONE) => {
                self.apply_intruder_ai_payloads(false);
                true
            }
            (KeyCode::Char('n'), KeyModifiers::NONE) => {
                self.apply_intruder_ai_payloads(true);
                true
            }
            (KeyCode::Char('d'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
                self.discard_intruder_ai_payloads();
                true
            }
            (KeyCode::F(5), _) => {
                self.project_message = "Apply or append the AI payload set before starting Intruder".to_string();
                true
            }
            _ => true,
        }
    }

    fn handle_intruder_ai_plan_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Char('p'), KeyModifiers::CONTROL) => {
                self.open_intruder_ai_attack_planner();
                true
            }
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.open_intruder_ai_payload_generator();
                true
            }
            (KeyCode::Char('a'), KeyModifiers::NONE) => {
                self.apply_intruder_ai_attack_plan();
                true
            }
            (KeyCode::Char('d'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
                self.discard_intruder_ai_attack_plan();
                true
            }
            (KeyCode::F(5), _) => {
                self.project_message = "Apply the AI attack plan before starting Intruder".to_string();
                true
            }
            _ => true,
        }
    }

    fn open_intruder_ai_payload_generator(&mut self) {
        if self.intruder_running {
            self.project_message = "Stop or pause Intruder before generating a new AI payload set".to_string();
            return;
        }
        self.intruder_ai_input.clear();
        self.intruder_ai_suggestion = None;
        self.intruder_ai_plan = None;
        self.intruder_ai_mode = IntruderAiMode::PayloadPrompt;
        self.project_message = "AI Payload Generator prompt opened".to_string();
    }

    fn open_intruder_ai_attack_planner(&mut self) {
        if self.intruder_running {
            self.project_message = "Stop or pause Intruder before generating an AI attack plan".to_string();
            return;
        }
        self.intruder_ai_input = "Setup safe fuzzing for this request".to_string();
        self.intruder_ai_suggestion = None;
        self.intruder_ai_plan = None;
        self.intruder_ai_mode = IntruderAiMode::PlannerPrompt;
        self.project_message = "AI Attack Planner prompt opened".to_string();
    }

    fn submit_intruder_ai_payload_prompt(&mut self) {
        let instruction = self.intruder_ai_input.trim().to_string();
        if instruction.is_empty() {
            return;
        }
        let request = self.intruder_request_text.clone();
        let attack_type = self.intruder_attack_type;
        let existing_payload_count = self
            .intruder_payloads_text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        self.intruder_ai_input.clear();
        self.intruder_ai_mode = IntruderAiMode::PayloadSuggestionPreview;
        self.intruder_ai_suggestion = Some(IntruderPayloadSuggestionState::Loading);
        self.project_message = format!("Asking {} to generate safe Intruder payloads", self.ai_panel.settings.model);

        let settings = self.ai_panel.settings.clone();
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = generate_intruder_payloads_with_ollama(
                settings,
                instruction,
                request,
                attack_type,
                existing_payload_count,
            )
            .await;
            let _ = tx.send(AiEvent::IntruderPayloadsComplete { result }).await;
        });
    }

    fn submit_intruder_ai_plan_prompt(&mut self) {
        let instruction = if self.intruder_ai_input.trim().is_empty() {
            "Setup safe fuzzing for this request".to_string()
        } else {
            self.intruder_ai_input.trim().to_string()
        };
        let request = self.intruder_request_text.clone();
        let attack_type = self.intruder_attack_type;
        let existing_payload_count = self
            .intruder_payloads_text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        self.intruder_ai_input.clear();
        self.intruder_ai_mode = IntruderAiMode::PlanPreview;
        self.intruder_ai_plan = Some(IntruderAttackPlanState::Loading);
        self.project_message = format!("Asking {} to plan a safe Intruder setup", self.ai_panel.settings.model);

        let settings = self.ai_panel.settings.clone();
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = plan_intruder_attack_with_ollama(
                settings,
                instruction,
                request,
                attack_type,
                existing_payload_count,
            )
            .await;
            let _ = tx.send(AiEvent::IntruderAttackPlanComplete { result }).await;
        });
    }

    fn apply_intruder_ai_payloads(&mut self, append: bool) {
        let Some(IntruderPayloadSuggestionState::Ready(suggestion)) = self.intruder_ai_suggestion.clone() else {
            self.project_message = "No ready AI payload set to apply".to_string();
            return;
        };
        let payloads = dedupe_payloads(suggestion.payloads);
        if payloads.is_empty() {
            self.project_message = "AI payload set is empty after safety filtering".to_string();
            return;
        }
        if append {
            let mut combined = self
                .intruder_payloads_text
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            combined.extend(payloads);
            self.intruder_payloads_text = dedupe_payloads(combined).join("\n");
            self.project_message = "Appended AI payloads to Intruder list. Press F5 to run manually.".to_string();
        } else {
            self.intruder_payloads_text = payloads.join("\n");
            self.project_message = "Replaced Intruder payload list with AI payloads. Press F5 to run manually.".to_string();
        }
        self.intruder_plan_payload_sets.clear();
        self.intruder_ai_suggestion = None;
        self.intruder_ai_mode = IntruderAiMode::Editing;
    }

    fn apply_intruder_ai_attack_plan(&mut self) {
        let Some(IntruderAttackPlanState::Ready(plan)) = self.intruder_ai_plan.clone() else {
            self.project_message = "No ready AI attack plan to apply".to_string();
            return;
        };
        if parse_positions(&plan.marked_request).is_empty() {
            self.project_message = "AI attack plan has no §position§ markers".to_string();
            return;
        }
        let attack_type = parse_attack_type_label(&plan.recommended_attack_type)
            .unwrap_or(self.intruder_attack_type);
        let payload_sets = normalize_plan_payload_sets(plan.payload_sets.clone());
        let combined_payloads = dedupe_payloads(
            payload_sets
                .iter()
                .flat_map(|set| set.payloads.clone())
                .collect::<Vec<_>>(),
        );
        if combined_payloads.is_empty() {
            self.project_message = "AI attack plan has no safe payloads after filtering".to_string();
            return;
        }

        self.intruder_request_text = plan.marked_request;
        self.intruder_attack_type = attack_type;
        self.intruder_payloads_text = combined_payloads.join("\n");
        self.intruder_plan_payload_sets = payload_sets;
        if let Some(rps) = plan.recommended_rps {
            self.intruder_rps = rps.clamp(1, 10);
        }
        self.intruder_results.clear();
        self.intruder_total = 0;
        self.intruder_selected_result = 0;
        self.intruder_ai_plan = None;
        self.intruder_ai_suggestion = None;
        self.intruder_ai_mode = IntruderAiMode::Editing;
        self.project_message = "AI attack plan applied. Review markers/payloads, then press F5 manually.".to_string();
    }

    fn discard_intruder_ai_attack_plan(&mut self) {
        self.intruder_ai_plan = None;
        self.intruder_ai_input.clear();
        self.intruder_ai_mode = IntruderAiMode::Editing;
        self.project_message = "Discarded AI attack plan".to_string();
    }

    fn discard_intruder_ai_payloads(&mut self) {
        self.intruder_ai_suggestion = None;
        self.intruder_ai_input.clear();
        self.intruder_ai_mode = IntruderAiMode::Editing;
        self.project_message = "Discarded AI payload suggestion".to_string();
    }

    pub fn filtered_intruder_results(&self) -> Vec<IntruderResult> {
        self.intruder_results
            .iter()
            .filter(|result| {
                self.intruder_filter_status
                    .map(|prefix| result.status.map(|status| status / 100 == prefix / 100).unwrap_or(false))
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    fn handle_scope_key(&mut self, key: KeyEvent) -> bool {
        if self.scope_ai_mode == ScopeAiMode::Prompt {
            return self.handle_scope_ai_prompt_key(key);
        }

        if self.scope_ai_mode == ScopeAiMode::ProposalPreview {
            return self.handle_scope_ai_proposal_key(key);
        }

        if let Some(mode) = self.scope_input_mode {
            match key.code {
                KeyCode::Enter => {
                    match mode {
                        ScopeInputMode::Add => self.add_scope_rule_from_buffer(),
                        ScopeInputMode::Edit => self.edit_scope_rule_from_buffer(),
                        ScopeInputMode::Test => {
                            self.scope_test_url = self.scope_buffer.clone();
                            self.last_scope_test_result = Some(self.scope_engine.is_in_scope(&self.scope_test_url));
                        }
                    }
                    self.scope_buffer.clear();
                    self.scope_input_mode = None;
                }
                KeyCode::Esc => {
                    self.scope_buffer.clear();
                    self.scope_input_mode = None;
                }
                KeyCode::Backspace => {
                    self.scope_buffer.pop();
                }
                KeyCode::Char(char) => self.scope_buffer.push(char),
                _ => {}
            }
            return true;
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.open_scope_ai_assistant();
                true
            }
            (KeyCode::Char('a'), _) => {
                self.scope_input_mode = Some(ScopeInputMode::Add);
                self.scope_buffer.clear();
                true
            }
            (KeyCode::Char('e'), KeyModifiers::NONE) => {
                if let Some(rule) = self.scope_engine.rules.get(self.selected_scope_rule) {
                    self.scope_input_mode = Some(ScopeInputMode::Edit);
                    self.scope_buffer = rule.pattern.clone();
                }
                true
            }
            (KeyCode::Char('d'), _) => {
                if self.selected_scope_rule < self.scope_engine.rules.len() {
                    self.scope_engine.rules.remove(self.selected_scope_rule);
                    self.selected_scope_rule = self
                        .selected_scope_rule
                        .min(self.scope_engine.rules.len().saturating_sub(1));
                    self.persist_scope_rules();
                }
                true
            }
            (KeyCode::Char(' '), _) => {
                if let Some(rule) = self.scope_engine.rules.get_mut(self.selected_scope_rule) {
                    rule.enabled = !rule.enabled;
                    self.persist_scope_rules();
                }
                true
            }
            (KeyCode::Char('i'), KeyModifiers::NONE) => {
                if let Some(rule) = self.scope_engine.rules.get_mut(self.selected_scope_rule) {
                    rule.rule_type = ScopeRuleType::Include;
                    self.persist_scope_rules();
                }
                true
            }
            (KeyCode::Char('o'), _) => {
                if let Some(rule) = self.scope_engine.rules.get_mut(self.selected_scope_rule) {
                    rule.rule_type = ScopeRuleType::Exclude;
                    self.persist_scope_rules();
                }
                true
            }
            (KeyCode::Char('t'), _) => {
                self.scope_input_mode = Some(ScopeInputMode::Test);
                self.scope_buffer = self.scope_test_url.clone();
                true
            }
            (KeyCode::Down | KeyCode::Char('j'), _) => {
                self.selected_scope_rule = (self.selected_scope_rule + 1)
                    .min(self.scope_engine.rules.len().saturating_sub(1));
                true
            }
            (KeyCode::Up | KeyCode::Char('k'), _) => {
                self.selected_scope_rule = self.selected_scope_rule.saturating_sub(1);
                true
            }
            _ => false,
        }
    }

    fn handle_scope_ai_prompt_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Esc, _) => {
                self.scope_ai_input.clear();
                self.scope_ai_mode = ScopeAiMode::Editing;
                true
            }
            (KeyCode::Enter, _) => {
                self.submit_scope_ai_prompt();
                true
            }
            (KeyCode::Backspace, _) => {
                self.scope_ai_input.pop();
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                self.scope_ai_input.push(char);
                true
            }
            _ => true,
        }
    }

    fn handle_scope_ai_proposal_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => false,
            (KeyCode::Char('k'), KeyModifiers::CONTROL) => {
                self.open_scope_ai_assistant();
                true
            }
            (KeyCode::Char('a'), KeyModifiers::NONE) => {
                self.apply_scope_ai_proposal(false);
                true
            }
            (KeyCode::Char('R'), _) => {
                self.apply_scope_ai_proposal(true);
                true
            }
            (KeyCode::Char('d'), KeyModifiers::NONE) | (KeyCode::Esc, _) => {
                self.discard_scope_ai_proposal();
                true
            }
            _ => true,
        }
    }

    fn open_scope_ai_assistant(&mut self) {
        self.scope_ai_input.clear();
        self.scope_ai_proposal = None;
        self.scope_ai_mode = ScopeAiMode::Prompt;
        self.project_message = "AI Scope Assistant prompt opened".to_string();
    }

    fn submit_scope_ai_prompt(&mut self) {
        let instruction = self.scope_ai_input.trim().to_string();
        if instruction.is_empty() {
            return;
        }
        let existing_rules = self
            .scope_engine
            .rules
            .iter()
            .map(|rule| {
                format!(
                    "{} {} enabled={}",
                    rule.rule_type.as_str(),
                    rule.pattern,
                    rule.enabled
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let test_url = self.scope_test_url.clone();
        self.scope_ai_input.clear();
        self.scope_ai_mode = ScopeAiMode::ProposalPreview;
        self.scope_ai_proposal = Some(ScopeRuleProposalState::Loading);
        self.project_message = format!("Asking {} to draft scope rules", self.ai_panel.settings.model);

        let settings = self.ai_panel.settings.clone();
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = generate_scope_rules_with_ollama(settings, instruction, existing_rules, test_url).await;
            let _ = tx.send(AiEvent::ScopeRulesComplete { result }).await;
        });
    }

    fn apply_scope_ai_proposal(&mut self, replace_existing: bool) {
        let Some(ScopeRuleProposalState::Ready(proposal)) = self.scope_ai_proposal.clone() else {
            self.project_message = "No ready AI scope proposal to apply".to_string();
            return;
        };
        let mut next_id = self.scope_engine.rules.iter().map(|rule| rule.id).max().unwrap_or(0) + 1;
        let mut new_rules = Vec::new();
        for draft in proposal.rules {
            if draft.pattern.trim().is_empty() {
                continue;
            }
            if let Err(error) = ScopeEngine::validate(&draft.pattern) {
                self.project_message = format!("AI scope regex invalid: {} ({error})", draft.pattern);
                return;
            }
            new_rules.push(ScopeRule {
                id: next_id,
                pattern: draft.pattern,
                rule_type: ScopeRuleType::from_str(&draft.rule_type.to_ascii_lowercase()),
                enabled: true,
            });
            next_id += 1;
        }
        if new_rules.is_empty() {
            self.project_message = "AI scope proposal has no valid rules".to_string();
            return;
        }
        let count = new_rules.len();
        if replace_existing {
            self.scope_engine.rules = new_rules;
            self.selected_scope_rule = 0;
        } else {
            self.scope_engine.rules.extend(new_rules);
            self.selected_scope_rule = self.scope_engine.rules.len().saturating_sub(1);
        }
        self.scope_ai_proposal = None;
        self.scope_ai_mode = ScopeAiMode::Editing;
        self.persist_scope_rules();
        self.project_message = if replace_existing {
            format!("Replaced scope with {count} AI-generated rules")
        } else {
            format!("Appended {count} AI-generated scope rules")
        };
    }

    fn discard_scope_ai_proposal(&mut self) {
        self.scope_ai_proposal = None;
        self.scope_ai_input.clear();
        self.scope_ai_mode = ScopeAiMode::Editing;
        self.project_message = "Discarded AI scope proposal".to_string();
    }

    fn handle_paste(&mut self, text: String) {
        if text.is_empty() {
            return;
        }
        if self.search_mode {
            self.search_query.push_str(&text.replace('\r', "").replace('\n', ""));
            self.ensure_selected_matches_filter();
            return;
        }

        match self.current_tab {
            Tab::Ai => {
                self.ai_panel.input.push_str(&text);
            }
            Tab::Repeater => {
                if self.renaming_repeater {
                    self.rename_buffer.push_str(text.trim());
                } else if self.repeater_ai_mode == RepeaterAiMode::Prompt {
                    self.repeater_ai_input.push_str(&text);
                } else if self.repeater_ai_mode == RepeaterAiMode::Editing {
                    self.insert_repeater_text(&text);
                }
            }
            Tab::Intruder => {
                if matches!(self.intruder_ai_mode, IntruderAiMode::PayloadPrompt | IntruderAiMode::PlannerPrompt) {
                    self.intruder_ai_input.push_str(&text);
                } else if self.intruder_ai_mode == IntruderAiMode::Editing {
                    self.intruder_request_text.push_str(&text.replace("\r\n", "\n"));
                    self.intruder_plan_payload_sets.clear();
                }
            }
            Tab::Decoder => {
                if self.decoder_ai_mode == DecoderAiMode::Editing {
                    self.decoder_input.push_str(&text.replace("\r\n", "\n"));
                }
            }
            Tab::Comparer => {
                if self.comparer_detail_mode == ComparerDetailMode::AiSummary {
                    self.discard_comparer_ai_summary();
                }
                if self.comparer_focus_right {
                    self.comparer_right.push_str(&text.replace("\r\n", "\n"));
                } else {
                    self.comparer_left.push_str(&text.replace("\r\n", "\n"));
                }
            }
            Tab::Scope => {
                if self.scope_ai_mode == ScopeAiMode::Prompt {
                    self.scope_ai_input.push_str(&text);
                } else if self.scope_input_mode.is_some() {
                    self.scope_buffer.push_str(text.trim());
                }
            }
            Tab::Scanner => {
                if self.scanner_ai_mode == ScannerAiMode::RulePrompt {
                    self.scanner_ai_input.push_str(&text);
                }
            }
            _ => {}
        }
    }

    fn handle_mouse_event(&mut self, mouse: MouseEvent) {
        match self.current_tab {
            Tab::Proxy => match mouse.kind {
                MouseEventKind::ScrollDown => {
                    self.request_scroll = self.request_scroll.saturating_add(1);
                    self.response_scroll = self.response_scroll.saturating_add(1);
                }
                MouseEventKind::ScrollUp => {
                    self.request_scroll = self.request_scroll.saturating_sub(1);
                    self.response_scroll = self.response_scroll.saturating_sub(1);
                }
                MouseEventKind::Down(_) => self.select_flow_at_mouse(mouse.column, mouse.row),
                _ => {}
            },
            Tab::Repeater => match mouse.kind {
                MouseEventKind::ScrollDown => {
                    self.repeater_response_scroll = self.repeater_response_scroll.saturating_add(1)
                }
                MouseEventKind::ScrollUp => {
                    self.repeater_response_scroll = self.repeater_response_scroll.saturating_sub(1)
                }
                MouseEventKind::Down(_) => {
                    if self.repeater_ai_mode != RepeaterAiMode::Prompt {
                        self.repeater_ai_mode = RepeaterAiMode::Editing;
                    }
                    if let Some(tab) = self.repeater_tabs.get(self.active_repeater) {
                        self.repeater_cursor = self.repeater_cursor.min(tab.request_text.len());
                    }
                }
                _ => {}
            },
            Tab::Comparer => {
                if let MouseEventKind::Down(_) = mouse.kind {
                    let (width, _) = self.terminal_size;
                    self.comparer_focus_right = mouse.column >= width / 2;
                    self.project_message = if self.comparer_focus_right {
                        "Focused comparer right box".to_string()
                    } else {
                        "Focused comparer left box".to_string()
                    };
                }
            }
            Tab::Decoder => {
                if let MouseEventKind::Down(_) = mouse.kind {
                    if self.decoder_ai_mode == DecoderAiMode::SuggestionPreview {
                        self.decoder_ai_mode = DecoderAiMode::Editing;
                    }
                }
            }
            Tab::Scanner => {
                if let MouseEventKind::Down(_) = mouse.kind {
                    let row = mouse.row.saturating_sub(5) as usize;
                    let findings = self.filtered_findings();
                    if let Some(finding) = findings.get(row) {
                        self.selected_finding = row;
                        if let Some(index) = self
                            .flow_store
                            .snapshot()
                            .iter()
                            .position(|flow| flow.id == finding.flow_id)
                        {
                            self.selected_flow = Some(index);
                            self.current_tab = Tab::Proxy;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn select_flow_at_mouse(&mut self, column: u16, row: u16) {
        let (width, _) = self.terminal_size;
        let table_width = width.saturating_mul(38) / 100;
        if column >= table_width || row < 5 {
            return;
        }
        let visible_row = row.saturating_sub(5) as usize;
        let indices = self.filtered_flow_indices();
        let visible_height = self.terminal_size.1.saturating_sub(6) as usize;
        let selected_pos = self
            .selected_flow
            .and_then(|selected| indices.iter().position(|index| *index == selected))
            .unwrap_or(0);
        let offset = selected_pos.saturating_sub(visible_height.saturating_sub(1));
        if let Some(index) = indices.get(offset + visible_row) {
            self.selected_flow = Some(*index);
            self.reset_detail_scroll();
        }
    }

    fn start_proxy(&mut self) {
        if self.proxy_status == ProxyStatus::Running {
            self.proxy_message = "Proxy is already running".to_string();
            return;
        }
        let config = self.proxy_config.clone();
        let listen_addr = config.listen_addr;
        self.proxy_task = Some(run_proxy(config, LoggingHandler, self.flow_store.clone()));
        self.proxy_status = ProxyStatus::Running;
        self.proxy_message = format!("Proxy listening on {listen_addr}");
    }

    fn stop_proxy(&mut self) {
        if let Some(task) = self.proxy_task.take() {
            task.abort();
        }
        self.proxy_status = ProxyStatus::Stopped;
        self.proxy_message = "Proxy stopped".to_string();
    }

    fn new_repeater_from_selection(&mut self) {
        let request = self
            .selected_flow
            .and_then(|index| self.flow_store.snapshot().get(index).cloned())
            .map(|flow| raw_request_from_flow(&flow))
            .unwrap_or_else(default_repeater_request);
        let id = self.next_repeater_id;
        self.next_repeater_id += 1;
        self.repeater_tabs
            .push(RepeaterTab::new(id, format!("Request {id}"), request));
        self.active_repeater = self.repeater_tabs.len().saturating_sub(1);
        self.repeater_cursor = self
            .repeater_tabs
            .get(self.active_repeater)
            .map(|tab| tab.request_text.len())
            .unwrap_or_default();
        self.repeater_ai_mode = RepeaterAiMode::Editing;
        self.current_tab = Tab::Repeater;
        self.persist_repeater_tabs();
    }

    fn close_active_repeater(&mut self) {
        if self.repeater_tabs.len() <= 1 {
            if let Some(tab) = self.repeater_tabs.get_mut(0) {
                self.repeater_ai_drafts.remove(&tab.id);
                tab.request_text = default_repeater_request();
                tab.response = None;
                tab.error = None;
                tab.history.clear();
                tab.is_sending = false;
            }
            self.repeater_ai_mode = RepeaterAiMode::Editing;
            self.repeater_cursor = default_repeater_request().len();
            self.persist_repeater_tabs();
            return;
        }
        if let Some(tab) = self.repeater_tabs.get(self.active_repeater) {
            self.repeater_ai_drafts.remove(&tab.id);
        }
        self.repeater_tabs.remove(self.active_repeater);
        self.active_repeater = self.active_repeater.min(self.repeater_tabs.len().saturating_sub(1));
        self.repeater_cursor = self
            .repeater_tabs
            .get(self.active_repeater)
            .map(|tab| tab.request_text.len())
            .unwrap_or_default();
        self.repeater_ai_mode = RepeaterAiMode::Editing;
        self.persist_repeater_tabs();
    }

    fn next_repeater_tab(&mut self) {
        if !self.repeater_tabs.is_empty() {
            self.active_repeater = (self.active_repeater + 1) % self.repeater_tabs.len();
            self.repeater_cursor = self.repeater_tabs[self.active_repeater].request_text.len();
            self.repeater_ai_mode = if self.repeater_ai_drafts.contains_key(&self.repeater_tabs[self.active_repeater].id) {
                RepeaterAiMode::DraftPreview
            } else {
                RepeaterAiMode::Editing
            };
        }
    }

    fn previous_repeater_tab(&mut self) {
        if !self.repeater_tabs.is_empty() {
            self.active_repeater =
                (self.active_repeater + self.repeater_tabs.len() - 1) % self.repeater_tabs.len();
            self.repeater_cursor = self.repeater_tabs[self.active_repeater].request_text.len();
            self.repeater_ai_mode = if self.repeater_ai_drafts.contains_key(&self.repeater_tabs[self.active_repeater].id) {
                RepeaterAiMode::DraftPreview
            } else {
                RepeaterAiMode::Editing
            };
        }
    }

    fn open_repeater_ai_builder(&mut self) {
        if self.active_repeater_tab().is_none() {
            self.project_message = "No repeater tab available for AI request builder".to_string();
            return;
        }
        if let Some(tab_id) = self.active_repeater_tab().map(|tab| tab.id) {
            self.repeater_ai_drafts.remove(&tab_id);
        }
        self.repeater_ai_input.clear();
        self.repeater_ai_mode = RepeaterAiMode::Prompt;
        self.project_message = "AI Request Builder prompt opened".to_string();
    }

    fn submit_repeater_ai_prompt(&mut self) {
        let instruction = self.repeater_ai_input.trim().to_string();
        if instruction.is_empty() {
            return;
        }
        let Some(tab) = self.active_repeater_tab().cloned() else {
            self.project_message = "No repeater tab available for AI request builder".to_string();
            return;
        };

        self.repeater_ai_input.clear();
        self.repeater_ai_mode = RepeaterAiMode::DraftPreview;
        self.repeater_ai_drafts
            .insert(tab.id, RepeaterAiDraftState::Loading);
        self.project_message = format!("Asking {} to build request draft", self.ai_panel.settings.model);

        let settings = self.ai_panel.settings.clone();
        let tx = self.ai_tx.clone();
        tokio::spawn(async move {
            let result = build_repeater_request_with_ollama(settings, tab.request_text, instruction).await;
            let _ = tx
                .send(AiEvent::RepeaterDraftComplete { tab_id: tab.id, result })
                .await;
        });
    }

    fn active_repeater_ai_draft(&self) -> Option<(usize, RepeaterAiDraft)> {
        let tab_id = self.active_repeater_tab()?.id;
        match self.repeater_ai_drafts.get(&tab_id) {
            Some(RepeaterAiDraftState::Ready(draft)) => Some((tab_id, draft.clone())),
            _ => None,
        }
    }

    fn apply_repeater_ai_draft(&mut self) {
        let Some((tab_id, draft)) = self.active_repeater_ai_draft() else {
            self.project_message = "No ready AI draft to apply".to_string();
            return;
        };
        let normalized = match normalize_raw_http_request(&draft.modified_request) {
            Ok(request) => request,
            Err(error) => {
                self.project_message = format!("AI draft is invalid: {error}");
                return;
            }
        };
        if let Some(tab) = self.repeater_tabs.iter_mut().find(|tab| tab.id == tab_id) {
            tab.request_text = normalized;
            tab.response = None;
            tab.error = None;
            tab.is_sending = false;
            self.repeater_cursor = tab.request_text.len();
            self.repeater_response_scroll = 0;
            self.repeater_ai_drafts.remove(&tab_id);
            self.repeater_ai_mode = RepeaterAiMode::Editing;
            self.persist_repeater_tabs();
            self.project_message = format!("Applied AI draft to repeater tab #{tab_id}. Press Ctrl+Enter to send manually.");
        }
    }

    fn new_repeater_tab_from_ai_draft(&mut self) {
        let Some((source_tab_id, draft)) = self.active_repeater_ai_draft() else {
            self.project_message = "No ready AI draft to open in a new tab".to_string();
            return;
        };
        let normalized = match normalize_raw_http_request(&draft.modified_request) {
            Ok(request) => request,
            Err(error) => {
                self.project_message = format!("AI draft is invalid: {error}");
                return;
            }
        };
        let id = self.next_repeater_id;
        self.next_repeater_id += 1;
        self.repeater_tabs
            .push(RepeaterTab::new(id, format!("AI Draft {id}"), normalized));
        self.active_repeater = self.repeater_tabs.len().saturating_sub(1);
        self.repeater_cursor = self
            .repeater_tabs
            .get(self.active_repeater)
            .map(|tab| tab.request_text.len())
            .unwrap_or_default();
        self.repeater_ai_drafts.remove(&source_tab_id);
        self.repeater_ai_mode = RepeaterAiMode::Editing;
        self.persist_repeater_tabs();
        self.project_message = format!("Opened AI draft in new repeater tab #{id}. Press Ctrl+Enter to send manually.");
    }

    fn discard_repeater_ai_draft(&mut self) {
        if let Some(tab_id) = self.active_repeater_tab().map(|tab| tab.id) {
            self.repeater_ai_drafts.remove(&tab_id);
        }
        self.repeater_ai_input.clear();
        self.repeater_ai_mode = RepeaterAiMode::Editing;
        self.project_message = "Discarded AI request draft".to_string();
    }

    fn send_active_repeater(&mut self) {
        let Some(tab) = self.repeater_tabs.get_mut(self.active_repeater) else {
            return;
        };
        if tab.is_sending {
            return;
        }
        tab.is_sending = true;
        tab.error = None;
        let tab_id = tab.id;
        let request_text = tab.request_text.clone();
        let tx = self.repeater_tx.clone();
        tokio::spawn(async move {
            let response = send_raw_request(request_text).await;
            let _ = tx
                .send(RepeaterEvent::SendComplete { tab_id, response })
                .await;
        });
    }

    fn insert_repeater_char(&mut self, char: char) {
        if let Some(tab) = self.repeater_tabs.get_mut(self.active_repeater) {
            self.repeater_cursor = self.repeater_cursor.min(tab.request_text.len());
            tab.request_text.insert(self.repeater_cursor, char);
            self.repeater_cursor += char.len_utf8();
        }
    }

    fn insert_repeater_text(&mut self, text: &str) {
        if let Some(tab) = self.repeater_tabs.get_mut(self.active_repeater) {
            self.repeater_cursor = self.repeater_cursor.min(tab.request_text.len());
            let text = text.replace("\r\n", "\n");
            tab.request_text.insert_str(self.repeater_cursor, &text);
            self.repeater_cursor += text.len();
        }
    }

    fn backspace_repeater_char(&mut self) {
        if let Some(tab) = self.repeater_tabs.get_mut(self.active_repeater) {
            self.repeater_cursor = self.repeater_cursor.min(tab.request_text.len());
            if self.repeater_cursor == 0 {
                return;
            }
            if let Some((index, _)) = tab.request_text[..self.repeater_cursor].char_indices().last() {
                tab.request_text.drain(index..self.repeater_cursor);
                self.repeater_cursor = index;
            }
        }
    }

    fn delete_repeater_char(&mut self) {
        if let Some(tab) = self.repeater_tabs.get_mut(self.active_repeater) {
            self.repeater_cursor = self.repeater_cursor.min(tab.request_text.len());
            if self.repeater_cursor >= tab.request_text.len() {
                return;
            }
            let next = tab.request_text[self.repeater_cursor..]
                .char_indices()
                .nth(1)
                .map(|(offset, _)| self.repeater_cursor + offset)
                .unwrap_or_else(|| tab.request_text.len());
            tab.request_text.drain(self.repeater_cursor..next);
        }
    }

    fn start_intruder_attack(&mut self) {
        if self.intruder_running && !self.intruder_paused {
            return;
        }
        if self.intruder_paused {
            self.intruder_paused = false;
        }
        let positions = parse_positions(&self.intruder_request_text);
        if positions.is_empty() {
            self.project_message = "Intruder request has no §position§ markers".to_string();
            return;
        }
        let payloads = self
            .intruder_payloads_text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>();
        if payloads.is_empty() {
            self.project_message = "Intruder payload list is empty".to_string();
            return;
        }
        let payload_sets = if matches!(self.intruder_attack_type, AttackType::Pitchfork | AttackType::ClusterBomb)
            && self.intruder_plan_payload_sets.len() >= positions.len()
        {
            self.intruder_plan_payload_sets
                .iter()
                .take(positions.len())
                .enumerate()
                .map(|(index, set)| {
                    let values = dedupe_payloads(set.payloads.clone());
                    let name = if set.name.trim().is_empty() {
                        format!("AI Set {}", index + 1)
                    } else {
                        set.name.clone()
                    };
                    PayloadSet::simple(name, values)
                })
                .collect()
        } else {
            match self.intruder_attack_type {
                AttackType::Pitchfork | AttackType::ClusterBomb => positions
                    .iter()
                    .enumerate()
                    .map(|(index, _)| PayloadSet::simple(format!("Set {}", index + 1), payloads.clone()))
                    .collect(),
                _ => vec![PayloadSet::simple("Payloads", payloads)],
            }
        };
        let config = AttackConfig {
            target_request: self.intruder_request_text.clone(),
            positions,
            payload_sets,
            attack_type: self.intruder_attack_type,
            concurrency: self.intruder_concurrency,
            rps: self.intruder_rps,
        };
        self.intruder_total = config.total_requests();
        self.intruder_results.clear();
        self.intruder_selected_result = 0;
        self.intruder_running = true;
        self.intruder_paused = false;
        self.intruder_task = Some(IntruderEngine::spawn(config, self.intruder_tx.clone()));
    }

    fn stop_intruder_attack(&mut self) {
        if let Some(task) = self.intruder_task.take() {
            task.abort();
        }
        self.intruder_running = false;
        self.intruder_paused = false;
    }

    fn sort_intruder_results(&mut self) {
        if self.intruder_sort_desc {
            self.intruder_results.sort_by(|a, b| b.time_ms.cmp(&a.time_ms));
        } else {
            self.intruder_results.sort_by(|a, b| a.id.cmp(&b.id));
        }
    }

    fn export_intruder_csv(&mut self) {
        let path = std::env::var_os("PROXIMA_INTRUDER_CSV")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("proxima-intruder-results.csv"));
        let result = (|| -> Result<(), csv::Error> {
            let mut writer = csv::Writer::from_path(&path)?;
            writer.write_record(["id", "payload", "status", "length", "time_ms", "error"])?;
            for row in &self.intruder_results {
                writer.write_record([
                    row.id.to_string(),
                    row.payload_label.clone(),
                    row.status.map(|s| s.to_string()).unwrap_or_default(),
                    row.length.to_string(),
                    row.time_ms.to_string(),
                    row.error.clone().unwrap_or_default(),
                ])?;
            }
            writer.flush()?;
            Ok(())
        })();
        self.project_message = match result {
            Ok(()) => format!("Exported Intruder CSV to {}", path.display()),
            Err(error) => format!("CSV export failed: {error}"),
        };
    }

    fn add_scope_rule_from_buffer(&mut self) {
        let pattern = self.scope_buffer.trim();
        if pattern.is_empty() {
            return;
        }
        if let Err(error) = ScopeEngine::validate(pattern) {
            self.project_message = format!("Invalid scope regex: {error}");
            return;
        }
        let next_id = self.scope_engine.rules.iter().map(|rule| rule.id).max().unwrap_or(0) + 1;
        self.scope_engine.rules.push(ScopeRule::include(next_id, pattern));
        self.selected_scope_rule = self.scope_engine.rules.len().saturating_sub(1);
        self.persist_scope_rules();
    }

    fn edit_scope_rule_from_buffer(&mut self) {
        let pattern = self.scope_buffer.trim();
        if pattern.is_empty() {
            return;
        }
        if let Err(error) = ScopeEngine::validate(pattern) {
            self.project_message = format!("Invalid scope regex: {error}");
            return;
        }
        if let Some(rule) = self.scope_engine.rules.get_mut(self.selected_scope_rule) {
            rule.pattern = pattern.to_string();
            self.persist_scope_rules();
        }
    }

    fn persist_scope_rules(&mut self) {
        if let Err(error) = self.database.save_scope_rules(&self.scope_engine.rules) {
            self.project_message = format!("Failed to save scope: {error}");
        } else {
            self.project_message = "Scope rules saved".to_string();
        }
    }

    fn persist_repeater_tabs(&mut self) {
        if let Err(error) = self.database.save_repeater_tabs(&self.repeater_tabs) {
            self.project_message = format!("Failed to save repeater tabs: {error}");
        }
    }

    fn autosave_project(&mut self) {
        self.persist_repeater_tabs();
        let _ = self
            .database
            .save_setting("proxy.listen_addr", &self.proxy_config.listen_addr.to_string());
        let _ = self.database.save_intruder_results(&self.intruder_results);
        if let Err(error) = self.database.save_scope_rules(&self.scope_engine.rules) {
            self.project_message = format!("Autosave failed: {error}");
        } else {
            self.project_message = format!("Autosaved {}", self.database.path().display());
        }
    }

    fn save_project_as_env(&mut self) {
        let destination = std::env::var_os("PROXIMA_SAVE_AS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| self.database.path().to_path_buf());
        self.autosave_project();
        match self.database.save_as(&destination) {
            Ok(path) => self.project_message = format!("Saved project to {}", path.display()),
            Err(error) => self.project_message = format!("Save failed: {error}"),
        }
    }

    fn open_project_from_env(&mut self) {
        let Some(path) = std::env::var_os("PROXIMA_OPEN_PROJECT")
            .or_else(|| std::env::var_os("PROXIMA_PROJECT"))
            .map(std::path::PathBuf::from)
        else {
            self.project_message = "Set PROXIMA_OPEN_PROJECT=/path/to/project.db then press Ctrl+O".to_string();
            return;
        };

        match Database::open(&path) {
            Ok(database) => {
                self.database = database;
                self.flow_store
                    .set_flows(self.database.load_flows(10_000, 0).unwrap_or_default());
                if let Ok(tabs) = self.database.load_repeater_tabs() {
                    if !tabs.is_empty() {
                        self.repeater_tabs = tabs;
                        self.active_repeater = 0;
                        self.next_repeater_id = self.repeater_tabs.iter().map(|tab| tab.id).max().unwrap_or(0) + 1;
                        self.repeater_cursor = self.repeater_tabs[0].request_text.len();
                    }
                }
                self.scope_engine = ScopeEngine::new(self.database.load_scope_rules().unwrap_or_default());
                self.intruder_results = self.database.load_intruder_results().unwrap_or_default();
                self.findings = self.database.load_findings().unwrap_or_default();
                self.project_message = format!("Opened project {}", self.database.path().display());
            }
            Err(error) => self.project_message = format!("Open failed: {error}"),
        }
    }

    fn scan_and_store_flow(&mut self, flow: &HttpFlow) {
        for mut finding in self.passive_scanner.scan_flow(flow) {
            if self
                .findings
                .iter()
                .any(|existing| existing.flow_id == finding.flow_id && existing.issue_id == finding.issue_id)
            {
                continue;
            }
            match self.database.save_finding(&finding) {
                Ok(id) => finding.id = id,
                Err(error) => {
                    self.project_message = format!("Failed to save finding: {error}");
                    continue;
                }
            }
            self.findings.push(finding);
        }
    }

    fn toggle_scanner_check(&mut self) {
        if let Some(definition) = self
            .passive_scanner
            .definitions
            .get_mut(self.selected_scanner_check)
        {
            definition.enabled = !definition.enabled;
            self.project_message = format!(
                "Scanner check {} {}",
                definition.id,
                if definition.enabled { "enabled" } else { "disabled" }
            );
        }
    }

    fn reload_scanner_definitions(&mut self) {
        self.passive_scanner = PassiveScanner::load_default();
        self.selected_scanner_check = 0;
        self.project_message = format!(
            "Loaded {} passive scanner definitions",
            self.passive_scanner.definitions.len()
        );
    }

    fn export_findings_reports(&mut self) {
        let json_path = std::env::var_os("PROXIMA_FINDINGS_JSON")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("proxima-findings.json"));
        let html_path = std::env::var_os("PROXIMA_FINDINGS_HTML")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("proxima-findings.html"));

        let json_result = serde_json::to_string_pretty(&self.findings)
            .map_err(|error| error.to_string())
            .and_then(|body| std::fs::write(&json_path, body).map_err(|error| error.to_string()));
        let html_result = std::fs::write(&html_path, findings_html(&self.findings));

        self.project_message = match (json_result, html_result) {
            (Ok(()), Ok(())) => format!(
                "Exported findings to {} and {}",
                json_path.display(),
                html_path.display()
            ),
            (Err(error), _) => format!("Findings JSON export failed: {error}"),
            (_, Err(error)) => format!("Findings HTML export failed: {error}"),
        };
    }

    fn enqueue_selected_flow_for_active_scan(&mut self) {
        let Some(flow) = self
            .selected_flow
            .and_then(|index| self.flow_store.snapshot().get(index).cloned())
        else {
            self.project_message = "Select a proxy flow before adding active target".to_string();
            return;
        };
        if !self.scope_engine.is_in_scope(&flow.uri) {
            self.project_message = "Active scanning is scope-gated; selected URL is out of scope".to_string();
            return;
        }
        let Ok(url) = reqwest::Url::parse(&flow.uri) else {
            self.project_message = "Selected flow URI is not a valid URL".to_string();
            return;
        };
        if !self.active_scan_targets.iter().any(|target| target.url == url) {
            self.active_scan_targets.push(ActiveScanTarget {
                url,
                confirmed: true,
                completed: 0,
                total: 3,
                running: false,
            });
        }
        self.current_tab = Tab::Active;
    }

    fn start_active_scan(&mut self) {
        if !self.active_scanning_enabled {
            self.project_message = "Active checks disabled; press e on Active tab after confirming authorization".to_string();
            return;
        }
        if self.active_scan_task.is_some() {
            return;
        }
        let Some(target) = self.active_scan_targets.get_mut(self.selected_active_target) else {
            self.project_message = "No active scan target queued".to_string();
            return;
        };
        if !target.confirmed || !self.scope_engine.is_in_scope(target.url.as_str()) {
            self.project_message = "Target must be confirmed and in scope".to_string();
            return;
        }
        target.running = true;
        target.completed = 0;
        let url = target.url.clone();
        let tx = self.active_scanner_tx.clone();
        self.active_scan_task = Some(tokio::spawn(async move {
            run_safe_active_scan(url, tx).await;
        }));
    }

    fn send_selection_to_decoder(&mut self) {
        let Some(flow) = self
            .selected_flow
            .and_then(|index| self.flow_store.snapshot().get(index).cloned())
        else {
            return;
        };
        let bytes = flow
            .response_body
            .or_else(|| Some(flow.request_body))
            .unwrap_or_default();
        self.decoder_input = String::from_utf8_lossy(&bytes).into_owned();
        self.current_tab = Tab::Decoder;
    }

    fn mark_selection_for_comparer(&mut self) {
        let Some(index) = self.selected_flow else {
            return;
        };
        if !self.comparer_marked_flows.contains(&index) {
            self.comparer_marked_flows.push(index);
        }
        if self.comparer_marked_flows.len() > 2 {
            self.comparer_marked_flows.remove(0);
        }
        if self.comparer_marked_flows.len() == 2 {
            let flows = self.flow_store.snapshot();
            if let (Some(left), Some(right)) = (
                flows.get(self.comparer_marked_flows[0]),
                flows.get(self.comparer_marked_flows[1]),
            ) {
                self.comparer_left = flow_compare_text(left);
                self.comparer_right = flow_compare_text(right);
                self.current_tab = Tab::Comparer;
            }
        }
    }

    fn select_next_flow(&mut self) {
        self.select_relative(1);
    }

    fn select_previous_flow(&mut self) {
        self.select_relative(-1);
    }

    fn select_relative(&mut self, delta: isize) {
        let indices = self.filtered_flow_indices();
        if indices.is_empty() {
            self.selected_flow = None;
            return;
        }
        let current = self
            .selected_flow
            .and_then(|selected| indices.iter().position(|index| *index == selected))
            .unwrap_or(0) as isize;
        let next = (current + delta).clamp(0, indices.len() as isize - 1) as usize;
        self.selected_flow = Some(indices[next]);
        self.reset_detail_scroll();
    }

    fn select_first_flow(&mut self) {
        self.selected_flow = self.filtered_flow_indices().first().copied();
        self.reset_detail_scroll();
    }

    fn select_last_flow(&mut self) {
        self.selected_flow = self.filtered_flow_indices().last().copied();
        self.reset_detail_scroll();
    }

    fn ensure_selected_matches_filter(&mut self) {
        let indices = self.filtered_flow_indices();
        if !self
            .selected_flow
            .map(|selected| indices.contains(&selected))
            .unwrap_or(false)
        {
            self.selected_flow = indices.first().copied();
        }
        self.reset_detail_scroll();
    }

    fn reset_detail_scroll(&mut self) {
        self.request_scroll = 0;
        self.response_scroll = 0;
    }

    fn next_tab(&mut self) {
        self.current_tab = Tab::from_index(self.current_tab.index() + 1);
    }

    fn previous_tab(&mut self) {
        self.current_tab = Tab::from_index(self.current_tab.index() + Tab::ALL.len() - 1);
    }

    fn quit(&mut self) {
        self.autosave_project();
        self.stop_proxy();
        self.should_quit = true;
    }
}

fn configured_ai_model_presets() -> Vec<String> {
    let mut models = Vec::new();
    for var in ["PROXIMA_AI_MODEL_PRESETS", "PROXIMA_CLOUD_AI_MODELS", "PROXIMA_AI_MODELS"] {
        if let Ok(value) = std::env::var(var) {
            for model in value.split(',').map(str::trim).filter(|model| !model.is_empty()) {
                if !models.iter().any(|existing: &String| existing == model) {
                    models.push(model.to_string());
                }
            }
        }
    }
    if let Ok(model) = std::env::var("PROXIMA_OLLAMA_MODEL") {
        if !model.trim().is_empty() && !models.iter().any(|existing| existing == &model) {
            models.push(model);
        }
    }
    for model in ["qwen2.5-coder:7b", "llama3.1:8b", "mistral:7b", "gemma2:9b"] {
        if !models.iter().any(|existing| existing == model) {
            models.push(model.to_string());
        }
    }
    models
}

async fn fetch_ollama_models(settings: crate::models::ai::AiSettings) -> Result<Vec<String>, String> {
    let url = format!("{}/api/tags", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let value: serde_json::Value = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    let mut models = value
        .get("models")
        .and_then(|models| models.as_array())
        .into_iter()
        .flatten()
        .filter_map(|model| model.get("name").and_then(|name| name.as_str()).map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    models.sort();
    models.dedup();
    Ok(models)
}

async fn ask_ollama(
    settings: crate::models::ai::AiSettings,
    context: Option<AiContext>,
    history: Vec<AiMessage>,
    prompt: String,
) -> Result<String, String> {
    let mut messages = vec![OllamaMessage {
        role: "system".to_string(),
        content: ai_system_prompt(),
    }];

    if let Some(context) = context {
        messages.push(OllamaMessage {
            role: "system".to_string(),
            content: format!(
                "Attached Proxima context:\nTitle: {}\nSummary:\n{}\n\nRedacted raw context:\n{}",
                context.title, context.summary, context.redacted_raw
            ),
        });
    }

    for message in history.iter().rev().take(8).rev() {
        let role = match message.role {
            crate::models::ai::AiRole::User => "user",
            crate::models::ai::AiRole::Assistant => "assistant",
            crate::models::ai::AiRole::System => "system",
        };
        messages.push(OllamaMessage {
            role: role.to_string(),
            content: message.content.clone(),
        });
    }
    messages.push(OllamaMessage {
        role: "user".to_string(),
        content: prompt,
    });

    let request = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())
}

async fn explain_flow_with_ollama(
    settings: crate::models::ai::AiSettings,
    flow: HttpFlow,
) -> Result<FlowExplanation, String> {
    let context = ai_context_from_flow(
        &flow,
        settings.redaction_enabled,
        settings.max_context_chars,
    );
    let messages = vec![
        OllamaMessage {
            role: "system".to_string(),
            content: ai_flow_explainer_system_prompt(),
        },
        OllamaMessage {
            role: "user".to_string(),
            content: format!(
                "Explain this selected HTTP flow as a structured AI Flow Brief.\n\nTitle: {}\nSummary:\n{}\n\nRedacted raw evidence:\n{}",
                context.title, context.summary, context.redacted_raw
            ),
        },
    ];

    let request = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    let content = response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())?;
    Ok(parse_flow_explanation(&content))
}

async fn triage_finding_with_ollama(
    settings: crate::models::ai::AiSettings,
    finding: Finding,
    flow: Option<HttpFlow>,
    definition_context: String,
) -> Result<FindingTriage, String> {
    let flow_context = flow
        .as_ref()
        .map(|flow| {
            let context = ai_context_from_flow(
                flow,
                settings.redaction_enabled,
                settings.max_context_chars,
            );
            format!(
                "Related HTTP flow:\nTitle: {}\nSummary:\n{}\n\nRedacted raw evidence:\n{}",
                context.title, context.summary, context.redacted_raw
            )
        })
        .unwrap_or_else(|| "Related HTTP flow unavailable in current store.".to_string());

    let messages = vec![
        OllamaMessage {
            role: "system".to_string(),
            content: ai_finding_triage_system_prompt(),
        },
        OllamaMessage {
            role: "user".to_string(),
            content: format!(
                "Triage this passive scanner finding.\n\nFinding:\nID: {}\nFlow ID: {}\nIssue ID: {}\nIssue Name: {}\nScanner Severity: {}\nScanner Confidence: {}\nURL: {}\nEvidence JSON:\n{}\n\nScanner definition:\n{}\n\n{}",
                finding.id,
                finding.flow_id,
                finding.issue_id,
                finding.issue_name,
                finding.severity.label(),
                finding.confidence.label(),
                finding.url,
                finding.evidence_json,
                definition_context,
                flow_context
            ),
        },
    ];

    let request = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    let content = response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())?;
    Ok(parse_finding_triage(&content))
}

async fn build_repeater_request_with_ollama(
    settings: crate::models::ai::AiSettings,
    raw_request: String,
    instruction: String,
) -> Result<RepeaterAiDraft, String> {
    let (redacted_request, preserved_values, preserved_names) = redact_repeater_request_for_ai(&raw_request);
    let messages = vec![
        OllamaMessage {
            role: "system".to_string(),
            content: ai_repeater_builder_system_prompt(),
        },
        OllamaMessage {
            role: "user".to_string(),
            content: format!(
                "User instruction:\n{}\n\nCurrent raw HTTP request with sensitive values replaced by preservation placeholders:\n{}",
                instruction, redacted_request
            ),
        },
    ];

    let request = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    let content = response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())?;
    let mut draft = parse_repeater_ai_draft(&content);
    if draft.modified_request.trim().is_empty() {
        return Err("AI response did not include modified_request".to_string());
    }

    draft.modified_request = restore_repeater_placeholders(&draft.modified_request, &preserved_values);
    if draft.modified_request.contains("{{PRESERVE_HEADER_") {
        return Err("AI draft contains unresolved preservation placeholders".to_string());
    }
    draft.modified_request = normalize_raw_http_request(&draft.modified_request)?;

    for name in preserved_names {
        if !draft.preserved_sensitive_items.iter().any(|item| item.eq_ignore_ascii_case(&name)) {
            draft.preserved_sensitive_items.push(name.clone());
        }
        if !request_contains_header(&draft.modified_request, &name) {
            draft
                .warnings
                .push(format!("Sensitive header {name} was not present in the AI draft; review before sending."));
        }
    }
    if !draft
        .change_summary
        .iter()
        .any(|item| item.to_ascii_lowercase().contains("content-length"))
    {
        draft
            .change_summary
            .push("Normalized raw HTTP formatting and Content-Length before preview.".to_string());
    }
    if draft.safety_notes.is_empty() {
        draft.safety_notes.push("Draft only: request was not sent automatically.".to_string());
        draft.safety_notes.push("Review authorization and scope before pressing Ctrl+Enter.".to_string());
    }
    Ok(draft)
}

async fn generate_intruder_payloads_with_ollama(
    settings: crate::models::ai::AiSettings,
    instruction: String,
    request: String,
    attack_type: AttackType,
    existing_payload_count: usize,
) -> Result<IntruderPayloadSuggestion, String> {
    let positions = parse_positions(&request);
    let position_summary = positions
        .iter()
        .enumerate()
        .map(|(index, position)| {
            format!(
                "{}. placeholder='{}' byte_range={}..{}",
                index + 1,
                position.placeholder,
                position.start,
                position.end
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let redacted_request = if settings.redaction_enabled {
        redact_repeater_request_for_ai(&request).0
    } else {
        request.clone()
    };
    let messages = vec![
        OllamaMessage {
            role: "system".to_string(),
            content: ai_intruder_payload_generator_system_prompt(),
        },
        OllamaMessage {
            role: "user".to_string(),
            content: format!(
                "User instruction:\n{}\n\nIntruder target request with §position§ markers:\n{}\n\nPositions:\n{}\n\nCurrent attack type: {}\nExisting payload count: {}\nSafety mode: destructive payloads disabled by default.",
                instruction,
                redacted_request.chars().take(settings.max_context_chars).collect::<String>(),
                if position_summary.is_empty() { "no positions marked".to_string() } else { position_summary },
                attack_type.label(),
                existing_payload_count
            ),
        },
    ];

    let request_body = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request_body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    let content = response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())?;
    Ok(normalize_intruder_payload_suggestion(parse_intruder_payload_suggestion(&content)))
}

async fn plan_intruder_attack_with_ollama(
    settings: crate::models::ai::AiSettings,
    instruction: String,
    request: String,
    attack_type: AttackType,
    existing_payload_count: usize,
) -> Result<IntruderAttackPlan, String> {
    let (redacted_request, preserved_values, _) = if settings.redaction_enabled {
        redact_repeater_request_for_ai(&request)
    } else {
        (request.clone(), Vec::new(), Vec::new())
    };
    let positions = parse_positions(&request);
    let position_summary = positions
        .iter()
        .enumerate()
        .map(|(index, position)| {
            format!(
                "{}. existing marker placeholder='{}' byte_range={}..{}",
                index + 1,
                position.placeholder,
                position.start,
                position.end
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let messages = vec![
        OllamaMessage {
            role: "system".to_string(),
            content: ai_intruder_attack_planner_system_prompt(),
        },
        OllamaMessage {
            role: "user".to_string(),
            content: format!(
                "User instruction:\n{}\n\nCurrent Intruder raw request:\n{}\n\nExisting positions:\n{}\n\nCurrent attack type: {}\nExisting payload count: {}\nSafety mode: destructive payloads disabled; attack must not start automatically.",
                instruction,
                redacted_request.chars().take(settings.max_context_chars).collect::<String>(),
                if position_summary.is_empty() { "no positions marked yet".to_string() } else { position_summary },
                attack_type.label(),
                existing_payload_count
            ),
        },
    ];

    let request_body = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request_body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    let content = response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())?;
    let mut plan = parse_intruder_attack_plan(&content);
    plan.marked_request = restore_repeater_placeholders(&plan.marked_request, &preserved_values);
    if plan.marked_request.contains("{{PRESERVE_HEADER_") {
        return Err("AI attack plan contains unresolved preservation placeholders".to_string());
    }
    Ok(normalize_intruder_attack_plan(plan)?)
}

async fn generate_scope_rules_with_ollama(
    settings: crate::models::ai::AiSettings,
    instruction: String,
    existing_rules: String,
    test_url: String,
) -> Result<ScopeRuleProposal, String> {
    let messages = vec![
        OllamaMessage {
            role: "system".to_string(),
            content: ai_scope_assistant_system_prompt(),
        },
        OllamaMessage {
            role: "user".to_string(),
            content: format!(
                "User scope instruction:\n{}\n\nExisting scope rules:\n{}\n\nCurrent test URL: {}",
                instruction,
                if existing_rules.trim().is_empty() { "<none>" } else { &existing_rules },
                test_url
            ),
        },
    ];

    let request_body = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request_body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    let content = response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())?;
    Ok(normalize_scope_rule_proposal(parse_scope_rule_proposal(&content))?)
}

async fn generate_passive_rule_with_ollama(
    settings: crate::models::ai::AiSettings,
    instruction: String,
    existing_ids: Vec<String>,
) -> Result<PassiveRuleDraft, String> {
    let messages = vec![
        OllamaMessage {
            role: "system".to_string(),
            content: ai_passive_rule_generator_system_prompt(),
        },
        OllamaMessage {
            role: "user".to_string(),
            content: format!(
                "User rule request:\n{}\n\nExisting passive scanner rule IDs:\n{}",
                instruction,
                if existing_ids.is_empty() { "<none>".to_string() } else { existing_ids.join(", ") }
            ),
        },
    ];

    let request_body = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request_body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    let content = response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())?;
    Ok(validate_passive_rule_draft(parse_passive_rule_draft(&content), &existing_ids))
}

async fn summarize_comparer_with_ollama(
    settings: crate::models::ai::AiSettings,
    left: String,
    right: String,
    mode: CompareMode,
    heuristics: String,
) -> Result<ComparerSummary, String> {
    let left_sample = left.chars().take(settings.max_context_chars.min(8_000)).collect::<String>();
    let right_sample = right.chars().take(settings.max_context_chars.min(8_000)).collect::<String>();
    let diff = diffy::PatchFormatter::new()
        .fmt_patch(&diffy::create_patch(&left_sample, &right_sample))
        .to_string()
        .chars()
        .take(8_000)
        .collect::<String>();
    let messages = vec![
        OllamaMessage {
            role: "system".to_string(),
            content: ai_comparer_summary_system_prompt(),
        },
        OllamaMessage {
            role: "user".to_string(),
            content: format!(
                "Compare mode: {}\n\nLocal heuristics:\n{}\n\nDiff sample:\n{}\n\nLeft sample:\n{}\n\nRight sample:\n{}",
                mode.label(), heuristics, diff, left_sample, right_sample
            ),
        },
    ];

    let request_body = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request_body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    let content = response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())?;
    Ok(normalize_comparer_summary(parse_comparer_summary(&content)))
}

async fn suggest_decoder_chain_with_ollama(
    settings: crate::models::ai::AiSettings,
    input: String,
    current_chain: String,
    heuristics: String,
) -> Result<DecoderChainSuggestion, String> {
    let sample = input.chars().take(settings.max_context_chars.min(8_000)).collect::<String>();
    let messages = vec![
        OllamaMessage {
            role: "system".to_string(),
            content: ai_decoder_chain_builder_system_prompt(),
        },
        OllamaMessage {
            role: "user".to_string(),
            content: format!(
                "Decoder input sample:\n{}\n\nCurrent transform chain: {}\n\nLocal heuristics:\n{}",
                sample,
                if current_chain.trim().is_empty() { "<empty>" } else { &current_chain },
                heuristics
            ),
        },
    ];

    let request_body = OllamaChatRequest {
        model: settings.model,
        stream: false,
        messages,
        options: OllamaOptions {
            temperature: settings.temperature,
        },
    };
    let url = format!("{}/api/chat", settings.ollama_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(&request_body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let body = response.text().await.map_err(|error| error.to_string())?;
    if !status.is_success() {
        return Err(format!("ollama returned {status}: {body}"));
    }
    let response: OllamaChatResponse = serde_json::from_str(&body).map_err(|error| error.to_string())?;
    if let Some(error) = response.error {
        return Err(error);
    }
    let content = response
        .message
        .map(|message| message.content)
        .ok_or_else(|| "ollama response did not include a message".to_string())?;
    Ok(normalize_decoder_chain_suggestion(parse_decoder_chain_suggestion(&content)))
}

fn parse_flow_explanation(content: &str) -> FlowExplanation {
    if let Ok(explanation) = serde_json::from_str::<FlowExplanation>(content) {
        return explanation;
    }

    if let Some(json) = extract_json_object(content) {
        if let Ok(explanation) = serde_json::from_str::<FlowExplanation>(json) {
            return explanation;
        }
    }

    FlowExplanation {
        purpose: "AI returned an unstructured explanation.".to_string(),
        raw_text: Some(content.trim().to_string()),
        ..FlowExplanation::default()
    }
}

fn parse_finding_triage(content: &str) -> FindingTriage {
    if let Ok(triage) = serde_json::from_str::<FindingTriage>(content) {
        return normalize_finding_triage(triage);
    }

    if let Some(json) = extract_json_object(content) {
        if let Ok(triage) = serde_json::from_str::<FindingTriage>(json) {
            return normalize_finding_triage(triage);
        }
    }

    FindingTriage {
        priority: "P4".to_string(),
        priority_label: "Needs review".to_string(),
        real_risk: "AI returned an unstructured triage response.".to_string(),
        raw_text: Some(content.trim().to_string()),
        ..FindingTriage::default()
    }
}

fn normalize_finding_triage(mut triage: FindingTriage) -> FindingTriage {
    if triage.priority.trim().is_empty() {
        triage.priority = priority_from_label(&triage.priority_label).to_string();
    }
    if triage.priority_label.trim().is_empty() {
        triage.priority_label = priority_label(&triage.priority).to_string();
    }
    triage
}

fn parse_repeater_ai_draft(content: &str) -> RepeaterAiDraft {
    if let Ok(draft) = serde_json::from_str::<RepeaterAiDraft>(content) {
        return draft;
    }

    if let Some(json) = extract_json_object(content) {
        if let Ok(draft) = serde_json::from_str::<RepeaterAiDraft>(json) {
            return draft;
        }
    }

    RepeaterAiDraft {
        modified_request: content.trim().to_string(),
        warnings: vec!["AI returned unstructured output; review carefully before applying.".to_string()],
        raw_text: Some(content.trim().to_string()),
        ..RepeaterAiDraft::default()
    }
}

fn parse_intruder_payload_suggestion(content: &str) -> IntruderPayloadSuggestion {
    if let Ok(suggestion) = serde_json::from_str::<IntruderPayloadSuggestion>(content) {
        return suggestion;
    }

    if let Some(json) = extract_json_object(content) {
        if let Ok(suggestion) = serde_json::from_str::<IntruderPayloadSuggestion>(json) {
            return suggestion;
        }
    }

    IntruderPayloadSuggestion {
        category: "Custom".to_string(),
        safe_only: true,
        payloads: content
            .lines()
            .map(|line| line.trim().trim_start_matches('-').trim().to_string())
            .filter(|line| !line.is_empty())
            .collect(),
        warnings: vec!["AI returned unstructured payload output; destructive filters were still applied.".to_string()],
        raw_text: Some(content.trim().to_string()),
        ..IntruderPayloadSuggestion::default()
    }
}

fn parse_intruder_attack_plan(content: &str) -> IntruderAttackPlan {
    if let Ok(plan) = serde_json::from_str::<IntruderAttackPlan>(content) {
        return plan;
    }

    if let Some(json) = extract_json_object(content) {
        if let Ok(plan) = serde_json::from_str::<IntruderAttackPlan>(json) {
            return plan;
        }
    }

    IntruderAttackPlan {
        plan_name: "Unstructured AI Attack Plan".to_string(),
        warnings: vec!["AI returned unstructured attack planning output; plan cannot be applied until it returns a marked_request.".to_string()],
        raw_text: Some(content.trim().to_string()),
        ..IntruderAttackPlan::default()
    }
}

fn parse_passive_rule_draft(content: &str) -> PassiveRuleDraft {
    if let Ok(draft) = serde_json::from_str::<PassiveRuleDraft>(content) {
        return draft;
    }

    if let Some(json) = extract_json_object(content) {
        if let Ok(draft) = serde_json::from_str::<PassiveRuleDraft>(json) {
            return draft;
        }
    }

    let yaml = strip_markdown_fence(content).trim().to_string();
    PassiveRuleDraft {
        yaml,
        raw_text: Some(content.trim().to_string()),
        warnings: vec!["AI returned unstructured output; treating it as YAML and validating.".to_string()],
        ..PassiveRuleDraft::default()
    }
}

fn validate_passive_rule_draft(mut draft: PassiveRuleDraft, existing_ids: &[String]) -> PassiveRuleDraft {
    draft.validation_errors.clear();
    draft.validation_warnings.clear();
    draft.yaml = strip_markdown_fence(&draft.yaml).trim().to_string();
    if draft.yaml.is_empty() {
        draft.validation_errors.push("YAML is empty".to_string());
        return draft;
    }

    let definition = match serde_yaml::from_str::<IssueDefinition>(&draft.yaml) {
        Ok(definition) => definition,
        Err(error) => {
            draft.validation_errors.push(format!("YAML parse error: {error}"));
            return draft;
        }
    };

    if definition.id.trim().is_empty() {
        draft.validation_errors.push("id is required".to_string());
    }
    let sanitized = sanitize_passive_rule_id(&definition.id);
    if sanitized != definition.id {
        draft.validation_errors.push("id must be lowercase kebab-case: a-z, 0-9, hyphen".to_string());
    }
    if existing_ids.iter().any(|id| id == &definition.id) {
        draft.validation_errors.push(format!("rule id already exists: {}", definition.id));
    }
    if definition.name.trim().is_empty() {
        draft.validation_errors.push("name is required".to_string());
    }
    if definition.passive_checks.is_empty() {
        draft.validation_errors.push("passive_checks must contain at least one check".to_string());
    }
    for check in &definition.passive_checks {
        match check {
            PassiveCheck::HeaderContains { value_regex, .. } => {
                if let Err(error) = regex::Regex::new(value_regex) {
                    draft.validation_errors.push(format!("header_contains value_regex invalid: {error}"));
                }
                if matches!(value_regex.as_str(), ".*" | "(?s).*" | "") {
                    draft.validation_warnings.push("header_contains regex is very broad".to_string());
                }
            }
            PassiveCheck::BodyRegex { pattern } => {
                if let Err(error) = regex::Regex::new(pattern) {
                    draft.validation_errors.push(format!("body_regex pattern invalid: {error}"));
                }
                if matches!(pattern.as_str(), ".*" | "(?s).*" | "") {
                    draft.validation_warnings.push("body_regex pattern is very broad/noisy".to_string());
                }
            }
            PassiveCheck::StatusCode { codes } => {
                if codes.is_empty() {
                    draft.validation_errors.push("status_code check must include at least one code".to_string());
                }
            }
            PassiveCheck::HeaderMissing { name } => {
                if name.trim().is_empty() {
                    draft.validation_errors.push("header_missing name is empty".to_string());
                }
            }
        }
    }
    draft.rule_id = definition.id.clone();
    draft.filename = format!("{}.yaml", definition.id);
    if draft.explanation.trim().is_empty() {
        draft.explanation = format!("Generated passive scanner rule: {}", definition.name);
    }
    if draft.warnings.is_empty() {
        draft.warnings.push("Review severity and confidence before relying on this custom rule.".to_string());
    }
    draft
}

fn sanitize_passive_rule_id(value: &str) -> String {
    let mut output = String::new();
    for ch in value.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            output.push(ch);
        } else if matches!(ch, '-' | '_' | ' ') {
            if !output.ends_with('-') {
                output.push('-');
            }
        }
    }
    output.trim_matches('-').to_string()
}

fn strip_markdown_fence(value: &str) -> String {
    let trimmed = value.trim();
    if !trimmed.starts_with("```") {
        return trimmed.to_string();
    }
    let without_start = trimmed
        .lines()
        .skip(1)
        .collect::<Vec<_>>()
        .join("\n");
    without_start
        .trim_end_matches("```")
        .trim()
        .to_string()
}

fn parse_comparer_summary(content: &str) -> ComparerSummary {
    if let Ok(summary) = serde_json::from_str::<ComparerSummary>(content) {
        return summary;
    }

    if let Some(json) = extract_json_object(content) {
        if let Ok(summary) = serde_json::from_str::<ComparerSummary>(json) {
            return summary;
        }
    }

    ComparerSummary {
        summary: "AI returned an unstructured comparer summary.".to_string(),
        raw_text: Some(content.trim().to_string()),
        ..ComparerSummary::default()
    }
}

fn normalize_comparer_summary(mut summary: ComparerSummary) -> ComparerSummary {
    if summary.summary.trim().is_empty() {
        summary.summary = "AI summarized the observed differences.".to_string();
    }
    if summary.risk_hint.trim().is_empty() {
        summary.risk_hint = "content_change".to_string();
    }
    summary
}

fn parse_decoder_chain_suggestion(content: &str) -> DecoderChainSuggestion {
    if let Ok(suggestion) = serde_json::from_str::<DecoderChainSuggestion>(content) {
        return suggestion;
    }

    if let Some(json) = extract_json_object(content) {
        if let Ok(suggestion) = serde_json::from_str::<DecoderChainSuggestion>(json) {
            return suggestion;
        }
    }

    DecoderChainSuggestion {
        detected_type: "Unstructured".to_string(),
        summary: "AI returned an unstructured decoder response.".to_string(),
        warnings: vec!["Could not parse structured decoder chain; no transforms can be applied.".to_string()],
        raw_text: Some(content.trim().to_string()),
        ..DecoderChainSuggestion::default()
    }
}

fn normalize_decoder_chain_suggestion(mut suggestion: DecoderChainSuggestion) -> DecoderChainSuggestion {
    suggestion
        .suggested_chain
        .retain(|item| parse_decoder_transform_label(&item.transform).is_some());
    if suggestion.detected_type.trim().is_empty() {
        suggestion.detected_type = "Unknown".to_string();
    }
    if suggestion.summary.trim().is_empty() {
        suggestion.summary = "AI suggested a decoder transform chain.".to_string();
    }
    suggestion
}

fn parse_decoder_transform_label(value: &str) -> Option<DecoderTransform> {
    let normalized = value
        .to_ascii_lowercase()
        .replace(' ', "")
        .replace('-', "")
        .replace('_', "");
    match normalized.as_str() {
        "base64decode" | "b64decode" | "frombase64" => Some(DecoderTransform::Base64Decode),
        "base64encode" | "b64encode" | "tobase64" => Some(DecoderTransform::Base64Encode),
        "hexdecode" | "fromhex" => Some(DecoderTransform::HexDecode),
        "hexencode" | "tohex" => Some(DecoderTransform::HexEncode),
        "urldecode" | "urlpercentdecode" | "percentdecode" => Some(DecoderTransform::UrlDecode),
        "urlencode" | "percentencode" => Some(DecoderTransform::UrlEncode),
        "htmldecode" | "htmlentitydecode" | "entitydecode" => Some(DecoderTransform::HtmlDecode),
        "jwtdecode" | "jwt" => Some(DecoderTransform::JwtDecode),
        "jsonprettyprint" | "jsonpretty" | "prettyjson" | "jsonformat" => Some(DecoderTransform::JsonPrettyPrint),
        "sha256" | "sha256hash" => Some(DecoderTransform::Sha256),
        "md5" | "md5hash" => Some(DecoderTransform::Md5),
        _ => None,
    }
}

fn comparer_heuristic_summary(left: &str, right: &str) -> String {
    let mut lines = Vec::new();
    lines.push(format!("left length: {} bytes", left.len()));
    lines.push(format!("right length: {} bytes", right.len()));
    let delta = right.len() as isize - left.len() as isize;
    lines.push(format!("body length delta right-left: {delta}"));
    if let (Some(left_status), Some(right_status)) = (http_status_hint(left), http_status_hint(right)) {
        if left_status != right_status {
            lines.push(format!("HTTP status changed {left_status} -> {right_status}"));
        } else {
            lines.push(format!("HTTP status unchanged: {left_status}"));
        }
    }
    let left_headers = parse_http_headers_text(left);
    let right_headers = parse_http_headers_text(right);
    for (name, value) in &right_headers {
        if !left_headers.iter().any(|(left_name, _)| left_name.eq_ignore_ascii_case(name)) {
            lines.push(format!("header added in right: {name}: {value}"));
        }
    }
    for (name, left_value) in &left_headers {
        if let Some((_, right_value)) = right_headers.iter().find(|(right_name, _)| right_name.eq_ignore_ascii_case(name)) {
            if left_value != right_value && is_security_interesting_header(name) {
                lines.push(format!("interesting header changed {name}: {left_value} -> {right_value}"));
            }
        } else if is_security_interesting_header(name) {
            lines.push(format!("interesting header removed in right: {name}"));
        }
    }
    if let (Ok(left_json), Ok(right_json)) = (
        serde_json::from_str::<serde_json::Value>(body_like_text(left)),
        serde_json::from_str::<serde_json::Value>(body_like_text(right)),
    ) {
        collect_json_key_changes("", &left_json, &right_json, &mut lines, 12);
    }
    for token in ["session", "csrf", "nonce", "timestamp", "trace", "request_id", "token"] {
        if left.to_ascii_lowercase().contains(token) && right.to_ascii_lowercase().contains(token) {
            lines.push(format!("token/noise hint present: {token}"));
        }
    }
    lines.join("\n")
}

fn http_status_hint(value: &str) -> Option<u16> {
    value
        .lines()
        .next()
        .and_then(|line| {
            if line.starts_with("HTTP/") {
                line.split_whitespace().nth(1)?.parse().ok()
            } else {
                None
            }
        })
}

fn parse_http_headers_text(value: &str) -> Vec<(String, String)> {
    let normalized = value.replace("\r\n", "\n");
    let head = normalized.split_once("\n\n").map(|(head, _)| head).unwrap_or(normalized.as_str());
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':').map(|(name, value)| (name.trim().to_string(), value.trim().to_string())))
        .collect()
}

fn is_security_interesting_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "set-cookie"
            | "location"
            | "www-authenticate"
            | "x-admin"
            | "x-role"
            | "content-type"
            | "content-length"
            | "access-control-allow-origin"
            | "content-security-policy"
            | "x-frame-options"
    )
}

fn body_like_text(value: &str) -> &str {
    value
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .or_else(|| value.split_once("\n\n").map(|(_, body)| body))
        .unwrap_or(value)
}

fn collect_json_key_changes(prefix: &str, left: &serde_json::Value, right: &serde_json::Value, lines: &mut Vec<String>, limit: usize) {
    if lines.len() > limit {
        return;
    }
    match (left, right) {
        (serde_json::Value::Object(left_map), serde_json::Value::Object(right_map)) => {
            for (key, left_value) in left_map {
                let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
                if let Some(right_value) = right_map.get(key) {
                    collect_json_key_changes(&path, left_value, right_value, lines, limit);
                } else {
                    lines.push(format!("JSON key removed in right: {path}"));
                }
            }
            for key in right_map.keys() {
                if !left_map.contains_key(key) {
                    let path = if prefix.is_empty() { key.clone() } else { format!("{prefix}.{key}") };
                    lines.push(format!("JSON key added in right: {path}"));
                }
            }
        }
        _ if left != right && is_interesting_json_path(prefix) => {
            lines.push(format!("JSON value changed at {prefix}: {left} -> {right}"));
        }
        _ => {}
    }
}

fn is_interesting_json_path(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    ["role", "admin", "is_admin", "user_id", "userid", "tenant", "org", "permission", "scope", "status", "email"]
        .iter()
        .any(|needle| path.contains(needle))
}

fn decoder_heuristic_summary(input: &str) -> String {
    let trimmed = input.trim();
    let mut lines = Vec::new();
    if trimmed.is_empty() {
        return "Input is empty".to_string();
    }
    if trimmed.split('.').count() == 3 && DecoderTransform::JwtDecode.apply(trimmed.as_bytes()).is_ok() {
        lines.push("possible JWT: three dot-separated base64url JSON segments".to_string());
    }
    if trimmed.contains('%') {
        lines.push("contains percent signs: possible URL encoding".to_string());
    }
    if trimmed.contains("&lt;") || trimmed.contains("&gt;") || trimmed.contains("&amp;") || trimmed.contains("&#") {
        lines.push("contains HTML entity markers".to_string());
    }
    let hex_like = trimmed.len() % 2 == 0 && trimmed.len() >= 8 && trimmed.chars().all(|ch| ch.is_ascii_hexdigit());
    if hex_like {
        let hash_hint = match trimmed.len() {
            32 => "; length also matches MD5 hash",
            64 => "; length also matches SHA-256 hash",
            _ => "",
        };
        lines.push(format!("hex-like input{hash_hint}"));
        if DecoderTransform::HexDecode.apply(trimmed.as_bytes()).is_ok() {
            lines.push("hex decode appears syntactically valid".to_string());
        }
    }
    let b64_chars = trimmed.chars().all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'));
    if b64_chars && trimmed.len() >= 8 {
        if DecoderTransform::Base64Decode.apply(trimmed.as_bytes()).is_ok() {
            lines.push("standard Base64 decode appears syntactically valid".to_string());
        }
    }
    if serde_json::from_str::<serde_json::Value>(trimmed).is_ok() {
        lines.push("input is already valid JSON".to_string());
    }
    if lines.is_empty() {
        lines.push("no strong local encoding signal detected".to_string());
    }
    lines.join("\n")
}

fn parse_scope_rule_proposal(content: &str) -> ScopeRuleProposal {
    if let Ok(proposal) = serde_json::from_str::<ScopeRuleProposal>(content) {
        return proposal;
    }

    if let Some(json) = extract_json_object(content) {
        if let Ok(proposal) = serde_json::from_str::<ScopeRuleProposal>(json) {
            return proposal;
        }
    }

    ScopeRuleProposal {
        summary: "AI returned an unstructured scope response.".to_string(),
        warnings: vec!["Could not parse structured scope proposal; no rules can be applied.".to_string()],
        raw_text: Some(content.trim().to_string()),
        ..ScopeRuleProposal::default()
    }
}

fn normalize_scope_rule_proposal(mut proposal: ScopeRuleProposal) -> Result<ScopeRuleProposal, String> {
    let mut valid_rules = Vec::new();
    let mut warnings = std::mem::take(&mut proposal.warnings);
    for mut rule in std::mem::take(&mut proposal.rules) {
        rule.rule_type = match rule.rule_type.to_ascii_lowercase().as_str() {
            "exclude" => "exclude".to_string(),
            _ => "include".to_string(),
        };
        if rule.pattern.trim().is_empty() {
            continue;
        }
        ScopeEngine::validate(&rule.pattern)
            .map_err(|error| format!("invalid regex {}: {error}", rule.pattern))?;
        if is_overbroad_scope_pattern(&rule.pattern) {
            warnings.push(format!("Potentially broad scope regex: {}", rule.pattern));
        }
        valid_rules.push(rule);
    }
    if valid_rules.is_empty() {
        return Err("AI proposal did not include any valid scope rules".to_string());
    }
    if proposal.summary.trim().is_empty() {
        proposal.summary = "AI-generated scope rule proposal".to_string();
    }
    proposal.rules = valid_rules;
    proposal.warnings = warnings;
    Ok(proposal)
}

fn is_overbroad_scope_pattern(pattern: &str) -> bool {
    let compact = pattern.replace(' ', "").to_ascii_lowercase();
    matches!(compact.as_str(), ".*" | "^.*$" | "https?://.*" | "^https?://.*")
        || compact.contains("https?://.*")
}

fn normalize_intruder_attack_plan(mut plan: IntruderAttackPlan) -> Result<IntruderAttackPlan, String> {
    if plan.marked_request.trim().is_empty() {
        return Err("AI plan did not include marked_request".to_string());
    }
    if parse_positions(&plan.marked_request).is_empty() {
        return Err("AI plan did not include any §position§ markers".to_string());
    }
    normalize_raw_http_request(&strip_intruder_markers(&plan.marked_request))?;
    plan.payload_sets = normalize_plan_payload_sets(plan.payload_sets);
    if plan.payload_sets.is_empty() {
        return Err("AI plan did not include any safe payload sets".to_string());
    }
    if plan.plan_name.trim().is_empty() {
        plan.plan_name = "AI Intruder Attack Plan".to_string();
    }
    if plan.recommended_attack_type.trim().is_empty() {
        plan.recommended_attack_type = "Sniper".to_string();
    }
    if parse_attack_type_label(&plan.recommended_attack_type) == Some(AttackType::ClusterBomb) {
        plan.warnings.push("Cluster Bomb can create many requests; review total request count before pressing F5.".to_string());
    }
    if let Some(rps) = plan.recommended_rps {
        if rps > 10 {
            plan.warnings.push(format!("Recommended RPS {rps} was capped to 10 when applied."));
        }
    }
    if plan.safety_notes.is_empty() {
        plan.safety_notes.push("Draft only: attack is not started automatically.".to_string());
        plan.safety_notes.push("Review authorization, scope, and request volume before pressing F5.".to_string());
    }
    Ok(plan)
}

fn normalize_plan_payload_sets(sets: Vec<IntruderPlanPayloadSet>) -> Vec<IntruderPlanPayloadSet> {
    sets.into_iter()
        .enumerate()
        .filter_map(|(index, mut set)| {
            let (safe_payloads, blocked_payloads) = filter_destructive_payloads(set.payloads);
            set.payloads = dedupe_payloads(safe_payloads);
            set.blocked_payloads.extend(blocked_payloads);
            if set.payloads.is_empty() {
                return None;
            }
            if set.name.trim().is_empty() {
                set.name = format!("AI Set {}", index + 1);
            }
            Some(set)
        })
        .collect()
}

fn strip_intruder_markers(request: &str) -> String {
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

fn parse_attack_type_label(value: &str) -> Option<AttackType> {
    let value = value
        .to_ascii_lowercase()
        .replace(' ', "")
        .replace('-', "")
        .replace('_', "");
    if value.contains("batteringram") {
        Some(AttackType::BatteringRam)
    } else if value.contains("pitchfork") {
        Some(AttackType::Pitchfork)
    } else if value.contains("clusterbomb") {
        Some(AttackType::ClusterBomb)
    } else if value.contains("sniper") {
        Some(AttackType::Sniper)
    } else {
        None
    }
}

fn normalize_intruder_payload_suggestion(mut suggestion: IntruderPayloadSuggestion) -> IntruderPayloadSuggestion {
    let (safe_payloads, blocked_payloads) = filter_destructive_payloads(suggestion.payloads);
    suggestion.payloads = dedupe_payloads(safe_payloads);
    if !blocked_payloads.is_empty() {
        let blocked_count = blocked_payloads.len();
        suggestion.blocked_payloads.extend(blocked_payloads);
        suggestion.warnings.push(format!(
            "Blocked {blocked_count} destructive or high-risk payloads because destructive payloads are disabled by default."
        ));
    }
    if suggestion.category.trim().is_empty() {
        suggestion.category = "Custom".to_string();
    }
    suggestion.safe_only = true;
    if suggestion.safety_notes.is_empty() {
        suggestion
            .safety_notes
            .push("Destructive payloads are disabled; payloads are not run automatically.".to_string());
        suggestion
            .safety_notes
            .push("Review scope and authorization, then press F5 manually only if permitted.".to_string());
    }
    suggestion
}

fn dedupe_payloads(payloads: Vec<String>) -> Vec<String> {
    let mut output = Vec::new();
    for payload in payloads {
        let payload = payload.trim().to_string();
        if payload.is_empty() {
            continue;
        }
        if !output.iter().any(|existing: &String| existing == &payload) {
            output.push(payload);
        }
    }
    output
}

fn filter_destructive_payloads(payloads: Vec<String>) -> (Vec<String>, Vec<String>) {
    let mut safe = Vec::new();
    let mut blocked = Vec::new();
    for payload in payloads {
        if is_destructive_payload(&payload) {
            blocked.push(payload);
        } else {
            safe.push(payload);
        }
    }
    (safe, blocked)
}

fn is_destructive_payload(payload: &str) -> bool {
    let value = payload.to_ascii_lowercase();
    let dangerous_needles = [
        "rm -rf",
        "mkfs",
        "shutdown",
        "reboot",
        ":(){",
        "/dev/tcp",
        "bash -i",
        "powershell",
        "invoke-webrequest",
        "netcat",
        "nc -",
        "curl http",
        "wget http",
        "drop table",
        "delete from",
        "update users",
        "insert into",
        "xp_cmdshell",
        "169.254.169.254",
        "metadata.google.internal",
        "100.100.100.200",
        "/etc/shadow",
    ];
    dangerous_needles.iter().any(|needle| value.contains(needle))
}

fn extract_json_object(content: &str) -> Option<&str> {
    let start = content.find('{')?;
    let end = content.rfind('}')?;
    (end > start).then_some(&content[start..=end])
}

fn ai_flow_explainer_system_prompt() -> String {
    r#"You are Proxima Flow Explainer, a local AI analyst for authorized web security testing.
Return ONLY valid JSON. Do not use markdown fences or prose outside JSON.
Sensitive values are redacted; never reconstruct or expose secrets.
Do not claim a vulnerability is confirmed unless the evidence is explicit. Prefer phrases like "interesting", "possible", or "worth checking".
Keep next steps safe and manual; do not recommend destructive, denial-of-service, credential stuffing, persistence, or data-modifying actions.

Required JSON shape:
{
  "purpose": "What this request appears to do in plain language.",
  "request_summary": "Short summary of method, endpoint, body/content type, and likely workflow.",
  "headers_meaning": [
    {"header": "Header-Name", "meaning": "Why this header matters", "evidence": "Observed evidence"}
  ],
  "cookies_session_tokens": "Explain cookie/session/token role without exposing values.",
  "suspicious_parameters": [
    {"name": "param", "reason": "Why it is interesting", "confidence": "low|medium|high", "evidence": "Observed evidence"}
  ],
  "interesting_endpoints": [
    {"endpoint": "/path", "reason": "Why the endpoint matters", "evidence": "Observed evidence"}
  ],
  "auth_observations": "Auth-related observations such as login, JWT, bearer token, CSRF, session cookie, redirects, or missing auth context.",
  "response_tech_hints": ["Server/framework/content-type/token/status hints from the response"],
  "risk_notes": "Potential risks or testing ideas stated carefully with uncertainty.",
  "safe_next_steps": ["Safe manual next step only"],
  "confidence": 0.0
}
Use confidence as a number between 0.0 and 1.0."#
        .to_string()
}

fn ai_finding_triage_system_prompt() -> String {
    r#"You are Proxima Vulnerability Triage, a local AI analyst for authorized web security assessment.
Return ONLY valid JSON. Do not use markdown fences or prose outside JSON.
Your job is to prioritize passive scanner findings using the provided evidence and related HTTP context.
Do not blindly accept scanner severity. Do not overclaim. A missing header is not automatically an exploitable vulnerability.
If evidence is insufficient, say so and lower confidence. Never expose or reconstruct secrets.
Keep validation steps safe and manual. Do not suggest destructive actions, denial of service, credential attacks, persistence, or data modification.

Priority guidance:
P0 = confirmed critical impact with strong evidence.
P1 = high business/security impact or clear exploit path.
P2 = meaningful risk that needs timely remediation.
P3 = low/context-dependent risk or defense-in-depth weakness.
P4 = informational, hygiene, likely false positive, or needs more context.

Required JSON shape:
{
  "priority": "P0|P1|P2|P3|P4",
  "priority_label": "Critical|High|Medium|Low|Informational|Needs review",
  "real_risk": "What the actual risk is in this app context, with uncertainty where needed.",
  "false_positive_likelihood": "unlikely|possible|likely|unknown",
  "false_positive_reason": "Why this may or may not be a false positive or low-impact finding.",
  "exploitability": "low|medium|high|unknown",
  "proof_explanation": "Explain the observed proof using only provided evidence.",
  "impact": "Potential impact if the preconditions are true.",
  "remediation": "Specific remediation guidance.",
  "report_summary": "Concise report-ready summary suitable for a security report.",
  "safe_validation_steps": ["Safe manual validation step"],
  "confidence": 0.0
}
Use confidence as a number between 0.0 and 1.0."#
        .to_string()
}

fn ai_repeater_builder_system_prompt() -> String {
    r#"You are Proxima AI Request Builder for authorized web security testing.
Return ONLY valid JSON. Do not use markdown fences or prose outside JSON.
You modify raw HTTP requests based on the user's instruction, but you never send traffic.
Preserve placeholders such as {{PRESERVE_HEADER_AUTHORIZATION}} and {{PRESERVE_HEADER_COOKIE}} exactly unless the user explicitly asks to remove that header. Never invent secrets, cookies, API keys, CSRF tokens, bearer tokens, or credentials.
Keep method, host, path, and authorization context unchanged unless the user explicitly asks to change them.
Prefer safe, reversible testing drafts. For SQL injection, use non-destructive test payloads only. For CSRF tests, produce a candidate request and do not claim bypass. For GraphQL, use valid JSON and preserve auth/session headers.
Always output a complete raw HTTP request with a request line, Host header when needed, headers, blank line, and body if present.

Required JSON shape:
{
  "modified_request": "POST /path HTTP/1.1\nHost: example.com\nContent-Type: application/json\n\n{...}",
  "change_summary": ["What changed and why"],
  "safety_notes": ["Draft only; user must review and send manually"],
  "preserved_sensitive_items": ["Authorization", "Cookie"],
  "warnings": ["Any uncertainty or scope/auth warning"],
  "confidence": 0.0
}
Use confidence as a number between 0.0 and 1.0."#
        .to_string()
}

fn ai_intruder_payload_generator_system_prompt() -> String {
    r#"You are Proxima AI Payload Generator for authorized web security testing.
Return ONLY valid JSON. Do not use markdown fences or prose outside JSON.
Generate concise Intruder payload lists for the marked §position§ values in the request.
Destructive payloads are disabled by default. Do NOT include payloads that delete/write data, cause denial of service, create reverse shells, exfiltrate data, access cloud metadata services, run credential attacks, or use destructive SQL/OS commands.
Command-injection payloads must be safe markers only, such as echoing PROXIMA_TEST. SSRF payloads must use safe test URLs or clearly non-routable placeholders. SQL injection payloads must be non-destructive. XSS payloads should prefer harmless markers by default.
Never start an attack; payloads are only suggestions that the user must review and manually apply.

Supported categories include SQLi, XSS markers, IDOR IDs, path traversal, JWT alg confusion values, command injection safe markers, Unicode bypass payloads, SSRF safe test URLs, and custom safe payloads.

Required JSON shape:
{
  "category": "SQLi|XSS|IDOR|Path Traversal|JWT|Command Injection Safe|Unicode Bypass|SSRF|Custom",
  "safe_only": true,
  "target_parameter_hint": "Where these payloads appear intended to go",
  "payloads": ["payload1", "payload2"],
  "rationale": ["Why these values are useful"],
  "safety_notes": ["Payloads are not run automatically", "Confirm scope and authorization"],
  "warnings": ["Any uncertainty or caution"],
  "recommended_attack_type": "Sniper|Battering Ram|Pitchfork|Cluster Bomb",
  "recommended_rps": 5,
  "confidence": 0.0
}
Use confidence as a number between 0.0 and 1.0."#
        .to_string()
}

fn ai_intruder_attack_planner_system_prompt() -> String {
    r#"You are Proxima AI Intruder Attack Planner for authorized web security testing.
Return ONLY valid JSON. Do not use markdown fences or prose outside JSON.
Your job is to create a draft Intruder setup: detect fuzzable parameters, add §position§ markers, recommend an attack type, choose safe payload sets, and explain expected result signals.
Never start an attack. Do not generate destructive payloads. Do not fuzz Authorization, Cookie, session, API key, CSRF token, or other secrets by default. Preserve placeholders such as {{PRESERVE_HEADER_AUTHORIZATION_1}} exactly.
Prefer low-volume safe plans. Use Sniper for first-pass fuzzing, Battering Ram when the same value belongs in repeated positions, Pitchfork for paired small payload sets, and Cluster Bomb only with explicit combinational need and strong warnings.
For state-changing methods such as POST, PUT, PATCH, or DELETE, include a warning. Recommended RPS should be 1-5 unless there is a clear reason.

Required JSON shape:
{
  "plan_name": "Short descriptive plan name",
  "marked_request": "Full raw HTTP request with §value§ markers around selected fuzzing positions",
  "detected_parameters": [
    {"name": "user_id", "location": "query|path|json_body|form_body|header", "reason": "Why it is interesting", "risk_hint": "IDOR/auth/input validation/etc"}
  ],
  "recommended_attack_type": "Sniper|Battering Ram|Pitchfork|Cluster Bomb",
  "attack_type_reason": "Why this type is recommended",
  "payload_sets": [
    {"name": "user_id IDOR candidates", "position_hint": "user_id", "payloads": ["0", "1", "2"]}
  ],
  "expected_result_columns": ["Status", "Length", "Time", "Error", "Payload"],
  "success_indicators": ["What anomalies to watch for"],
  "safety_notes": ["Draft only; attack not started", "Review scope before F5"],
  "warnings": ["State-changing request or volume warnings"],
  "recommended_rps": 5,
  "confidence": 0.0
}
Use confidence as a number between 0.0 and 1.0."#
        .to_string()
}

fn ai_scope_assistant_system_prompt() -> String {
    r#"You are Proxima AI Scope Assistant for an authorized web security testing tool.
Return ONLY valid JSON. Do not use markdown fences or prose outside JSON.
Convert natural-language scope instructions into precise regex rules. Scope controls what traffic and active scanning are allowed, so be conservative and avoid broad matches.
Prefer anchored URL regexes such as ^https?://example\.com(?:/|$). Escape dots in domains. Avoid patterns that match arbitrary domains or URL query text. Do not auto-apply anything.
Generate include/exclude rules, test cases with expected results, warnings for broad or lossy rules, and a confidence score. For "only" or "sirf" instructions, set replace_existing=true, but still let the user choose append or replace.
If excluding static assets, warn that JavaScript files can contain useful endpoint references.

Required JSON shape:
{
  "summary": "What this proposal does",
  "replace_existing": false,
  "rules": [
    {"rule_type": "include|exclude", "pattern": "^https?://example\\.com(?:/|$)", "reason": "Why this rule exists"}
  ],
  "test_cases": [
    {"url": "https://example.com/login", "expected_in_scope": true, "reason": "Apex domain included"}
  ],
  "warnings": ["Caveats or broad-match warnings"],
  "confidence": 0.0
}
Use confidence as a number between 0.0 and 1.0."#
        .to_string()
}

fn ai_passive_rule_generator_system_prompt() -> String {
    r#"You are Proxima AI Passive Scanner Rule Generator for an authorized web security testing tool.
Return ONLY valid JSON. Do not use markdown fences or prose outside JSON unless the YAML string itself requires newlines.
Generate a single passive scanner issue definition YAML using ONLY the supported schema and passive check types.
Supported severities: info, low, medium, high, critical. Supported confidence: tentative, firm, certain. Prefer conservative severity/confidence.
Supported passive_checks only:
- type: header_missing  with name
- type: header_contains with name and value_regex
- type: body_regex      with pattern
- type: status_code     with codes
Do not invent unsupported check types, Boolean logic, request-side checks, active probes, or destructive behavior.
The YAML id must be lowercase kebab-case. Keep regexes valid for Rust regex. Add references if useful, otherwise references: [].

Required JSON shape:
{
  "rule_id": "debug-header-disclosure",
  "filename": "debug-header-disclosure.yaml",
  "yaml": "id: debug-header-disclosure\nname: Debug header disclosure\nseverity: low\nconfidence: firm\npassive_checks:\n  - type: header_contains\n    name: x-debug\n    value_regex: \".+\"\nreferences: []\nenabled: true\n",
  "explanation": "What this rule detects and what it does not prove",
  "test_examples": [
    {"description": "Should match", "response_headers": "X-Debug: true", "response_body": "", "expected_match": true}
  ],
  "warnings": ["Presence alone may be low risk unless sensitive data is exposed"],
  "confidence": 0.0
}"#
        .to_string()
}

fn ai_comparer_summary_system_prompt() -> String {
    r#"You are Proxima AI Difference Analyst for authorized web security testing.
Return ONLY valid JSON. Do not use markdown fences or prose outside JSON.
Summarize differences between left and right inputs in natural language. Separate observed changes from security interpretation. Do not claim IDOR/auth bypass is confirmed unless the evidence is sufficient; use terms like possible/candidate when request context is missing.
Prioritize high-signal changes: HTTP status changes, auth/role/admin fields, user_id/tenant/org changes, security headers, Set-Cookie/Location changes, and error-vs-success body differences. Identify likely noise such as session tokens, CSRF tokens, nonces, timestamps, trace IDs, and request IDs.

Required JSON shape:
{
  "summary": "Short natural language summary of the most important difference",
  "high_signal_changes": [
    {"change": "Status changed 403 to 200", "security_relevance": "Possible authorization boundary difference", "evidence": "HTTP status line"}
  ],
  "likely_noise": ["Session token value changed"],
  "security_interpretation": "What this may mean for IDOR/auth bypass testing, with uncertainty",
  "suggested_next_steps": ["Replay both requests with only one variable changed"],
  "risk_hint": "none|likely_noise|possible_idor|possible_auth_bypass|possible_privilege_change|server_error_signal|content_change|header_security_change",
  "confidence": 0.0
}
Use confidence as a number between 0.0 and 1.0."#
        .to_string()
}

fn ai_decoder_chain_builder_system_prompt() -> String {
    r#"You are Proxima AI Decode Assistant for a local decoder tab.
Return ONLY valid JSON. Do not use markdown fences or prose outside JSON.
Suggest a decoder transform chain for the provided input sample. Prefer decode/format transforms: UrlDecode, Base64Decode, HexDecode, HtmlDecode, JwtDecode, JsonPrettyPrint. Do not suggest hashing or encoding unless the input clearly asks for it; this workflow is primarily for decoding unknown blobs.
JWT decoding does not verify signatures. Hash-looking values such as MD5/SHA-256 are one-way and should usually return no suggested_chain plus a warning.
Use only these transform names: Base64Decode, HexDecode, UrlDecode, HtmlDecode, JwtDecode, JsonPrettyPrint, Base64Encode, HexEncode, UrlEncode, Sha256, Md5.

Required JSON shape:
{
  "detected_type": "JWT|Base64 JSON|URL encoded|Hex JSON|HTML entities|Hash|Unknown",
  "summary": "Brief explanation of what the input appears to be",
  "suggested_chain": [
    {"transform": "JwtDecode", "reason": "Three dot-separated base64url JSON segments"}
  ],
  "expected_output": "What the user should see after applying the chain",
  "warnings": ["JWT signature is not verified"],
  "confidence": 0.0
}
Use confidence as a number between 0.0 and 1.0."#
        .to_string()
}

fn priority_rank(value: &str) -> u8 {
    let value = value.trim().to_ascii_lowercase();
    if value.starts_with("p0") || value.contains("critical") {
        0
    } else if value.starts_with("p1") || value.contains("high") {
        1
    } else if value.starts_with("p2") || value.contains("medium") {
        2
    } else if value.starts_with("p3") || value.contains("low") {
        3
    } else if value.starts_with("p4") || value.contains("info") {
        4
    } else {
        90
    }
}

fn priority_label(priority: &str) -> &'static str {
    match priority_rank(priority) {
        0 => "Critical",
        1 => "High",
        2 => "Medium",
        3 => "Low",
        4 => "Informational",
        _ => "Needs review",
    }
}

fn priority_from_label(label: &str) -> &'static str {
    match priority_rank(label) {
        0 => "P0",
        1 => "P1",
        2 => "P2",
        3 => "P3",
        4 => "P4",
        _ => "P4",
    }
}

fn ai_system_prompt() -> String {
    "You are Proxima AI Analyst, a local assistant for authorized web security testing. \
    Be practical, concise, and careful. Never claim a vulnerability is confirmed unless evidence is sufficient. \
    Do not suggest destructive, denial-of-service, credential stuffing, persistence, or data-modifying actions. \
    Prefer safe manual tests inside scope. Structure answers with: Summary, Observations, Potential Risks, Safe Next Steps, Confidence. \
    If suggesting tool actions, mark them as suggestions only and require user confirmation."
        .to_string()
}

fn ai_context_from_flow(flow: &HttpFlow, redact: bool, max_chars: usize) -> AiContext {
    let mut request_headers = String::new();
    for (name, value) in flow.request_headers.iter() {
        request_headers.push_str(name.as_str());
        request_headers.push_str(": ");
        request_headers.push_str(&redact_header_value(name.as_str(), value.to_str().unwrap_or("<binary>"), redact));
        request_headers.push('\n');
    }
    let mut response_headers = String::new();
    if let Some(headers) = &flow.response_headers {
        for (name, value) in headers.iter() {
            response_headers.push_str(name.as_str());
            response_headers.push_str(": ");
            response_headers.push_str(&redact_header_value(name.as_str(), value.to_str().unwrap_or("<binary>"), redact));
            response_headers.push('\n');
        }
    }

    let request_body = redact_body(&String::from_utf8_lossy(&flow.request_body), redact);
    let response_body = flow
        .response_body
        .as_ref()
        .map(|body| redact_body(&String::from_utf8_lossy(body), redact))
        .unwrap_or_default();
    let summary = format!(
        "Flow #{}\nMethod: {}\nURL: {}\nStatus: {}\nHost: {}\nPath: {}\nResponse length: {} bytes\nRedaction: {}",
        flow.id,
        flow.method,
        flow.uri,
        flow.status.map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string()),
        flow.host(),
        flow.path(),
        flow.response_len(),
        if redact { "enabled" } else { "disabled" }
    );
    let raw = format!(
        "REQUEST HEADERS\n{}\nREQUEST BODY PREVIEW\n{}\n\nRESPONSE HEADERS\n{}\nRESPONSE BODY PREVIEW\n{}",
        request_headers,
        request_body.chars().take(4_000).collect::<String>(),
        response_headers,
        response_body.chars().take(6_000).collect::<String>(),
    );
    AiContext {
        title: format!("Flow #{} {} {}", flow.id, flow.method, flow.path()),
        summary,
        redacted_raw: raw.chars().take(max_chars).collect(),
    }
}

fn redact_header_value(name: &str, value: &str, redact: bool) -> String {
    if !redact {
        return value.to_string();
    }
    let name = name.to_ascii_lowercase();
    if matches!(name.as_str(), "authorization" | "cookie" | "set-cookie" | "x-api-key" | "x-csrf-token") {
        "REDACTED".to_string()
    } else {
        value.to_string()
    }
}

fn redact_body(value: &str, redact: bool) -> String {
    if !redact {
        return value.to_string();
    }
    let mut output = value.to_string();
    for key in ["password", "passwd", "token", "secret", "api_key", "apikey", "access_token", "refresh_token"] {
        output = redact_jsonish_key(&output, key);
    }
    output
}

fn redact_jsonish_key(input: &str, key: &str) -> String {
    let mut output = String::new();
    for line in input.lines() {
        if line.to_ascii_lowercase().contains(key) {
            output.push_str(key);
            output.push_str(": REDACTED\n");
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    output
}

fn findings_html(findings: &[Finding]) -> String {
    let mut rows = String::new();
    for finding in findings {
        rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>\n",
            finding.severity.label(),
            finding.confidence.label(),
            html_escape(&finding.issue_name),
            html_escape(&finding.url),
            html_escape(&finding.evidence_json),
        ));
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Proxima Findings</title><style>body{{font-family:sans-serif}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:4px}}th{{background:#eee}}</style></head><body><h1>Proxima Passive Scanner Findings</h1><table><thead><tr><th>Severity</th><th>Confidence</th><th>Issue</th><th>URL</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></body></html>"
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn default_intruder_request() -> String {
    "GET /get?candidate=§test§ HTTP/1.1\nHost: httpbin.org\nUser-Agent: Proxima-Intruder\nAccept: */*\n\n".to_string()
}

fn default_repeater_request() -> String {
    "GET /get HTTP/1.1\nHost: httpbin.org\nUser-Agent: Proxima-TUI\nAccept: */*\n\n".to_string()
}

fn flow_compare_text(flow: &HttpFlow) -> String {
    if let Some(body) = &flow.response_body {
        String::from_utf8_lossy(body).into_owned()
    } else {
        raw_request_from_flow(flow)
    }
}

fn raw_request_from_flow(flow: &HttpFlow) -> String {
    let mut output = format!("{} {} HTTP/1.1\n", flow.method, flow.path());
    for (name, value) in flow.request_headers.iter() {
        output.push_str(name.as_str());
        output.push_str(": ");
        output.push_str(value.to_str().unwrap_or("<binary>"));
        output.push('\n');
    }
    output.push('\n');
    output.push_str(&String::from_utf8_lossy(&flow.request_body));
    output
}

fn redact_repeater_request_for_ai(raw: &str) -> (String, Vec<(String, String)>, Vec<String>) {
    let normalized = raw.replace("\r\n", "\n");
    let (head, body) = normalized
        .split_once("\n\n")
        .map(|(head, body)| (head, body))
        .unwrap_or((normalized.as_str(), ""));
    let mut output = String::new();
    let mut preserved_values = Vec::new();
    let mut preserved_names = Vec::new();

    for (line_index, line) in head.lines().enumerate() {
        if line_index == 0 || !line.contains(':') {
            output.push_str(line);
            output.push('\n');
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            output.push_str(line);
            output.push('\n');
            continue;
        };
        if is_sensitive_request_header(name.trim()) {
            let placeholder = format!(
                "{{{{PRESERVE_HEADER_{}_{}}}}}",
                sanitize_placeholder_name(name.trim()),
                preserved_values.len() + 1
            );
            output.push_str(name.trim());
            output.push_str(": ");
            output.push_str(&placeholder);
            output.push('\n');
            preserved_values.push((placeholder, value.trim().to_string()));
            if !preserved_names.iter().any(|existing: &String| existing.eq_ignore_ascii_case(name.trim())) {
                preserved_names.push(name.trim().to_string());
            }
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    output.push('\n');
    output.push_str(&redact_body(body, true));
    (output, preserved_values, preserved_names)
}

fn restore_repeater_placeholders(raw: &str, preserved_values: &[(String, String)]) -> String {
    let mut restored = raw.to_string();
    for (placeholder, value) in preserved_values {
        restored = restored.replace(placeholder, value);
    }
    restored
}

fn is_sensitive_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "cookie"
            | "x-api-key"
            | "api-key"
            | "x-csrf-token"
            | "x-xsrf-token"
            | "csrf-token"
            | "x-auth-token"
            | "proxy-authorization"
    )
}

fn sanitize_placeholder_name(name: &str) -> String {
    name.chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch.to_ascii_uppercase() } else { '_' })
        .collect()
}

fn request_contains_header(raw: &str, header_name: &str) -> bool {
    let normalized = raw.replace("\r\n", "\n");
    let head = normalized.split_once("\n\n").map(|(head, _)| head).unwrap_or(normalized.as_str());
    head.lines().skip(1).any(|line| {
        line.split_once(':')
            .map(|(name, _)| name.trim().eq_ignore_ascii_case(header_name))
            .unwrap_or(false)
    })
}

fn normalize_raw_http_request(raw: &str) -> Result<String, String> {
    let normalized = raw.replace("\r\n", "\n");
    let (head, body) = normalized
        .split_once("\n\n")
        .map(|(head, body)| (head, body))
        .unwrap_or((normalized.as_str(), ""));
    let mut lines = head.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?
        .trim();
    let parts = request_line.split_whitespace().collect::<Vec<_>>();
    if parts.len() < 2 {
        return Err("request line must include METHOD and target".to_string());
    }
    let method = parts[0];
    let target = parts[1];
    let version = parts.get(2).copied().unwrap_or("HTTP/1.1");
    if !version.starts_with("HTTP/") {
        return Err("request line must include a valid HTTP version".to_string());
    }

    let mut headers = Vec::new();
    let mut has_host = false;
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("invalid header line: {line}"))?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        if name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        headers.push((name.to_string(), value.to_string()));
    }

    if !(target.starts_with("http://") || target.starts_with("https://")) && !has_host {
        return Err("origin-form request requires Host header".to_string());
    }

    let mut output = format!("{method} {target} {version}\n");
    for (name, value) in headers {
        output.push_str(&name);
        output.push_str(": ");
        output.push_str(&value);
        output.push('\n');
    }
    if !body.is_empty() {
        output.push_str("Content-Length: ");
        output.push_str(&body.as_bytes().len().to_string());
        output.push('\n');
    }
    output.push('\n');
    output.push_str(body);
    Ok(output)
}

async fn send_raw_request(raw: String) -> Result<HttpResponse, String> {
    let parsed = ParsedRequest::parse(&raw)?;
    let started_at = Instant::now();
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| error.to_string())?;
    let method = reqwest::Method::from_bytes(parsed.method.as_bytes()).map_err(|e| e.to_string())?;
    let mut builder = client.request(method, parsed.url);
    for (name, value) in parsed.headers.iter() {
        if name.as_str().eq_ignore_ascii_case("host") {
            continue;
        }
        builder = builder.header(name, value);
    }
    let response = builder
        .body(parsed.body)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("").to_string();
    let headers = response.headers().clone();
    let body = response.bytes().await.map_err(|error| error.to_string())?;

    Ok(HttpResponse {
        status: status.as_u16(),
        reason,
        headers,
        body,
        duration_ms: started_at.elapsed().as_millis() as u64,
    })
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
        let (head, body) = normalized
            .split_once("\n\n")
            .map(|(head, body)| (head, body))
            .unwrap_or((normalized.as_str(), ""));
        let mut lines = head.lines();
        let request_line = lines.next().ok_or_else(|| "missing request line".to_string())?;
        let parts = request_line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 2 {
            return Err("request line must be METHOD PATH HTTP/VERSION".to_string());
        }
        let method = parts[0].to_string();
        let target = parts[1];
        let mut headers = HeaderMap::new();
        let mut host = None;
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| format!("invalid header line: {line}"))?;
            let name = hyper::header::HeaderName::from_bytes(name.trim().as_bytes())
                .map_err(|error| error.to_string())?;
            let value = hyper::header::HeaderValue::from_str(value.trim())
                .map_err(|error| error.to_string())?;
            if name.as_str().eq_ignore_ascii_case("host") {
                host = Some(value.to_str().unwrap_or_default().to_string());
            }
            headers.insert(name, value);
        }

        let url = if target.starts_with("http://") || target.starts_with("https://") {
            target.to_string()
        } else {
            let host = host.ok_or_else(|| "origin-form request requires Host header".to_string())?;
            format!("http://{host}{target}")
        };

        Ok(Self {
            method,
            url,
            headers,
            body: Bytes::copy_from_slice(body.as_bytes()),
        })
    }
}
