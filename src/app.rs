use std::{sync::Arc, time::Instant};

use bytes::Bytes;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use hyper::HeaderMap;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::{
    db::Database,
    db_writer::DbWriter,
    events::{Event, ProxyEvent, RepeaterEvent},
    models::{
        ai::{AiContext, AiEvent, AiMessage, AiPanelState, OllamaChatRequest, OllamaChatResponse, OllamaMessage, OllamaOptions, QUICK_PROMPTS},
        comparer::CompareMode,
        decoder::DecoderTransform,
        flow::HttpFlow,
        intruder::{parse_positions, AttackConfig, AttackType, IntruderEngine, IntruderEvent, IntruderResult, PayloadSet},
        repeater::{HttpResponse, RepeaterTab, SendHistoryEntry},
        scope::{ScopeEngine, ScopeRule, ScopeRuleType},
    },
    plugins::PluginManager,
    policy::{Decision as PolicyDecision, Policy, Traffic},
    proxy::{run_proxy, LoggingHandler, ProxyConfig},
    scanner::{run_safe_active_scan, ActiveScanTarget, ActiveScannerEvent, Confidence, Finding, PassiveScanner, Severity},
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
    pub search_mode: bool,
    pub search_query: String,
    pub terminal_size: (u16, u16),
    pub repeater_tabs: Vec<RepeaterTab>,
    pub active_repeater: usize,
    pub repeater_cursor: usize,
    pub repeater_response_scroll: u16,
    pub renaming_repeater: bool,
    pub rename_buffer: String,
    pub database: Database,
    pub db_writer: DbWriter,
    pub policy: Arc<Policy>,
    pub project_message: String,
    pub scope_engine: ScopeEngine,
    pub selected_scope_rule: usize,
    pub scope_input_mode: Option<ScopeInputMode>,
    pub scope_buffer: String,
    pub scope_test_url: String,
    pub last_scope_test_result: Option<bool>,
    pub intruder_request_text: String,
    pub intruder_attack_type: AttackType,
    pub intruder_payloads_text: String,
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
    pub comparer_left: String,
    pub comparer_right: String,
    pub comparer_mode: CompareMode,
    pub comparer_focus_right: bool,
    pub comparer_marked_flows: Vec<usize>,
    pub passive_scanner: PassiveScanner,
    pub findings: Vec<Finding>,
    pub selected_finding: usize,
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
        let mut database = Database::open_default().expect("failed to open default project database");
        if let Ok(Some(listen_addr)) = database.load_setting("proxy.listen_addr") {
            if let Ok(listen_addr) = listen_addr.parse() {
                proxy_config.listen_addr = listen_addr;
            }
        }
        let db_writer = DbWriter::spawn(database.path()).expect("failed to start database writer");
        let policy = Arc::new(Policy::load_default());
        let policy_line = policy.status_line();
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
        let project_message = format!(
            "Project: {} · {}",
            database.path().display(),
            policy_line
        );
        Self {
            current_tab: Tab::Proxy,
            should_quit: false,
            tick_count: 0,
            proxy_status: ProxyStatus::Stopped,
            proxy_message: format!(
                "Proxy ready on {} · {}",
                proxy_config.listen_addr, policy_line
            ),
            proxy_config,
            flow_store,
            selected_flow: None,
            request_scroll: 0,
            response_scroll: 0,
            search_mode: false,
            search_query: String::new(),
            terminal_size: (120, 40),
            repeater_tabs,
            active_repeater: 0,
            repeater_cursor,
            repeater_response_scroll: 0,
            renaming_repeater: false,
            rename_buffer: String::new(),
            database,
            db_writer,
            policy,
            project_message,
            scope_engine: ScopeEngine::new(scope_rules),
            selected_scope_rule: 0,
            scope_input_mode: None,
            scope_buffer: String::new(),
            scope_test_url: "https://example.com/".to_string(),
            last_scope_test_result: None,
            intruder_request_text: default_intruder_request(),
            intruder_attack_type: AttackType::Sniper,
            intruder_payloads_text: "admin\ntest\npassword\n123456".to_string(),
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
            comparer_left: String::new(),
            comparer_right: String::new(),
            comparer_mode: CompareMode::Line,
            comparer_focus_right: false,
            comparer_marked_flows: Vec::new(),
            passive_scanner: PassiveScanner::load_default(),
            findings,
            selected_finding: 0,
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
                    // Queued on the writer thread: a slow disk must not stall input.
                    self.db_writer.save_flow(&flow);
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
            ActiveScannerEvent::Blocked { target, reason } => {
                self.project_message = format!("Active scan blocked for {target}: {reason}");
                if let Some(item) = self
                    .active_scan_targets
                    .iter_mut()
                    .find(|item| item.url.as_str() == target.as_str())
                {
                    item.running = false;
                }
                self.active_scan_task = None;
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
        self.ai_panel.is_waiting = false;
        match event {
            AiEvent::Complete(Ok(answer)) => {
                self.ai_panel.status = "complete".to_string();
                self.ai_panel.messages.push(AiMessage::assistant(answer));
            }
            AiEvent::Complete(Err(error)) => {
                self.ai_panel.status = format!("error: {error}");
                self.ai_panel
                    .messages
                    .push(AiMessage::assistant(format!("AI request failed: {error}")));
            }
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

        match (key.code, key.modifiers) {
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
        match (key.code, key.modifiers) {
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
                if let Some(finding) = self.filtered_findings().get(self.selected_finding) {
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
        findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| b.id.cmp(&a.id)));
        findings
    }

    fn handle_decoder_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
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

    fn handle_comparer_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
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
                true
            }
            (KeyCode::Enter, _) => {
                if self.comparer_focus_right {
                    self.comparer_right.push('\n');
                } else {
                    self.comparer_left.push('\n');
                }
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                if self.comparer_focus_right {
                    self.comparer_right.push(char);
                } else {
                    self.comparer_left.push(char);
                }
                true
            }
            _ => false,
        }
    }

    fn handle_intruder_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
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
                true
            }
            (KeyCode::Backspace, _) => {
                self.intruder_request_text.pop();
                true
            }
            (KeyCode::Char(char), KeyModifiers::NONE) | (KeyCode::Char(char), KeyModifiers::SHIFT) => {
                self.intruder_request_text.push(char);
                true
            }
            _ => false,
        }
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
                _ => {}
            },
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
        let table_width = width.saturating_mul(40) / 100;
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
        self.proxy_task = Some(run_proxy(
            config,
            LoggingHandler,
            self.flow_store.clone(),
            Arc::clone(&self.policy),
        ));
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
        self.current_tab = Tab::Repeater;
        self.persist_repeater_tabs();
    }

    fn close_active_repeater(&mut self) {
        if self.repeater_tabs.len() <= 1 {
            if let Some(tab) = self.repeater_tabs.get_mut(0) {
                tab.request_text = default_repeater_request();
                tab.response = None;
                tab.error = None;
                tab.history.clear();
                tab.is_sending = false;
            }
            self.repeater_cursor = default_repeater_request().len();
            self.persist_repeater_tabs();
            return;
        }
        self.repeater_tabs.remove(self.active_repeater);
        self.active_repeater = self.active_repeater.min(self.repeater_tabs.len().saturating_sub(1));
        self.repeater_cursor = self
            .repeater_tabs
            .get(self.active_repeater)
            .map(|tab| tab.request_text.len())
            .unwrap_or_default();
        self.persist_repeater_tabs();
    }

    fn next_repeater_tab(&mut self) {
        if !self.repeater_tabs.is_empty() {
            self.active_repeater = (self.active_repeater + 1) % self.repeater_tabs.len();
            self.repeater_cursor = self.repeater_tabs[self.active_repeater].request_text.len();
        }
    }

    fn previous_repeater_tab(&mut self) {
        if !self.repeater_tabs.is_empty() {
            self.active_repeater =
                (self.active_repeater + self.repeater_tabs.len() - 1) % self.repeater_tabs.len();
            self.repeater_cursor = self.repeater_tabs[self.active_repeater].request_text.len();
        }
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
        let policy = Arc::clone(&self.policy);
        tokio::spawn(async move {
            let response = send_raw_request(request_text, policy).await;
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
        let payload_sets = match self.intruder_attack_type {
            AttackType::Pitchfork | AttackType::ClusterBomb => positions
                .iter()
                .enumerate()
                .map(|(index, _)| PayloadSet::simple(format!("Set {}", index + 1), payloads.clone()))
                .collect(),
            _ => vec![PayloadSet::simple("Payloads", payloads)],
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
        self.intruder_task = Some(IntruderEngine::spawn(
            config,
            self.intruder_tx.clone(),
            Arc::clone(&self.policy),
        ));
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
        } else if self.db_writer.failures() > 0 {
            self.project_message = format!(
                "Autosaved {} ({} flow write(s) failed - see logs)",
                self.database.path().display(),
                self.db_writer.failures()
            );
        } else {
            self.project_message = format!("Autosaved {}", self.database.path().display());
        }
    }

    fn save_project_as_env(&mut self) {
        let destination = std::env::var_os("PROXIMA_SAVE_AS")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| self.database.path().to_path_buf());
        self.autosave_project();
        // The copy must contain every queued flow, so drain the writer first.
        self.db_writer.flush();
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
                // Start the new writer before switching projects: if it cannot be
                // started we abort the open, because keeping the previous writer
                // would silently persist this project's flows into the old database.
                let writer = match DbWriter::spawn(database.path()) {
                    Ok(writer) => writer,
                    Err(error) => {
                        self.project_message = format!(
                            "Open failed: no flow persistence for {}: {error}",
                            database.path().display()
                        );
                        return;
                    }
                };
                self.db_writer.flush();
                self.database = database;
                self.db_writer = writer;
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
        let policy = Arc::clone(&self.policy);
        self.active_scan_task = Some(tokio::spawn(async move {
            run_safe_active_scan(url, tx, policy).await;
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
            .response_view()
            .map(|view| view.body)
            .unwrap_or_else(|| flow.request_view().body);
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
        // Blocking here is correct: leaving without the queue drained loses flows.
        self.db_writer.flush();
        self.policy.flush_audit();
        self.stop_proxy();
        self.should_quit = true;
    }
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

    // The analyst must see the same bytes a browser would, not the compressed wire form.
    let request_view = flow.request_view();
    let response_view = flow.response_view();
    let request_body = redact_body(&String::from_utf8_lossy(&request_view.body), redact);
    let response_body = response_view
        .as_ref()
        .map(|view| redact_body(&String::from_utf8_lossy(&view.body), redact))
        .unwrap_or_default();
    let codings = request_view
        .codings
        .iter()
        .chain(response_view.iter().flat_map(|view| view.codings.iter()))
        .cloned()
        .collect::<Vec<_>>();
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
    let summary = if codings.is_empty() {
        summary
    } else {
        format!("{summary}\nContent-Encoding decoded for analysis: {}", codings.join(", "))
    };
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
    match flow.response_view() {
        Some(view) => String::from_utf8_lossy(&view.body).into_owned(),
        None => raw_request_from_flow(flow),
    }
}

fn raw_request_from_flow(flow: &HttpFlow) -> String {
    // Repeater composes a fresh request, so a compressed captured body is decoded
    // once here and its `Content-Encoding`/`Content-Length` headers dropped, rather
    // than being replayed as bytes the origin would decode a second time.
    let view = flow.request_view();
    let headers = crate::net::decode::headers_for_decoded_body(&flow.request_headers, &view);
    let mut output = format!("{} {} HTTP/1.1\n", flow.method, flow.path());
    for (name, value) in headers.iter() {
        output.push_str(name.as_str());
        output.push_str(": ");
        output.push_str(value.to_str().unwrap_or("<binary>"));
        output.push('\n');
    }
    output.push('\n');
    output.push_str(&String::from_utf8_lossy(&view.body));
    output
}

async fn send_raw_request(raw: String, policy: Arc<Policy>) -> Result<HttpResponse, String> {
    let parsed = ParsedRequest::parse(&raw)?;
    if let PolicyDecision::Deny(reason) = policy.authorize(Traffic::Generated, &parsed.method, &parsed.url) {
        return Err(format!("blocked by engagement envelope: {reason}"));
    }
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
    // Generated traffic feeds the same halt conditions as proxied traffic: this is
    // where 429s and 5xx waves actually come from.
    policy.observe(status.as_u16());
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
