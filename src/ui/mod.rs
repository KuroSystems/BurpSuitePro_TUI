use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Tabs, Wrap},
    Frame,
};

mod active_tab;
mod ai_tab;
mod comparer_tab;
mod decoder_tab;
mod intruder_tab;
mod plugin_tab;
mod proxy_tab;
mod repeater_tab;
mod scanner_tab;
mod websocket_tab;

use crate::{
    app::{App, ScopeAiMode, Tab},
    models::{
        ai::{ScopeRuleProposal, ScopeRuleProposalState},
        scope::{ScopeEngine, ScopeRule, ScopeRuleType},
    },
};

pub fn render(frame: &mut Frame, app: &App) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(frame.area());

    render_tabs(frame, app, layout[0]);
    render_current_tab(frame, app, layout[1]);
    render_status_line(frame, app, layout[2]);
}

fn render_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles = Tab::ALL
        .iter()
        .map(|tab| Line::from(Span::styled(tab.title(), Style::default().fg(Color::Gray))))
        .collect::<Vec<_>>();

    let selected = Tab::ALL
        .iter()
        .position(|tab| *tab == app.current_tab)
        .unwrap_or_default();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title(" Proxima TUI ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .select(selected)
        .style(Style::default().fg(Color::Gray))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .divider(" │ ");

    frame.render_widget(tabs, area);
}

fn render_current_tab(frame: &mut Frame, app: &App, area: Rect) {
    match app.current_tab {
        Tab::Proxy => proxy_tab::render_proxy_tab(frame, app, area),
        Tab::Ai => ai_tab::render_ai_tab(frame, app, area),
        Tab::Repeater => repeater_tab::render_repeater_tab(frame, app, area),
        Tab::Scope => render_scope(frame, app, area),
        Tab::Intruder => intruder_tab::render_intruder_tab(frame, app, area),
        Tab::Decoder => decoder_tab::render_decoder_tab(frame, app, area),
        Tab::Comparer => comparer_tab::render_comparer_tab(frame, app, area),
        Tab::Scanner => scanner_tab::render_scanner_tab(frame, app, area),
        Tab::Active => active_tab::render_active_tab(frame, app, area),
        Tab::WebSockets => websocket_tab::render_websocket_tab(frame, app, area),
        Tab::Plugins => plugin_tab::render_plugin_tab(frame, app, area),
        Tab::Settings => render_settings(frame, app, area),
    }
}

fn render_scope(frame: &mut Frame, app: &App, area: Rect) {
    let ai_active = app.scope_ai_mode != ScopeAiMode::Editing;
    let chunks = if ai_active {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(42), Constraint::Min(0), Constraint::Length(4)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(5), Constraint::Length(0)])
            .split(area)
    };

    render_scope_rules_table(frame, app, chunks[0]);
    if ai_active {
        render_scope_ai_assistant(frame, app, chunks[1]);
        render_scope_controls(frame, app, chunks[2]);
    } else {
        render_scope_controls(frame, app, chunks[1]);
    }
}

fn render_scope_rules_table(frame: &mut Frame, app: &App, area: Rect) {
    let rows = app.scope_engine.rules.iter().map(|rule| {
        Row::new(vec![
            Cell::from(rule.id.to_string()),
            Cell::from(if rule.enabled { "yes" } else { "no" }),
            Cell::from(rule.rule_type.as_str()),
            Cell::from(rule.pattern.clone()),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Percentage(70),
        ],
    )
    .header(
        Row::new(["ID", "Enabled", "Type", "Regex"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(" Scope Rules ").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(if app.scope_engine.rules.is_empty() {
        None
    } else {
        Some(app.selected_scope_rule)
    });
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_scope_controls(frame: &mut Frame, app: &App, area: Rect) {
    let input = match app.scope_input_mode {
        Some(crate::app::ScopeInputMode::Add) => format!(" add regex: {}_", app.scope_buffer),
        Some(crate::app::ScopeInputMode::Edit) => format!(" edit regex: {}_", app.scope_buffer),
        Some(crate::app::ScopeInputMode::Test) => format!(" test URL: {}_", app.scope_buffer),
        None => String::new(),
    };
    let test = app
        .last_scope_test_result
        .map(|in_scope| format!(" test {} => {}", app.scope_test_url, if in_scope { "in scope" } else { "out of scope" }))
        .unwrap_or_default();
    let mode_help = match app.scope_ai_mode {
        ScopeAiMode::Prompt => "AI prompt: Enter generate  Esc cancel",
        ScopeAiMode::ProposalPreview => "AI proposal: a append  R replace  d/Esc discard  Ctrl+K regenerate",
        ScopeAiMode::Editing => "Ctrl+K AI assistant  a add  e edit  d delete  Space enable/disable  i include  o exclude  t test URL",
    };
    let help = vec![
        Line::from(mode_help),
        Line::from(format!("{}{}", input, test)),
        Line::from(app.project_message.clone()),
    ];
    frame.render_widget(
        Paragraph::new(help)
            .block(Block::default().title(" Scope Controls ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_scope_ai_assistant(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    match app.scope_ai_mode {
        ScopeAiMode::Prompt => {
            let input = if app.scope_ai_input.is_empty() {
                "Describe scope rules, e.g. only example.com and api.example.com; exclude static assets...".to_string()
            } else {
                format!("{} _", app.scope_ai_input)
            };
            lines.push(Line::from(vec![
                Span::styled("AI Scope > ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(input),
            ]));
            lines.push(Line::styled("The proposal will be validated and will not auto-apply.", Style::default().fg(Color::DarkGray)));
        }
        ScopeAiMode::ProposalPreview => match &app.scope_ai_proposal {
            Some(ScopeRuleProposalState::Loading) => {
                let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(app.tick_count as usize) % 10];
                lines.push(Line::styled(format!("{spinner} AI drafting precise scope regex rules..."), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            }
            Some(ScopeRuleProposalState::Error(error)) => {
                lines.push(Line::styled("AI scope proposal failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
                lines.push(Line::raw(error.clone()));
            }
            Some(ScopeRuleProposalState::Ready(proposal)) => push_scope_proposal_lines(&mut lines, proposal),
            None => lines.push(Line::raw("No proposal available")),
        },
        ScopeAiMode::Editing => {}
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Scope Assistant ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn push_scope_proposal_lines(lines: &mut Vec<Line<'static>>, proposal: &ScopeRuleProposal) {
    lines.push(Line::from(vec![
        Span::styled("PROPOSAL ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(if proposal.replace_existing { "replace recommended" } else { "append recommended" }),
        Span::raw("  "),
        confidence_span(proposal.confidence),
    ]));
    lines.push(Line::raw(proposal.summary.clone()));
    lines.push(Line::raw(""));
    lines.push(Line::styled("Rules", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    for rule in proposal.rules.iter().take(6) {
        let color = if rule.rule_type.eq_ignore_ascii_case("exclude") { Color::Red } else { Color::Green };
        lines.push(Line::from(vec![
            Span::styled(format!("[{}] ", rule.rule_type.to_ascii_uppercase()), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::raw(rule.pattern.clone()),
        ]));
    }
    push_scope_test_lines(lines, proposal);
    if !proposal.warnings.is_empty() {
        lines.push(Line::styled("Warnings", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        for warning in proposal.warnings.iter().take(3) {
            lines.push(Line::raw(format!("• {warning}")));
        }
    }
}

fn push_scope_test_lines(lines: &mut Vec<Line<'static>>, proposal: &ScopeRuleProposal) {
    if proposal.test_cases.is_empty() {
        return;
    }
    let rules = proposal
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| ScopeRule {
            id: index as i64 + 1,
            pattern: rule.pattern.clone(),
            rule_type: if rule.rule_type.eq_ignore_ascii_case("exclude") { ScopeRuleType::Exclude } else { ScopeRuleType::Include },
            enabled: true,
        })
        .collect::<Vec<_>>();
    let engine = ScopeEngine::new(rules);
    lines.push(Line::styled("Test Cases", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    for test in proposal.test_cases.iter().take(5) {
        let actual = engine.is_in_scope(&test.url);
        let ok = actual == test.expected_in_scope;
        lines.push(Line::from(vec![
            Span::styled(if ok { "✓ " } else { "! " }, Style::default().fg(if ok { Color::Green } else { Color::Red })),
            Span::raw(format!("{} -> {}", test.url, if actual { "IN" } else { "OUT" })),
        ]));
    }
}

fn confidence_span(confidence: Option<f32>) -> Span<'static> {
    let Some(mut value) = confidence else {
        return Span::styled("confidence: n/a", Style::default().fg(Color::DarkGray));
    };
    if value > 1.0 {
        value /= 100.0;
    }
    Span::styled(format!("confidence: {:.0}%", value.clamp(0.0, 1.0) * 100.0), Style::default().fg(Color::Green))
}

fn render_settings(frame: &mut Frame, app: &App, area: Rect) {
    let listen_line = format!("Listen address: {}", app.proxy_config.listen_addr);
    let status_line = format!("Proxy status: {}", app.proxy_status.label());
    let ca_line = format!("CA certificate: {}", app.proxy_config.ca_cert_path.display());
    let key_line = format!("CA private key: {}", app.proxy_config.ca_key_path.display());
    render_placeholder(
        frame,
        area,
        "Settings",
        &[
            "Proxy controls:",
            "  s - start proxy",
            "  x - stop proxy",
            listen_line.as_str(),
            status_line.as_str(),
            app.proxy_message.as_str(),
            app.project_message.as_str(),
            "  Ctrl+S - save project (PROXIMA_SAVE_AS optional)",
            "  Ctrl+O - open project (PROXIMA_OPEN_PROJECT/PROXIMA_PROJECT)",
            ca_line.as_str(),
            key_line.as_str(),
            "Install/import the CA certificate into your browser or OS trust store for HTTPS interception.",
        ],
    );
}

fn render_placeholder(frame: &mut Frame, area: Rect, title: &str, lines: &[&str]) {
    let text = lines
        .iter()
        .map(|line| Line::from(*line))
        .collect::<Vec<_>>();

    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .title(format!(" {title} "))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::DarkGray)),
        )
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

fn render_status_line(frame: &mut Frame, app: &App, area: Rect) {
    let total_flows = app.flow_store.len();
    let selected = app
        .selected_flow
        .map(|index| format!("{}", index + 1))
        .unwrap_or_else(|| "-".to_string());
    let selected_flow_scope = app
        .selected_flow
        .and_then(|index| app.flow_store.snapshot().get(index).cloned())
        .map(|flow| if app.scope_engine.is_in_scope(&flow.uri) { "in-scope" } else { "out-of-scope" })
        .unwrap_or("no-flow");
    let search = if app.search_mode {
        format!(" search: {}_ ", app.search_query)
    } else if !app.search_query.is_empty() {
        format!(" filter: {} ", app.search_query)
    } else {
        format!(" scope: {selected_flow_scope} ")
    };

    let tab_hint = if app.current_tab == Tab::Proxy {
        " e explain flow  r AI/raw  "
    } else if app.current_tab == Tab::Scanner {
        " Ctrl+K AI rule  t triage  "
    } else if app.current_tab == Tab::Repeater {
        " Ctrl+K AI builder  "
    } else if app.current_tab == Tab::Intruder {
        " Ctrl+K payloads  Ctrl+P plan  "
    } else if app.current_tab == Tab::Scope {
        " Ctrl+K AI scope  "
    } else if app.current_tab == Tab::Decoder {
        " Ctrl+K AI decode  "
    } else if app.current_tab == Tab::Comparer {
        " Ctrl+K AI summary  "
    } else {
        ""
    };

    let status = Line::from(vec![
        Span::styled(" ←/→ ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" switch tabs  "),
        Span::styled(tab_hint, Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::styled(" Ctrl+C ", Style::default().fg(Color::Black).bg(Color::Red)),
        Span::raw(" quit  "),
        Span::styled(" s/x ", Style::default().fg(Color::Black).bg(Color::Yellow)),
        Span::raw(" start/stop proxy in Settings  "),
        Span::styled(
            format!(" flows: {total_flows} selected: {selected} "),
            Style::default().fg(Color::Black).bg(Color::Green),
        ),
        Span::raw(format!(" proxy: {}  ", app.proxy_config.listen_addr)),
        Span::styled(search, Style::default().fg(Color::Black).bg(Color::Magenta)),
        Span::raw(format!(" active: {} ", app.current_tab.title())),
    ]);

    frame.render_widget(Paragraph::new(status), area);
}
