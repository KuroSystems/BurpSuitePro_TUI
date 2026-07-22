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
    app::{agent_tool_catalog, App, BrainViewMode, ProjectPanelAction, ProjectPanelMode, ScopeAiMode, Tab},
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
        Tab::Brain => render_brain(frame, app, area),
        Tab::Plugins => plugin_tab::render_plugin_tab(frame, app, area),
        Tab::Help => render_help(frame, app, area),
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

fn render_brain(frame: &mut Frame, app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(4)])
        .split(area);
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(layout[0]);

    let editor_lines = if app.brain_view_mode == BrainViewMode::Preview {
        render_brain_preview_lines(&app.brain_markdown)
    } else {
        app.brain_markdown
            .split('\n')
            .map(|line| Line::raw(line.to_string()))
            .collect::<Vec<_>>()
    };
    let title = if app.brain_view_mode == BrainViewMode::Preview {
        " Proxima Brain Markdown Preview "
    } else {
        " Proxima Brain Markdown Editor "
    };
    frame.render_widget(
        Paragraph::new(editor_lines)
            .block(Block::default().title(title).borders(Borders::ALL).border_style(Style::default().fg(Color::Magenta)))
            .scroll((app.brain_scroll, 0))
            .wrap(Wrap { trim: false }),
        columns[0],
    );

    let side = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(columns[1]);
    let markdown_files = brain_markdown_file_lines(app);
    frame.render_widget(
        Paragraph::new(markdown_files)
            .block(Block::default().title(" Markdown Files (.md)  Ctrl+N new  ↑/↓ switch  Del delete ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        side[0],
    );
    frame.render_widget(
        Paragraph::new(brain_intelligence_lines(app))
            .block(Block::default().title(" Brain Intelligence Status ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
            .wrap(Wrap { trim: true }),
        side[1],
    );

    let words = app.brain_markdown.split_whitespace().count();
    let section_count = app.brain_markdown.lines().filter(|line| line.trim_start().starts_with('#')).count();
    let footer = vec![
        Line::from(vec![
            Span::styled(" Ctrl+S ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" save  "),
            Span::styled(" v/F3 ", Style::default().fg(Color::Black).bg(Color::Magenta)),
            Span::raw(format!(" {}  ", app.brain_view_mode.label())),
            Span::styled(" Ctrl+N/F2 ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" new .md  "),
            Span::styled(" Del/Ctrl+D ", Style::default().fg(Color::Black).bg(Color::Red)),
            Span::raw(" delete  "),
            Span::styled(" ↑/↓ ", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" switch  "),
            Span::styled(" PgUp/PgDn ", Style::default().fg(Color::Black).bg(Color::Magenta)),
            Span::raw(" scroll  "),
            Span::styled(if app.brain_dirty { " unsaved " } else { " saved " }, Style::default().fg(Color::Black).bg(if app.brain_dirty { Color::Yellow } else { Color::Green })),
            Span::raw(format!(" sections: {section_count} words: {words}")),
        ]),
        Line::styled(app.brain_message.clone(), Style::default().fg(Color::DarkGray)),
    ];
    frame.render_widget(
        Paragraph::new(footer).block(Block::default().title(" Brain Status ").borders(Borders::ALL)),
        layout[1],
    );
}

fn render_brain_preview_lines(markdown: &str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut in_code = false;
    for raw in markdown.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_code = !in_code;
            lines.push(Line::styled(if in_code { " code " } else { "" }, Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)));
        } else if in_code {
            lines.push(Line::styled(format!("  {line}"), Style::default().fg(Color::LightCyan).bg(Color::Black)));
        } else if let Some(text) = trimmed.strip_prefix("# ") {
            lines.push(Line::styled(text.to_string(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
        } else if let Some(text) = trimmed.strip_prefix("## ") {
            lines.push(Line::styled(text.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
        } else if let Some(text) = trimmed.strip_prefix("- ").or_else(|| trimmed.strip_prefix("* ")) {
            lines.push(Line::from(vec![Span::styled("  • ", Style::default().fg(Color::Cyan)), Span::raw(text.to_string())]));
        } else if trimmed.starts_with('|') && trimmed.ends_with('|') {
            lines.push(Line::styled(trimmed.to_string(), Style::default().fg(Color::Yellow)));
        } else {
            lines.push(Line::raw(line.to_string()));
        }
    }
    lines
}

fn brain_intelligence_lines(app: &App) -> Vec<Line<'static>> {
    let files = app.brain_markdown_files();
    let total_sections = files
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .map(|content| content.lines().filter(|line| line.trim_start().starts_with('#')).count())
        .sum::<usize>();
    let total_words = files
        .iter()
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .map(|content| content.split_whitespace().count())
        .sum::<usize>();
    let active_sections = app.brain_markdown.lines().filter(|line| line.trim_start().starts_with('#')).count();
    let active_words = app.brain_markdown.split_whitespace().count();
    let query = app.ai_panel.input.trim();
    let relevant = if query.is_empty() {
        0
    } else {
        app.relevant_brain_context(query)
            .map(|context| context.split("\n\n---\n\n").count())
            .unwrap_or(0)
    };
    vec![
        Line::from(vec![Span::styled("Mode: ", Style::default().fg(Color::DarkGray)), Span::styled(app.brain_view_mode.label(), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD))]),
        Line::raw(format!("Files indexed: {}", files.len())),
        Line::raw(format!("Total sections: {total_sections}")),
        Line::raw(format!("Total words: {total_words}")),
        Line::raw(format!("Active file sections: {active_sections}")),
        Line::raw(format!("Active file words: {active_words}")),
        Line::raw(format!("Relevant sections for AI prompt: {relevant}")),
        Line::styled("AI integration: top matching Brain sections are injected into Skill and Agent prompts.", Style::default().fg(Color::DarkGray)),
    ]
}

fn brain_markdown_file_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    lines.push(Line::styled("Project directory Markdown files", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    if let Some(input) = &app.brain_new_file_input {
        lines.push(Line::styled(format!("new file: {input}_"), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    }
    lines.push(Line::raw(""));
    let files = app.brain_markdown_files();
    for (index, path) in files.iter().enumerate() {
        let is_selected = index == app.brain_selected_file.min(files.len().saturating_sub(1));
        let is_active = path == &app.brain_file_path;
        let label = path.file_name().and_then(|name| name.to_str()).unwrap_or("<invalid>");
        lines.push(Line::from(vec![
            Span::styled(if is_selected { "▶ " } else { "  " }, Style::default().fg(Color::Magenta)),
            Span::styled(label.to_string(), Style::default().fg(if is_active { Color::Green } else { Color::Gray }).add_modifier(if is_active || is_selected { Modifier::BOLD } else { Modifier::empty() })),
        ]));
    }
    if files.is_empty() {
        lines.push(Line::styled("No .md files found beside this project yet.", Style::default().fg(Color::DarkGray)));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled("Active Brain file", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
    lines.push(Line::raw(app.brain_file_path.display().to_string()));
    lines
}

fn render_help(frame: &mut Frame, _app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0), Constraint::Length(4)])
        .split(area);
    let header = vec![
        Line::from(vec![
            Span::styled(" Proxima Agent Tool Catalog ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("  use this when designing custom agents"),
        ]),
        Line::raw("Tools are grouped by tab. Risk: passive = read-only, local_modify = changes local state, sends_traffic = requires explicit user approval."),
    ];
    frame.render_widget(
        Paragraph::new(header)
            .block(Block::default().title(" Help / Agent Capabilities ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        layout[0],
    );

    let mut lines = Vec::new();
    let mut current_tab = "";
    for tool in agent_tool_catalog() {
        if tool.tab != current_tab {
            current_tab = tool.tab;
            lines.push(Line::raw(""));
            lines.push(Line::styled(current_tab.to_string(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
        }
        let risk_color = match tool.risk {
            "passive" => Color::Green,
            "local_modify" => Color::Yellow,
            "sends_traffic" => Color::Red,
            _ => Color::Gray,
        };
        lines.push(Line::from(vec![
            Span::styled(format!("  {} ", tool.risk), Style::default().fg(Color::Black).bg(risk_color)),
            Span::raw(" "),
            Span::styled(tool.tool, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" — {}", tool.purpose)),
        ]));
        lines.push(Line::styled(format!("     Agent usage: {}", tool.agent_usage), Style::default().fg(Color::DarkGray)));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Available Agent Tools ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        layout[1],
    );

    let footer = vec![
        Line::raw("Agent Page: AI tab -> F3/Ctrl+G. In Agent Mode, AI routes prompts to relevant custom agents and proposes a plan."),
        Line::raw("Safety governor: passive tools can be summarized; traffic-sending tools are never executed automatically."),
    ];
    frame.render_widget(
        Paragraph::new(footer)
            .block(Block::default().title(" Agent Design Notes ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        layout[2],
    );
}

fn render_settings(frame: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(area);
    render_proxy_settings(frame, app, columns[0]);
    render_ai_settings(frame, app, columns[1]);
    if app.project_panel_mode != ProjectPanelMode::Closed {
        render_project_panel(frame, app, area);
    }
}

fn render_proxy_settings(frame: &mut Frame, app: &App, area: Rect) {
    let status_color = match app.proxy_status {
        crate::app::ProxyStatus::Running => Color::Green,
        crate::app::ProxyStatus::Failed => Color::Red,
        crate::app::ProxyStatus::Stopped => Color::Yellow,
    };
    let project_line = if app.project_input_mode.is_some() {
        format!("Project: {} _", app.project_name_buffer)
    } else {
        format!("Project: {}", app.database.path().display())
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(" Status ", Style::default().fg(Color::Black).bg(status_color).add_modifier(Modifier::BOLD)),
            Span::raw(format!(" {}", app.proxy_status.label())),
        ]),
        Line::raw(project_line),
        Line::raw(""),
        Line::from(vec![
            Span::styled("Listen", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(if app.settings_editing_proxy_addr { "  " } else { "  " }),
            Span::styled(
                if app.settings_editing_proxy_addr { format!("{} _", app.proxy_addr_input) } else { app.proxy_config.listen_addr.to_string() },
                Style::default().fg(if app.settings_editing_proxy_addr { Color::Yellow } else { Color::Gray }).add_modifier(if app.settings_editing_proxy_addr { Modifier::BOLD } else { Modifier::empty() }),
            ),
        ]),
        Line::from(vec![Span::styled("CA cert", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)), Span::raw(format!("  {}", app.proxy_config.ca_cert_path.display()))]),
        Line::from(vec![Span::styled("CA key ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)), Span::raw(format!("  {}", app.proxy_config.ca_key_path.display()))]),
        Line::raw(""),
        Line::styled(app.proxy_message.clone(), Style::default().fg(status_color)),
        Line::styled(app.project_message.clone(), Style::default().fg(Color::DarkGray)),
        Line::raw(""),
        Line::from(vec![
            Span::styled(" s/F5 ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" start  "),
            Span::styled(" x/F7 ", Style::default().fg(Color::Black).bg(Color::Red)),
            Span::raw(" stop  "),
            Span::styled(" p ", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" edit port  "),
            Span::styled(" F2 ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" project panel"),
        ]),
        Line::from(vec![
            Span::styled(" Enter ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" apply edited port  "),
            Span::styled(" Esc ", Style::default().fg(Color::Black).bg(Color::Red)),
            Span::raw(" cancel edit"),
        ]),
        Line::from(vec![
            Span::styled(" F2 ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" Project Manager handles new/rename/save/open"),
        ]),
        Line::raw(""),
        Line::styled("Tip: import the CA certificate into browser/OS trust store for HTTPS interception.", Style::default().fg(Color::DarkGray)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Proxy Control Center ").borders(Borders::ALL).border_style(Style::default().fg(status_color)))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_project_panel(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(64, 62, area);
    frame.render_widget(ratatui::widgets::Clear, popup);
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0), Constraint::Length(4)])
        .split(popup);
    frame.render_widget(
        Paragraph::new(vec![
            Line::styled("Project Manager", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Line::raw(format!("Current: {}", app.database.path().display())),
        ])
        .block(Block::default().title(" Project Panel ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan))),
        layout[0],
    );

    match app.project_panel_mode {
        ProjectPanelMode::Menu => {
            let items = ProjectPanelAction::ALL.iter().enumerate().map(|(index, action)| {
                let selected = index == app.project_panel_selected;
                Line::from(vec![
                    Span::styled(if selected { "▶ " } else { "  " }, Style::default().fg(Color::Cyan)),
                    Span::styled(action.label(), Style::default().fg(if selected { Color::Green } else { Color::Gray }).add_modifier(if selected { Modifier::BOLD } else { Modifier::empty() })),
                ])
            }).collect::<Vec<_>>();
            frame.render_widget(
                Paragraph::new(items)
                    .block(Block::default().title(" Choose Action ").borders(Borders::ALL))
                    .wrap(Wrap { trim: true }),
                layout[1],
            );
        }
        ProjectPanelMode::Input => {
            let action = ProjectPanelAction::ALL[app.project_panel_selected.min(ProjectPanelAction::ALL.len() - 1)];
            let hint = match action {
                ProjectPanelAction::New => "Enter new project name/path. Empty auto-generates a timestamped project.",
                ProjectPanelAction::Rename => "Enter new project name/path. Relative names stay near current project.",
                ProjectPanelAction::Open => "Enter project path/name to open.",
                ProjectPanelAction::Save => "Save uses current project path.",
            };
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(action.label(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                    Line::raw(hint),
                    Line::raw(""),
                    Line::from(vec![Span::styled("> ", Style::default().fg(Color::Cyan)), Span::raw(format!("{} _", app.project_panel_input))]),
                ])
                .block(Block::default().title(" Project Input ").borders(Borders::ALL))
                .wrap(Wrap { trim: true }),
                layout[1],
            );
        }
        ProjectPanelMode::Closed => {}
    }

    frame.render_widget(
        Paragraph::new("↑/↓ choose • Enter select/apply • Esc close/back • F2 opens Project Panel")
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL)),
        layout[2],
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn render_ai_settings(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0), Constraint::Length(5)])
        .split(area);
    let header = vec![
        Line::from(vec![Span::styled("Ollama URL", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)), Span::raw(format!("  {}", app.ai_panel.settings.ollama_url))]),
        Line::from(vec![Span::styled("Active model", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)), Span::raw(format!("  {}", app.ai_panel.settings.model))]),
        Line::from(vec![Span::styled("Ollama", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)), Span::raw(format!("  {}", app.ollama_status))]),
        Line::raw(""),
        Line::from(vec![
            Span::styled(" o/r ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" refresh models  "),
            Span::styled(" ↑/↓ ", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" select  "),
            Span::styled(" Enter ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" apply"),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(header)
            .block(Block::default().title(" AI Connection ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        rows[0],
    );

    let models = app.ai_model_options();
    let model_lines = if models.is_empty() {
        vec![Line::styled("No model options. Start Ollama and press o.", Style::default().fg(Color::Yellow))]
    } else {
        models
            .iter()
            .enumerate()
            .map(|(index, model)| {
                let selected = index == app.selected_ai_model.min(models.len().saturating_sub(1));
                let active = model == &app.ai_panel.settings.model;
                Line::from(vec![
                    Span::styled(if selected { "▶ " } else { "  " }, Style::default().fg(Color::Cyan)),
                    Span::styled(model.clone(), Style::default().fg(if active { Color::Green } else { Color::Gray }).add_modifier(if selected { Modifier::BOLD } else { Modifier::empty() })),
                    Span::raw(if active { "  active" } else { "" }),
                ])
            })
            .collect::<Vec<_>>()
    };
    frame.render_widget(
        Paragraph::new(model_lines)
            .block(Block::default().title(" Local Ollama / Configured Model Options ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        rows[1],
    );

    let footer = vec![
        Line::raw("Local models are loaded from Ollama /api/tags."),
        Line::raw("Cloud/free model names can be listed via PROXIMA_AI_MODEL_PRESETS or PROXIMA_CLOUD_AI_MODELS."),
        Line::styled("Note: AI calls currently use the configured Ollama-compatible /api/chat endpoint.", Style::default().fg(Color::DarkGray)),
    ];
    frame.render_widget(
        Paragraph::new(footer)
            .block(Block::default().title(" Model Discovery Notes ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        rows[2],
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
        " Ctrl+K/F2 payloads  Ctrl+P/F4 plan  "
    } else if app.current_tab == Tab::Scope {
        " Ctrl+K AI scope  "
    } else if app.current_tab == Tab::Decoder {
        " Ctrl+K chain  Ctrl+G/F2 agent  "
    } else if app.current_tab == Tab::Comparer {
        " Ctrl+K AI summary  "
    } else if app.current_tab == Tab::Brain {
        " Ctrl+S save brain  .md files listed  "
    } else if app.current_tab == Tab::Help {
        " agent tool catalog  "
    } else {
        ""
    };

    let status = Line::from(vec![
        Span::styled(" ←/→ ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" switch tabs  "),
        Span::styled(tab_hint, Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::styled(" Alt+C/V ", Style::default().fg(Color::Black).bg(Color::Yellow)),
        Span::raw(" copy/paste box  "),
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
