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

use crate::app::{App, Tab};

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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(5)])
        .split(area);

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
    frame.render_stateful_widget(table, chunks[0], &mut state);

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
    let help = vec![
        Line::from("a add  e edit  d delete  Space enable/disable  i include  o exclude  t test URL"),
        Line::from(format!("{}{}", input, test)),
        Line::from(app.project_message.clone()),
    ];
    frame.render_widget(
        Paragraph::new(help)
            .block(Block::default().title(" Scope Controls ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        chunks[1],
    );
}

fn render_settings(frame: &mut Frame, app: &App, area: Rect) {
    let listen_line = format!("Listen address: {}", app.proxy_config.listen_addr);
    let status_line = format!("Proxy status: {}", app.proxy_status.label());
    let ca_line = format!("CA certificate: {}", app.proxy_config.ca_cert_path.display());
    let key_line = format!("CA private key: {}", app.proxy_config.ca_key_path.display());
    let scope_line = format!("Engagement scope: {}", app.policy.status_line());
    let requests_line = format!(
        "Authorized requests: {} · denials: {} · audit entries: {}",
        app.policy.requests_used(),
        app.policy.denials(),
        app.policy.audit_entries()
    );
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
            scope_line.as_str(),
            requests_line.as_str(),
            "  PROXIMA_ENVELOPE - path to engagement.yaml (scope is NOT enforced when unset)",
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

    let status = Line::from(vec![
        Span::styled(" ←/→ ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" switch tabs  "),
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
