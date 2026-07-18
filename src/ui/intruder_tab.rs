use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
use ratatui_textarea::TextArea;

use crate::{app::App, models::intruder::parse_positions};

pub fn render_intruder_tab(frame: &mut Frame, app: &App, area: Rect) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(area);
    render_progress(frame, app, outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(outer[1]);
    render_request_editor(frame, app, body[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(body[1]);
    render_config(frame, app, right[0]);
    render_results(frame, app, right[1]);
    render_controls(frame, app, outer[2]);
}

fn render_progress(frame: &mut Frame, app: &App, area: Rect) {
    let completed = app.intruder_results.len();
    let total = app.intruder_total.max(completed).max(1);
    let ratio = completed as f64 / total as f64;
    let state = if app.intruder_running {
        if app.intruder_paused { "paused" } else { "running" }
    } else {
        "idle"
    };
    frame.render_widget(
        Gauge::default()
            .block(Block::default().title(" Intruder Progress ").borders(Borders::ALL))
            .gauge_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .ratio(ratio)
            .label(format!("{completed}/{total} {state}")),
        area,
    );
}

fn render_request_editor(frame: &mut Frame, app: &App, area: Rect) {
    let mut textarea = TextArea::from(
        app.intruder_request_text
            .lines()
            .map(|line| line.to_string())
            .collect::<Vec<_>>(),
    );
    let positions = parse_positions(&app.intruder_request_text);
    textarea.set_block(
        Block::default()
            .title(format!(" Target Request - {} positions marked with § § ", positions.len()))
            .borders(Borders::ALL),
    );
    textarea.set_line_number_style(Style::default().fg(Color::DarkGray));
    textarea.set_cursor_line_style(Style::default().bg(Color::Black));
    frame.render_widget(textarea.widget(), area);
}

fn render_config(frame: &mut Frame, app: &App, area: Rect) {
    let positions = parse_positions(&app.intruder_request_text);
    let lines = vec![
        Line::from(vec![Span::styled("Attack: ", Style::default().fg(Color::Yellow)), Span::raw(app.intruder_attack_type.label())]),
        Line::from(format!("Positions: {}   Concurrency: {}   RPS: {}", positions.len(), app.intruder_concurrency, app.intruder_rps)),
        Line::from("Payload source: SimpleList from built-in textarea/string"),
        Line::from(format!("Payloads: {}", app.intruder_payloads_text.lines().filter(|line| !line.trim().is_empty()).count())),
        Line::from("Filters: 0 all, 2 xx, 4 xx, 5 xx   Sort: s toggles time/id"),
        Line::from(format!("Status filter: {}", app.intruder_filter_status.map(|s| format!("{}xx", s / 100)).unwrap_or_else(|| "all".to_string()))),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Payload Sets / Attack Config ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_results(frame: &mut Frame, app: &App, area: Rect) {
    let results = app.filtered_intruder_results();
    let rows = results.iter().map(|result| {
        let status = result.status.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
        let error = result.error.clone().unwrap_or_default();
        Row::new(vec![
            Cell::from(result.payload_label.clone()),
            Cell::from(status),
            Cell::from(result.length.to_string()),
            Cell::from(format!("{}ms", result.time_ms)),
            Cell::from(error),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(32),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Percentage(35),
        ],
    )
    .header(
        Row::new(["Payload", "Status", "Length", "Time", "Error"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(" Results ").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(if results.is_empty() {
        None
    } else {
        Some(app.intruder_selected_result.min(results.len() - 1))
    });
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_controls(frame: &mut Frame, app: &App, area: Rect) {
    let controls = Line::from(vec![
        Span::styled(" F5 ", Style::default().fg(Color::Black).bg(Color::Green)),
        Span::raw(" start/resume  "),
        Span::styled(" F6 ", Style::default().fg(Color::Black).bg(Color::Yellow)),
        Span::raw(" pause  "),
        Span::styled(" F7 ", Style::default().fg(Color::Black).bg(Color::Red)),
        Span::raw(" stop  "),
        Span::styled(" F8 ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" attack type  "),
        Span::styled(" F9 ", Style::default().fg(Color::Black).bg(Color::Magenta)),
        Span::raw(" export CSV  "),
        Span::raw(app.project_message.clone()),
    ]);
    frame.render_widget(
        Paragraph::new(controls).block(Block::default().title(" Attack Controls ").borders(Borders::ALL)),
        area,
    );
}
