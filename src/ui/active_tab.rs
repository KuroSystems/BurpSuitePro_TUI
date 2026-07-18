use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

use crate::app::App;

pub fn render_active_tab(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(0), Constraint::Length(5)])
        .split(area);
    render_warning(frame, app, rows[0]);
    render_targets(frame, app, rows[1]);
    render_controls(frame, app, rows[2]);
}

fn render_warning(frame: &mut Frame, app: &App, area: Rect) {
    let text = if app.active_scanning_enabled {
        "ACTIVE CHECKS ENABLED - ensure you have explicit authorization for every in-scope target"
    } else {
        "Active checks disabled. Press e only after confirming authorization. Safe checks only: traversal probe, reflected marker, verb tampering."
    };
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Active Scanner Warning ").borders(Borders::ALL))
            .style(if app.active_scanning_enabled { Style::default().fg(Color::Red).add_modifier(Modifier::BOLD) } else { Style::default().fg(Color::Yellow) })
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_targets(frame: &mut Frame, app: &App, area: Rect) {
    let rows = app.active_scan_targets.iter().map(|target| {
        let state = if target.running { "running" } else if target.completed >= target.total && target.total > 0 { "done" } else { "queued" };
        Row::new(vec![
            Cell::from(target.url.to_string()),
            Cell::from(if target.confirmed { "yes" } else { "no" }),
            Cell::from(state),
            Cell::from(format!("{}/{}", target.completed, target.total)),
        ])
    });
    let table = Table::new(
        rows,
        [Constraint::Percentage(55), Constraint::Length(10), Constraint::Length(10), Constraint::Length(12)],
    )
    .header(Row::new(["Target", "Confirmed", "State", "Progress"]).style(Style::default().fg(Color::Cyan)))
    .block(Block::default().title(" Active Scan Queue ").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(if app.active_scan_targets.is_empty() { None } else { Some(app.selected_active_target.min(app.active_scan_targets.len() - 1)) });
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_controls(frame: &mut Frame, app: &App, area: Rect) {
    let selected = app.active_scan_targets.get(app.selected_active_target);
    let ratio = selected
        .map(|target| target.completed as f64 / target.total.max(1) as f64)
        .unwrap_or(0.0);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(2), Constraint::Length(3)])
        .split(area);
    frame.render_widget(Gauge::default().ratio(ratio).label(format!("{:.0}%", ratio * 100.0)), chunks[0]);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("e", Style::default().fg(Color::Black).bg(Color::Red)),
            Span::raw(" opt-in/out  "),
            Span::styled("a", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" add selected proxy flow target  "),
            Span::styled("F5", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" start  "),
            Span::styled("F7", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" stop  rate limit: 10 req/s per target"),
        ])).block(Block::default().title(" Controls ").borders(Borders::ALL)),
        chunks[1],
    );
}
