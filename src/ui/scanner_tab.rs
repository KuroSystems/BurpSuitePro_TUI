use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

use crate::{
    app::App,
    scanner::{Confidence, Finding, Severity},
};

pub fn render_scanner_tab(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(62), Constraint::Percentage(25), Constraint::Length(5)])
        .split(area);
    render_findings(frame, app, rows[0]);
    render_checks(frame, app, rows[1]);
    render_controls(frame, app, rows[2]);
}

fn render_findings(frame: &mut Frame, app: &App, area: Rect) {
    let findings = app.filtered_findings();
    let rows = findings.iter().map(|finding| {
        Row::new(vec![
            Cell::from(finding.severity.label()),
            Cell::from(finding.confidence.label()),
            Cell::from(finding.issue_name.clone()),
            Cell::from(finding.url.clone()),
            Cell::from(short_evidence(finding)),
        ])
        .style(severity_style(finding.severity))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Percentage(24),
            Constraint::Percentage(34),
            Constraint::Percentage(30),
        ],
    )
    .header(
        Row::new(["Severity", "Confidence", "Issue", "URL", "Evidence"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(" Passive Scanner Findings ").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(if findings.is_empty() {
        None
    } else {
        Some(app.selected_finding.min(findings.len() - 1))
    });
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_checks(frame: &mut Frame, app: &App, area: Rect) {
    let rows = app.passive_scanner.definitions.iter().map(|definition| {
        Row::new(vec![
            Cell::from(if definition.enabled { "yes" } else { "no" }),
            Cell::from(definition.severity.label()),
            Cell::from(definition.confidence.label()),
            Cell::from(definition.id.clone()),
            Cell::from(definition.name.clone()),
        ])
        .style(if definition.enabled { Style::default() } else { Style::default().fg(Color::DarkGray) })
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(7),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(24),
            Constraint::Percentage(50),
        ],
    )
    .header(Row::new(["Enabled", "Severity", "Confidence", "ID", "Name"]).style(Style::default().fg(Color::Cyan)))
    .block(Block::default().title(" Scanner Checks ").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray));
    let mut state = TableState::default().with_selected(if app.passive_scanner.definitions.is_empty() {
        None
    } else {
        Some(app.selected_scanner_check.min(app.passive_scanner.definitions.len() - 1))
    });
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_controls(frame: &mut Frame, app: &App, area: Rect) {
    let severity = app
        .scanner_severity_filter
        .map(|severity| severity.label().to_string())
        .unwrap_or_else(|| "all".to_string());
    let confidence = app
        .scanner_confidence_filter
        .map(|confidence| confidence.label().to_string())
        .unwrap_or_else(|| "all".to_string());
    let lines = vec![
        Line::from(vec![
            Span::styled("Enter", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" jump to flow  "),
            Span::styled("[/]", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" select check  "),
            Span::styled("e", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" enable/disable check  "),
            Span::styled("r", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" reload defs  "),
            Span::styled("x", Style::default().fg(Color::Black).bg(Color::Magenta)),
            Span::raw(" export JSON/HTML"),
        ]),
        Line::from(format!(
            "Severity filters: 0 all, i info, l low, m medium, h high, c critical | Confidence: 1 tentative, 2 firm, 3 certain | active severity={severity} confidence={confidence}"
        )),
        Line::from(app.project_message.clone()),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Scanner Controls ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn short_evidence(finding: &Finding) -> String {
    finding
        .evidence_json
        .chars()
        .take(120)
        .collect::<String>()
        .replace('\n', " ")
}

fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(Color::Red),
        Severity::Medium => Style::default().fg(Color::Yellow),
        Severity::Low => Style::default().fg(Color::Blue),
        Severity::Info => Style::default().fg(Color::Gray),
    }
}

#[allow(dead_code)]
fn _confidence_style(confidence: Confidence) -> Style {
    match confidence {
        Confidence::Certain => Style::default().fg(Color::Green),
        Confidence::Firm => Style::default().fg(Color::Cyan),
        Confidence::Tentative => Style::default().fg(Color::Gray),
    }
}
