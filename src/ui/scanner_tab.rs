use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap},
    Frame,
};

use crate::{
    app::{App, ScannerAiMode, ScannerDetailMode},
    models::ai::{FindingTriage, FindingTriageState, PassiveRuleDraft, PassiveRuleDraftState},
    scanner::{Confidence, Finding, Severity},
};

pub fn render_scanner_tab(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(5)])
        .split(area);
    let main = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(rows[0]);

    render_finding_queue(frame, app, main[0]);
    render_triage_detail(frame, app, main[1]);
    render_controls(frame, app, rows[1]);
}

fn render_finding_queue(frame: &mut Frame, app: &App, area: Rect) {
    let findings = app.filtered_findings();
    let rows = findings.iter().map(|finding| {
        let (ai, priority, exploitability, fp) = triage_cells(app, finding);
        Row::new(vec![
            Cell::from(ai),
            Cell::from(priority),
            Cell::from(exploitability),
            Cell::from(fp),
            Cell::from(finding.issue_name.clone()),
            Cell::from(short_endpoint(&finding.url)),
        ])
        .style(finding_row_style(app, finding))
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(9),
            Constraint::Percentage(32),
            Constraint::Percentage(36),
        ],
    )
    .header(
        Row::new(["AI", "Priority", "Exploit", "FP", "Issue", "Endpoint"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(" AI Vulnerability Triage Queue ").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(if findings.is_empty() {
        None
    } else {
        Some(app.selected_finding.min(findings.len() - 1))
    });
    if let Some(selected) = state.selected() {
        let visible_rows = area.height.saturating_sub(3) as usize;
        *state.offset_mut() = selected.saturating_sub(visible_rows.saturating_sub(1));
    }
    frame.render_stateful_widget(table, area, &mut state);
}

fn triage_cells(app: &App, finding: &Finding) -> (String, String, String, String) {
    match app.finding_triage.get(&finding.id) {
        Some(FindingTriageState::Ready(triage)) => (
            "AI".to_string(),
            format_priority(triage),
            compact_or_dash(&triage.exploitability),
            compact_or_dash(&triage.false_positive_likelihood),
        ),
        Some(FindingTriageState::Loading) => (
            "...".to_string(),
            "triaging".to_string(),
            "-".to_string(),
            "-".to_string(),
        ),
        Some(FindingTriageState::Error(_)) => (
            "err".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        ),
        None => (
            "-".to_string(),
            finding.severity.label().to_string(),
            "-".to_string(),
            "-".to_string(),
        ),
    }
}

fn finding_row_style(app: &App, finding: &Finding) -> Style {
    if let Some(FindingTriageState::Ready(triage)) = app.finding_triage.get(&finding.id) {
        return priority_style(&triage.priority).add_modifier(Modifier::BOLD);
    }
    severity_style(finding.severity)
}

fn render_triage_detail(frame: &mut Frame, app: &App, area: Rect) {
    if app.scanner_ai_mode == ScannerAiMode::RulePreview {
        render_passive_rule_draft(frame, app, area);
        return;
    }
    match app.scanner_detail_mode {
        ScannerDetailMode::AiTriage => render_ai_triage(frame, app, area),
        ScannerDetailMode::Evidence => render_evidence(frame, app, area),
    }
}

fn render_ai_triage(frame: &mut Frame, app: &App, area: Rect) {
    let findings = app.filtered_findings();
    let Some(finding) = findings.get(app.selected_finding.min(findings.len().saturating_sub(1))) else {
        render_empty(frame, " AI Triage Brief ", "No scanner finding selected", area);
        return;
    };

    let mut lines = vec![finding_header(finding), Line::raw("")];
    match app.finding_triage.get(&finding.id) {
        Some(FindingTriageState::Loading) => push_loading_state(&mut lines, app.tick_count),
        Some(FindingTriageState::Ready(triage)) => push_triage_lines(&mut lines, triage),
        Some(FindingTriageState::Error(error)) => {
            lines.push(Line::styled("AI triage failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw(error.clone()));
            lines.push(Line::raw(""));
            lines.push(Line::styled("Press t to retry with local Ollama.", Style::default().fg(Color::DarkGray)));
        }
        None => push_empty_triage_state(&mut lines),
    }

    render_scrollable_lines(
        frame,
        lines,
        format!(" AI Triage Brief #{}  t triage/refresh  v evidence ", finding.id),
        app.request_scroll,
        area,
        Color::Cyan,
    );
}

fn finding_header(finding: &Finding) -> Line<'static> {
    Line::from(vec![
        Span::styled("FINDING ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(format!("#{} ", finding.id), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{} ", finding.severity.label()), severity_style(finding.severity).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{} ", finding.confidence.label()), Style::default().fg(Color::DarkGray)),
        Span::raw(finding.issue_name.clone()),
    ])
}

fn push_empty_triage_state(lines: &mut Vec<Line<'static>>) {
    lines.push(Line::styled(
        "No AI triage yet",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    ));
    lines.push(Line::raw("Press t to ask local Ollama to prioritize the selected finding."));
    lines.push(Line::raw("Press v to inspect scanner evidence and related flow context."));
    lines.push(Line::raw(""));
    lines.push(Line::styled("AI triage will produce", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    for item in [
        "Real app risk and context-dependent impact",
        "False-positive likelihood and reason",
        "Exploitability rating",
        "Proof explanation based on observed evidence",
        "Remediation and report-ready summary",
    ] {
        lines.push(Line::raw(format!("• {item}")));
    }
}

fn push_loading_state(lines: &mut Vec<Line<'static>>, tick_count: u64) {
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(tick_count as usize) % 10];
    let stage = [
        "Reviewing scanner evidence",
        "Checking related HTTP context",
        "Estimating exploitability",
        "Evaluating false-positive likelihood",
        "Drafting report-ready remediation",
    ][((tick_count / 8) as usize) % 5];
    lines.push(Line::from(vec![
        Span::styled(format!("{spinner} "), Style::default().fg(Color::Cyan)),
        Span::styled("AI triaging vulnerability finding", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::raw(format!("{stage}...")));
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "The model is asked to avoid overclaiming and to separate real risk from scanner noise.",
        Style::default().fg(Color::DarkGray),
    ));
}

fn push_triage_lines(lines: &mut Vec<Line<'static>>, triage: &FindingTriage) {
    lines.push(decision_strip(triage));
    lines.push(confidence_line(triage.confidence));
    lines.push(Line::raw(""));

    push_section(lines, "Real Risk", triage.real_risk.clone(), Color::Cyan);
    push_section(
        lines,
        "False Positive Analysis",
        format_labeled_body(&triage.false_positive_likelihood, &triage.false_positive_reason),
        Color::Yellow,
    );
    push_section(lines, "Proof Explanation", triage.proof_explanation.clone(), Color::Green);
    push_section(lines, "Impact", triage.impact.clone(), Color::Magenta);
    push_section(lines, "Remediation", triage.remediation.clone(), Color::Green);
    push_section(lines, "Report-ready Summary", triage.report_summary.clone(), Color::Cyan);
    push_string_list(lines, "Safe Validation Steps", &triage.safe_validation_steps, Color::Yellow);

    if let Some(raw_text) = &triage.raw_text {
        push_section(lines, "Unstructured AI Output", raw_text.clone(), Color::Gray);
    }
}

fn decision_strip(triage: &FindingTriage) -> Line<'static> {
    let priority = format_priority(triage);
    let exploitability = compact_or_dash(&triage.exploitability);
    let fp = compact_or_dash(&triage.false_positive_likelihood);
    Line::from(vec![
        Span::styled(format!(" {priority} "), Style::default().fg(Color::Black).bg(priority_color(&triage.priority)).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(format!(" Exploitability: {exploitability} "), Style::default().fg(Color::Black).bg(exploitability_color(&exploitability))),
        Span::raw("  "),
        Span::styled(format!(" FP: {fp} "), Style::default().fg(Color::Black).bg(false_positive_color(&fp))),
    ])
}

fn render_evidence(frame: &mut Frame, app: &App, area: Rect) {
    let findings = app.filtered_findings();
    let Some(finding) = findings.get(app.selected_finding.min(findings.len().saturating_sub(1))) else {
        render_empty(frame, " Triage Evidence ", "No scanner finding selected", area);
        return;
    };

    let mut lines = vec![finding_header(finding), Line::raw("")];
    lines.push(Line::styled("Original Scanner Assessment", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    lines.push(Line::raw(format!("Issue ID: {}", finding.issue_id)));
    lines.push(Line::raw(format!("Severity: {}", finding.severity.label())));
    lines.push(Line::raw(format!("Confidence: {}", finding.confidence.label())));
    lines.push(Line::raw(format!("URL: {}", finding.url)));
    lines.push(Line::raw(format!("Flow ID: {}", finding.flow_id)));
    lines.push(Line::raw(""));

    push_section(&mut lines, "Evidence JSON", pretty_json_or_raw(&finding.evidence_json), Color::Yellow);

    if let Some(definition) = app
        .passive_scanner
        .definitions
        .iter()
        .find(|definition| definition.id == finding.issue_id)
    {
        lines.push(Line::styled("Scanner Check Definition", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
        lines.push(Line::raw(format!("Name: {}", definition.name)));
        lines.push(Line::raw(format!("Enabled: {}", if definition.enabled { "yes" } else { "no" })));
        if !definition.references.is_empty() {
            lines.push(Line::raw(format!("References: {}", definition.references.join(", "))));
        }
        lines.push(Line::raw(""));
    }

    if let Some(flow) = app.flow_store.snapshot().iter().find(|flow| flow.id == finding.flow_id).cloned() {
        lines.push(Line::styled("Related Flow", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
        lines.push(Line::raw(format!("{} {}", flow.method, flow.uri)));
        lines.push(Line::raw(format!(
            "Status: {} | Response bytes: {} | Time: {}",
            flow.status.map(|status| status.to_string()).unwrap_or_else(|| "pending".to_string()),
            flow.response_len(),
            flow.duration_ms.map(|ms| format!("{ms}ms")).unwrap_or_else(|| "-".to_string())
        )));
        lines.push(Line::raw("Press Enter to jump to this flow, or use Proxy AI Flow Brief for request-level analysis."));
        lines.push(Line::raw(""));
    }

    render_scrollable_lines(
        frame,
        lines,
        format!(" Triage Evidence #{}  v AI triage ", finding.id),
        app.request_scroll,
        area,
        Color::Yellow,
    );
}

fn render_passive_rule_draft(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    match &app.scanner_rule_draft {
        Some(PassiveRuleDraftState::Loading) => {
            let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(app.tick_count as usize) % 10];
            lines.push(Line::styled(format!("{spinner} AI generating passive scanner YAML..."), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            lines.push(Line::styled("Checking supported check types, severity/confidence, YAML shape, and regex validity.", Style::default().fg(Color::DarkGray)));
        }
        Some(PassiveRuleDraftState::Error(error)) => {
            lines.push(Line::styled("AI passive rule generation failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw(error.clone()));
            lines.push(Line::styled("Ctrl+K retry  d/Esc discard", Style::default().fg(Color::DarkGray)));
        }
        Some(PassiveRuleDraftState::Ready(draft)) => push_passive_rule_draft_lines(&mut lines, draft),
        None => lines.push(Line::raw("No passive rule draft available")),
    }

    render_scrollable_lines(
        frame,
        lines,
        " AI Passive Rule Draft  a save  d/Esc discard ".to_string(),
        app.request_scroll,
        area,
        Color::Cyan,
    );
}

fn push_passive_rule_draft_lines(lines: &mut Vec<Line<'static>>, draft: &PassiveRuleDraft) {
    let valid = draft.validation_errors.is_empty();
    lines.push(Line::from(vec![
        Span::styled(if valid { " VALID " } else { " INVALID " }, Style::default().fg(Color::Black).bg(if valid { Color::Green } else { Color::Red }).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(if draft.rule_id.is_empty() { "<no id>" } else { draft.rule_id.as_str() }, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        draft_confidence_span(draft.confidence),
    ]));
    if !draft.explanation.trim().is_empty() {
        lines.push(Line::raw(draft.explanation.clone()));
        lines.push(Line::raw(""));
    }
    if !draft.validation_errors.is_empty() {
        push_string_list(lines, "Validation Errors", &draft.validation_errors, Color::Red);
    }
    if !draft.validation_warnings.is_empty() {
        push_string_list(lines, "Validation Warnings", &draft.validation_warnings, Color::Yellow);
    }
    if !draft.warnings.is_empty() {
        push_string_list(lines, "AI Warnings", &draft.warnings, Color::Yellow);
    }
    lines.push(Line::styled("YAML", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    for line in draft.yaml.lines().take(80) {
        lines.push(Line::raw(line.to_string()));
    }
    if !draft.test_examples.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Test Examples", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
        for test in draft.test_examples.iter().take(4) {
            lines.push(Line::raw(format!("• {} -> {}", test.description, if test.expected_match { "match" } else { "no match" })));
        }
    }
}

fn render_rule_prompt(frame: &mut Frame, app: &App, area: Rect) {
    let input = if app.scanner_ai_input.is_empty() {
        "Describe passive rule, e.g. detect debug header disclosure...".to_string()
    } else {
        format!("{} _", app.scanner_ai_input)
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("AI Rule > ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(input),
        ]),
        Line::styled("Enter generate YAML  Esc cancel  Supported: header_missing, header_contains, body_regex, status_code", Style::default().fg(Color::DarkGray)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Passive Rule Generator ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_rule_preview_controls(frame: &mut Frame, app: &App, area: Rect) {
    let status = match &app.scanner_rule_draft {
        Some(PassiveRuleDraftState::Loading) => "generating and validating rule...",
        Some(PassiveRuleDraftState::Ready(draft)) if draft.validation_errors.is_empty() => "valid rule draft; press a to save and reload",
        Some(PassiveRuleDraftState::Ready(_)) => "draft has validation errors; saving disabled",
        Some(PassiveRuleDraftState::Error(_)) => "generation failed; discard or retry",
        None => "rule preview mode",
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(" a ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" save rule  "),
            Span::styled(" d/Esc ", Style::default().fg(Color::Black).bg(Color::Red)),
            Span::raw(" discard  "),
            Span::styled(" Ctrl+K ", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" regenerate"),
        ]),
        Line::styled(format!("Status: {status}"), Style::default().fg(Color::DarkGray)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Rule Controls ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_controls(frame: &mut Frame, app: &App, area: Rect) {
    if app.scanner_ai_mode == ScannerAiMode::RulePrompt {
        render_rule_prompt(frame, app, area);
        return;
    }
    if app.scanner_ai_mode == ScannerAiMode::RulePreview {
        render_rule_preview_controls(frame, app, area);
        return;
    }

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
            Span::styled("Ctrl+K", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" AI rule  "),
            Span::styled("t", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" AI triage  "),
            Span::styled("v", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" triage/evidence  "),
            Span::styled("Enter", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" jump to flow  "),
            Span::styled("[/]", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" select check  "),
            Span::styled("e", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" enable check  "),
            Span::styled("r", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" reload defs  "),
            Span::styled("x", Style::default().fg(Color::Black).bg(Color::Magenta)),
            Span::raw(" export"),
        ]),
        Line::from(format!(
            "Filters: 0 all, i/l/m/h/c severity, 1/2/3 confidence | active severity={severity} confidence={confidence} | triaged findings sort by AI priority"
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

fn render_scrollable_lines(
    frame: &mut Frame,
    lines: Vec<Line<'static>>,
    title: String,
    scroll: u16,
    area: Rect,
    border_color: Color,
) {
    let line_count = lines.len();
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(border_color)),
        )
        .scroll((scroll, 0))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);

    let mut scrollbar = ScrollbarState::new(line_count).position(scroll as usize);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight),
        area,
        &mut scrollbar,
    );
}

fn push_section(lines: &mut Vec<Line<'static>>, title: &str, body: String, color: Color) {
    if body.trim().is_empty() {
        return;
    }
    lines.push(Line::styled(title.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)));
    for line in body.lines() {
        lines.push(Line::raw(line.to_string()));
    }
    lines.push(Line::raw(""));
}

fn push_string_list(lines: &mut Vec<Line<'static>>, title: &str, items: &[String], color: Color) {
    if items.is_empty() {
        return;
    }
    lines.push(Line::styled(title.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)));
    for item in items.iter().filter(|item| !item.trim().is_empty()) {
        lines.push(Line::raw(format!("• {item}")));
    }
    lines.push(Line::raw(""));
}

fn draft_confidence_span(confidence: Option<f32>) -> Span<'static> {
    let Some(mut value) = confidence else {
        return Span::styled("confidence: n/a", Style::default().fg(Color::DarkGray));
    };
    if value > 1.0 {
        value /= 100.0;
    }
    Span::styled(format!("confidence: {:.0}%", value.clamp(0.0, 1.0) * 100.0), Style::default().fg(Color::Green))
}

fn confidence_line(confidence: Option<f32>) -> Line<'static> {
    let Some(mut value) = confidence else {
        return Line::styled("Triage confidence: not provided", Style::default().fg(Color::DarkGray));
    };
    if value > 1.0 {
        value /= 100.0;
    }
    let value = value.clamp(0.0, 1.0);
    let filled = (value * 10.0).round() as usize;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(10usize.saturating_sub(filled)));
    Line::from(vec![
        Span::styled("Triage Confidence ", Style::default().fg(Color::DarkGray)),
        Span::styled(bar, Style::default().fg(if value >= 0.75 { Color::Green } else if value >= 0.45 { Color::Yellow } else { Color::Red })),
        Span::raw(format!(" {:.0}%", value * 100.0)),
    ])
}

fn format_labeled_body(label: &str, body: &str) -> String {
    let label = compact_or_dash(label);
    if body.trim().is_empty() {
        format!("Likelihood: {label}")
    } else {
        format!("Likelihood: {label}\n{body}")
    }
}

fn format_priority(triage: &FindingTriage) -> String {
    let priority = compact_or_dash(&triage.priority);
    let label = compact_or_dash(&triage.priority_label);
    if priority == "-" {
        label
    } else if label == "-" {
        priority
    } else {
        format!("{priority} {label}")
    }
}

fn compact_or_dash(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        "-".to_string()
    } else {
        value.chars().take(24).collect()
    }
}

fn pretty_json_or_raw(value: &str) -> String {
    serde_json::from_str::<serde_json::Value>(value)
        .and_then(|json| serde_json::to_string_pretty(&json))
        .unwrap_or_else(|_| value.to_string())
}

fn short_endpoint(url: &str) -> String {
    reqwest::Url::parse(url)
        .map(|url| {
            let mut endpoint = url.path().to_string();
            if let Some(query) = url.query() {
                endpoint.push('?');
                endpoint.push_str(query);
            }
            endpoint
        })
        .unwrap_or_else(|_| url.to_string())
}

fn render_empty(frame: &mut Frame, title: &str, message: &str, area: Rect) {
    frame.render_widget(
        Paragraph::new(message).block(Block::default().title(title).borders(Borders::ALL)),
        area,
    );
}

fn priority_style(priority: &str) -> Style {
    Style::default().fg(priority_color(priority))
}

fn priority_color(priority: &str) -> Color {
    let value = priority.to_ascii_lowercase();
    if value.starts_with("p0") || value.contains("critical") || value.starts_with("p1") || value.contains("high") {
        Color::Red
    } else if value.starts_with("p2") || value.contains("medium") {
        Color::Yellow
    } else if value.starts_with("p3") || value.contains("low") {
        Color::Blue
    } else {
        Color::Gray
    }
}

fn exploitability_color(value: &str) -> Color {
    let value = value.to_ascii_lowercase();
    if value.contains("high") {
        Color::Red
    } else if value.contains("medium") {
        Color::Yellow
    } else if value.contains("low") {
        Color::Green
    } else {
        Color::Gray
    }
}

fn false_positive_color(value: &str) -> Color {
    let value = value.to_ascii_lowercase();
    if value.contains("unlikely") {
        Color::Green
    } else if value.contains("possible") || value.contains("unknown") {
        Color::Yellow
    } else if value.contains("likely") {
        Color::Red
    } else {
        Color::Gray
    }
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
