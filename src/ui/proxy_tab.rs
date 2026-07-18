use bytes::Bytes;
use hyper::{header::CONTENT_TYPE, HeaderMap};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap},
    Frame,
};

use crate::{
    app::{App, ProxyDetailMode},
    models::{
        ai::{FlowExplanation, FlowExplanationState},
        flow::HttpFlow,
    },
};

pub fn render_proxy_tab(frame: &mut Frame, app: &App, area: Rect) {
    let flows = app.flow_store.snapshot();
    let filtered_indices = flows
        .iter()
        .enumerate()
        .filter_map(|(index, flow)| flow.matches_query(&app.search_query).then_some(index))
        .collect::<Vec<_>>();

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(area);

    render_traffic_table(frame, app, &flows, &filtered_indices, columns[0]);
    render_detail_pane(frame, app, flows.get(app.selected_flow.unwrap_or(usize::MAX)), columns[1]);
}

fn render_traffic_table(
    frame: &mut Frame,
    app: &App,
    flows: &[HttpFlow],
    filtered_indices: &[usize],
    area: Rect,
) {
    let rows = filtered_indices.iter().filter_map(|index| {
        let flow = flows.get(*index)?;
        let scope_style = if app.scope_engine.is_in_scope(&flow.uri) {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let ai_state = match app.flow_ai_explanations.get(&flow.id) {
            Some(FlowExplanationState::Ready(_)) => "AI",
            Some(FlowExplanationState::Loading) => "...",
            Some(FlowExplanationState::Error(_)) => "err",
            None => "-",
        };
        Some(
            Row::new(vec![
                Cell::from(flow.id.to_string()),
                Cell::from(ai_state),
                Cell::from(flow.method.clone()),
                Cell::from(flow.host()),
                Cell::from(flow.path()),
                Cell::from(flow.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into())),
                Cell::from(flow.response_len().to_string()),
            ])
            .style(scope_style),
        )
    });

    let title = if app.search_query.is_empty() {
        " Traffic Intelligence ".to_string()
    } else {
        format!(" Traffic Intelligence /{} ", app.search_query)
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(4),
            Constraint::Length(7),
            Constraint::Percentage(26),
            Constraint::Percentage(38),
            Constraint::Length(6),
            Constraint::Length(7),
        ],
    )
    .header(
        Row::new(["#", "AI", "Method", "Host", "Endpoint", "Status", "Bytes"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(title).borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");

    let selected_pos = app
        .selected_flow
        .and_then(|selected| filtered_indices.iter().position(|index| *index == selected));
    let mut state = TableState::default().with_selected(selected_pos);
    if let Some(selected) = selected_pos {
        let visible_rows = area.height.saturating_sub(3) as usize;
        *state.offset_mut() = selected.saturating_sub(visible_rows.saturating_sub(1));
    }

    frame.render_stateful_widget(table, area, &mut state);
}

fn render_detail_pane(frame: &mut Frame, app: &App, flow: Option<&HttpFlow>, area: Rect) {
    match app.proxy_detail_mode {
        ProxyDetailMode::AiBrief => render_ai_flow_brief(frame, app, flow, area),
        ProxyDetailMode::RawEvidence => render_raw_evidence(frame, app, flow, area),
    }
}

fn render_ai_flow_brief(frame: &mut Frame, app: &App, flow: Option<&HttpFlow>, area: Rect) {
    let Some(flow) = flow else {
        render_empty(frame, " AI Flow Brief ", "No flow selected", area);
        return;
    };

    let mut lines = vec![selected_flow_header(flow), Line::raw("")];
    match app.flow_ai_explanations.get(&flow.id) {
        Some(FlowExplanationState::Loading) => push_loading_state(&mut lines, app.tick_count),
        Some(FlowExplanationState::Ready(explanation)) => push_explanation_lines(&mut lines, explanation),
        Some(FlowExplanationState::Error(error)) => {
            lines.push(Line::styled("Analysis failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw(error.clone()));
            lines.push(Line::raw(""));
            lines.push(Line::styled("Press e to retry with local Ollama.", Style::default().fg(Color::DarkGray)));
        }
        None => push_empty_ai_state(&mut lines),
    }

    let line_count = lines.len();
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(format!(" AI Flow Brief #{}  e analyze/refresh  r raw evidence ", flow.id))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .scroll((app.request_scroll, 0))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, area);

    let mut scrollbar = ScrollbarState::new(line_count).position(app.request_scroll as usize);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight),
        area,
        &mut scrollbar,
    );
}

fn selected_flow_header(flow: &HttpFlow) -> Line<'static> {
    Line::from(vec![
        Span::styled("FLOW ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(format!("#{} ", flow.id), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::styled(format!("{} ", flow.method), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(flow.path()),
        Span::raw("  "),
        Span::styled(
            flow.status.map(|status| status.to_string()).unwrap_or_else(|| "pending".to_string()),
            Style::default().fg(status_color(flow.status)),
        ),
        Span::raw(format!("  {} bytes", flow.response_len())),
    ])
}

fn status_color(status: Option<u16>) -> Color {
    match status {
        Some(200..=299) => Color::Green,
        Some(300..=399) => Color::Cyan,
        Some(400..=499) => Color::Yellow,
        Some(500..=599) => Color::Red,
        _ => Color::Gray,
    }
}

fn push_empty_ai_state(lines: &mut Vec<Line<'static>>) {
    lines.push(Line::styled(
        "No AI brief yet",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    ));
    lines.push(Line::raw("Press e to explain the selected request/response with local Ollama."));
    lines.push(Line::raw("Raw HTTP stays available as Evidence mode; press r to inspect it."));
    lines.push(Line::raw(""));
    lines.push(Line::styled("What the brief will cover", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    for item in [
        "Request purpose and likely workflow",
        "Headers, cookies, sessions, and token roles",
        "Suspicious or high-value parameters",
        "Interesting endpoints and auth boundaries",
        "Response tech stack hints and safe next steps",
    ] {
        lines.push(Line::raw(format!("• {item}")));
    }
}

fn push_loading_state(lines: &mut Vec<Line<'static>>, tick_count: u64) {
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(tick_count as usize) % 10];
    let stage = [
        "Reading request purpose",
        "Inspecting headers and cookies",
        "Checking auth/session signals",
        "Looking for interesting parameters",
        "Extracting response tech hints",
    ][((tick_count / 8) as usize) % 5];
    lines.push(Line::from(vec![
        Span::styled(format!("{spinner} "), Style::default().fg(Color::Cyan)),
        Span::styled("AI analyzing selected flow", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::raw(format!("{stage}...")));
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Local Ollama is generating an evidence-backed explanation. Sensitive values are redacted before context is sent.",
        Style::default().fg(Color::DarkGray),
    ));
}

fn push_explanation_lines(lines: &mut Vec<Line<'static>>, explanation: &FlowExplanation) {
    lines.push(confidence_line(explanation.confidence));
    lines.push(Line::raw(""));

    push_section(lines, "Purpose", explanation.purpose.clone(), Color::Cyan);
    push_section(lines, "Request Summary", explanation.request_summary.clone(), Color::Green);
    push_header_meanings(lines, explanation);
    push_section(
        lines,
        "Cookies / Session Tokens",
        explanation.cookies_session_tokens.clone(),
        Color::Magenta,
    );
    push_parameters(lines, explanation);
    push_endpoints(lines, explanation);
    push_section(lines, "Auth Observations", explanation.auth_observations.clone(), Color::Yellow);
    push_string_list(lines, "Response Tech Hints", &explanation.response_tech_hints, Color::Cyan);
    push_section(lines, "Risk Notes", explanation.risk_notes.clone(), Color::Yellow);
    push_string_list(lines, "Safe Next Steps", &explanation.safe_next_steps, Color::Green);

    if let Some(raw_text) = &explanation.raw_text {
        push_section(lines, "Unstructured AI Output", raw_text.clone(), Color::Gray);
    }
}

fn confidence_line(confidence: Option<f32>) -> Line<'static> {
    let Some(mut value) = confidence else {
        return Line::styled("Confidence: not provided", Style::default().fg(Color::DarkGray));
    };
    if value > 1.0 {
        value /= 100.0;
    }
    let value = value.clamp(0.0, 1.0);
    let filled = (value * 10.0).round() as usize;
    let bar = format!("{}{}", "█".repeat(filled), "░".repeat(10usize.saturating_sub(filled)));
    Line::from(vec![
        Span::styled("Confidence ", Style::default().fg(Color::DarkGray)),
        Span::styled(bar, Style::default().fg(if value >= 0.75 { Color::Green } else if value >= 0.45 { Color::Yellow } else { Color::Red })),
        Span::raw(format!(" {:.0}%", value * 100.0)),
    ])
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

fn push_header_meanings(lines: &mut Vec<Line<'static>>, explanation: &FlowExplanation) {
    if explanation.headers_meaning.is_empty() {
        return;
    }
    lines.push(Line::styled("Headers Meaning", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    for header in &explanation.headers_meaning {
        let name = if header.header.trim().is_empty() { "header" } else { header.header.trim() };
        lines.push(Line::from(vec![
            Span::styled(format!("• {name}: "), Style::default().fg(Color::Yellow)),
            Span::raw(header.meaning.clone()),
        ]));
        if !header.evidence.trim().is_empty() {
            lines.push(Line::styled(format!("  evidence: {}", header.evidence), Style::default().fg(Color::DarkGray)));
        }
    }
    lines.push(Line::raw(""));
}

fn push_parameters(lines: &mut Vec<Line<'static>>, explanation: &FlowExplanation) {
    if explanation.suspicious_parameters.is_empty() {
        return;
    }
    lines.push(Line::styled(
        "Suspicious / Interesting Parameters",
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
    ));
    for parameter in &explanation.suspicious_parameters {
        let name = if parameter.name.trim().is_empty() { "parameter" } else { parameter.name.trim() };
        let confidence = if parameter.confidence.trim().is_empty() {
            "unknown"
        } else {
            parameter.confidence.trim()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("• {name} "), Style::default().fg(Color::Yellow)),
            Span::styled(format!("[{confidence}] "), Style::default().fg(Color::Magenta)),
            Span::raw(parameter.reason.clone()),
        ]));
        if !parameter.evidence.trim().is_empty() {
            lines.push(Line::styled(format!("  evidence: {}", parameter.evidence), Style::default().fg(Color::DarkGray)));
        }
    }
    lines.push(Line::raw(""));
}

fn push_endpoints(lines: &mut Vec<Line<'static>>, explanation: &FlowExplanation) {
    if explanation.interesting_endpoints.is_empty() {
        return;
    }
    lines.push(Line::styled("Interesting Endpoints", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    for endpoint in &explanation.interesting_endpoints {
        let name = if endpoint.endpoint.trim().is_empty() { "endpoint" } else { endpoint.endpoint.trim() };
        lines.push(Line::from(vec![
            Span::styled(format!("• {name}: "), Style::default().fg(Color::Cyan)),
            Span::raw(endpoint.reason.clone()),
        ]));
        if !endpoint.evidence.trim().is_empty() {
            lines.push(Line::styled(format!("  evidence: {}", endpoint.evidence), Style::default().fg(Color::DarkGray)));
        }
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

fn render_raw_evidence(frame: &mut Frame, app: &App, flow: Option<&HttpFlow>, area: Rect) {
    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(flow) = flow {
        render_message(
            frame,
            " Request Evidence  r AI brief ",
            &flow.request_headers,
            &flow.request_body,
            app.request_scroll,
            panes[0],
        );

        if let (Some(headers), Some(body)) = (&flow.response_headers, &flow.response_body) {
            render_message(frame, " Response Evidence  r AI brief ", headers, body, app.response_scroll, panes[1]);
        } else {
            render_empty(frame, " Response Evidence ", "No response captured yet", panes[1]);
        }
    } else {
        render_empty(frame, " Request Evidence ", "No flow selected", panes[0]);
        render_empty(frame, " Response Evidence ", "No flow selected", panes[1]);
    }
}

fn render_message(
    frame: &mut Frame,
    title: &str,
    headers: &HeaderMap,
    body: &Bytes,
    scroll: u16,
    area: Rect,
) {
    let mut lines = Vec::new();
    for (name, value) in headers.iter() {
        lines.push(Line::from(vec![
            Span::styled(format!("{}: ", name.as_str()), Style::default().fg(Color::Yellow)),
            Span::raw(value.to_str().unwrap_or("<binary>").to_string()),
        ]));
    }
    lines.push(Line::raw(""));
    let body_text = render_body(headers, body);
    lines.extend(body_text.lines().map(|line| Line::raw(line.to_string())));

    let line_count = lines.len();
    let paragraph = Paragraph::new(lines)
        .block(Block::default().title(title).borders(Borders::ALL))
        .scroll((scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);

    let mut scrollbar = ScrollbarState::new(line_count).position(scroll as usize);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight),
        area,
        &mut scrollbar,
    );
}

fn render_empty(frame: &mut Frame, title: &str, message: &str, area: Rect) {
    frame.render_widget(
        Paragraph::new(message).block(Block::default().title(title).borders(Borders::ALL)),
        area,
    );
}

fn render_body(headers: &HeaderMap, body: &Bytes) -> String {
    if body.is_empty() {
        return "<empty body>".to_string();
    }

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();

    if content_type.contains("application/json") || looks_like_json(body) {
        return serde_json::from_slice::<serde_json::Value>(body)
            .and_then(|value| serde_json::to_string_pretty(&value))
            .unwrap_or_else(|_| String::from_utf8_lossy(body).into_owned());
    }

    if content_type.starts_with("text/")
        || content_type.contains("html")
        || content_type.contains("xml")
        || content_type.contains("javascript")
    {
        return String::from_utf8_lossy(body).into_owned();
    }

    hex_preview(body)
}

fn looks_like_json(body: &Bytes) -> bool {
    body.iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte == b'{' || byte == b'[')
        .unwrap_or(false)
}

fn hex_preview(body: &Bytes) -> String {
    let mut output = String::new();
    for (offset, chunk) in body.chunks(16).take(256).enumerate() {
        output.push_str(&format!("{:08x}  ", offset * 16));
        for byte in chunk {
            output.push_str(&format!("{byte:02x} "));
        }
        output.push('\n');
    }
    if body.len() > 4096 {
        output.push_str("... truncated ...\n");
    }
    output
}
