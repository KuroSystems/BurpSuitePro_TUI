use bytes::Bytes;
use hyper::{header::CONTENT_TYPE, HeaderMap};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Tabs, Wrap},
    Frame,
};
use ratatui_textarea::TextArea;

use crate::{
    app::{App, RepeaterAiMode},
    models::{
        ai::{RepeaterAiDraft, RepeaterAiDraftState},
        repeater::HttpResponse,
    },
};

pub fn render_repeater_tab(frame: &mut Frame, app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(4),
        ])
        .split(area);

    render_repeater_tabs(frame, app, layout[0]);

    let panes = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(layout[1]);

    render_editor(frame, app, panes[0]);
    render_response(frame, app, panes[1]);
    render_history(frame, app, layout[2]);
}

fn render_repeater_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles = app
        .repeater_tabs
        .iter()
        .map(|tab| Line::from(tab.name.clone()))
        .collect::<Vec<_>>();
    let tabs = Tabs::new(titles)
        .block(Block::default().title(" Repeater ").borders(Borders::ALL))
        .select(app.active_repeater)
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .divider(" │ ");
    frame.render_widget(tabs, area);
}

fn render_editor(frame: &mut Frame, app: &App, area: Rect) {
    let Some(tab) = app.active_repeater_tab() else {
        return;
    };
    let mut textarea = TextArea::from(tab.request_text.lines().map(ToOwned::to_owned).collect::<Vec<_>>());
    textarea.set_block(
        Block::default()
            .title(" Request Workspace  Ctrl+K AI Builder  Ctrl+Enter send ")
            .borders(Borders::ALL),
    );
    textarea.set_line_number_style(Style::default().fg(Color::DarkGray));
    textarea.set_cursor_line_style(Style::default().bg(Color::Black));
    frame.render_widget(&textarea, area);
}

fn render_response(frame: &mut Frame, app: &App, area: Rect) {
    let Some(tab) = app.active_repeater_tab() else {
        render_empty(frame, " Response ", "No repeater tab", area);
        return;
    };

    if app.repeater_ai_mode == RepeaterAiMode::DraftPreview {
        if let Some(draft_state) = app.repeater_ai_drafts.get(&tab.id) {
            render_ai_draft(frame, app, draft_state, area);
            return;
        }
    }

    if tab.is_sending {
        render_empty(frame, " Response ", "Sending request...", area);
        return;
    }

    if let Some(error) = &tab.error {
        render_empty(frame, " Response Error ", error, area);
        return;
    }

    if let Some(response) = &tab.response {
        render_http_response(frame, response, app.repeater_response_scroll, area);
    } else {
        render_empty(frame, " Response ", "No response yet. Press Ctrl+Enter to send.", area);
    }
}

fn render_ai_draft(frame: &mut Frame, app: &App, draft_state: &RepeaterAiDraftState, area: Rect) {
    let mut lines = Vec::new();
    match draft_state {
        RepeaterAiDraftState::Loading => push_ai_draft_loading(&mut lines, app.tick_count),
        RepeaterAiDraftState::Error(error) => {
            lines.push(Line::styled("AI Request Builder failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw(error.clone()));
            lines.push(Line::raw(""));
            lines.push(Line::styled("Press Ctrl+K to try again, or Esc/d to discard this draft state.", Style::default().fg(Color::DarkGray)));
        }
        RepeaterAiDraftState::Ready(draft) => push_ai_draft_lines(&mut lines, draft),
    }

    let line_count = lines.len();
    let paragraph = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" AI Request Draft  a apply  n new tab  d/Esc discard ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .scroll((app.repeater_response_scroll, 0))
        .wrap(Wrap { trim: false });
    frame.render_widget(paragraph, area);
    let mut scrollbar = ScrollbarState::new(line_count).position(app.repeater_response_scroll as usize);
    frame.render_stateful_widget(
        Scrollbar::new(ScrollbarOrientation::VerticalRight),
        area,
        &mut scrollbar,
    );
}

fn push_ai_draft_loading(lines: &mut Vec<Line<'static>>, tick_count: u64) {
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(tick_count as usize) % 10];
    let stage = [
        "Reading raw HTTP structure",
        "Preserving auth/session placeholders",
        "Applying requested mutation",
        "Checking safety notes",
        "Preparing draft preview",
    ][((tick_count / 8) as usize) % 5];
    lines.push(Line::from(vec![
        Span::styled(format!("{spinner} "), Style::default().fg(Color::Cyan)),
        Span::styled("AI building request draft", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::raw(format!("{stage}...")));
    lines.push(Line::raw(""));
    lines.push(Line::styled(
        "Draft only. The request will not be sent until you apply it and press Ctrl+Enter.",
        Style::default().fg(Color::DarkGray),
    ));
}

fn push_ai_draft_lines(lines: &mut Vec<Line<'static>>, draft: &RepeaterAiDraft) {
    lines.push(Line::from(vec![
        Span::styled("DRAFT READY ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        confidence_span(draft.confidence),
    ]));
    lines.push(Line::raw(""));
    push_list_section(lines, "Change Summary", &draft.change_summary, Color::Green);
    push_list_section(lines, "Preserved Sensitive Items", &draft.preserved_sensitive_items, Color::Magenta);
    push_list_section(lines, "Warnings", &draft.warnings, Color::Yellow);
    push_list_section(lines, "Safety Notes", &draft.safety_notes, Color::Cyan);

    lines.push(Line::styled("Modified Raw HTTP Request", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    for line in draft.modified_request.lines() {
        lines.push(Line::raw(line.to_string()));
    }

    if let Some(raw_text) = &draft.raw_text {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Unstructured AI Output", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)));
        for line in raw_text.lines() {
            lines.push(Line::raw(line.to_string()));
        }
    }
}

fn push_list_section(lines: &mut Vec<Line<'static>>, title: &str, items: &[String], color: Color) {
    if items.is_empty() {
        return;
    }
    lines.push(Line::styled(title.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)));
    for item in items.iter().filter(|item| !item.trim().is_empty()) {
        lines.push(Line::raw(format!("• {item}")));
    }
    lines.push(Line::raw(""));
}

fn confidence_span(confidence: Option<f32>) -> Span<'static> {
    let Some(mut value) = confidence else {
        return Span::styled("confidence: n/a", Style::default().fg(Color::DarkGray));
    };
    if value > 1.0 {
        value /= 100.0;
    }
    let value = value.clamp(0.0, 1.0);
    Span::styled(
        format!("confidence: {:.0}%", value * 100.0),
        Style::default().fg(if value >= 0.75 { Color::Green } else if value >= 0.45 { Color::Yellow } else { Color::Red }),
    )
}

fn render_http_response(frame: &mut Frame, response: &HttpResponse, scroll: u16, area: Rect) {
    let mut lines = vec![Line::from(vec![
        Span::styled(
            format!("HTTP {}", response.status),
            Style::default().fg(status_color(response.status)).add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" {}  ", response.reason)),
        Span::styled(
            format!("{}ms  {} bytes", response.duration_ms, response.body_len()),
            Style::default().fg(Color::DarkGray),
        ),
    ])];
    lines.push(Line::raw(""));
    for (name, value) in response.headers.iter() {
        lines.push(Line::from(vec![
            Span::styled(format!("{}: ", name.as_str()), Style::default().fg(Color::Yellow)),
            Span::raw(value.to_str().unwrap_or("<binary>")),
        ]));
    }
    lines.push(Line::raw(""));
    let body_text = render_body(&response.headers, &response.body);
    lines.extend(body_text.lines().map(|line| Line::raw(line.to_string())));

    let line_count = lines.len();
    let paragraph = Paragraph::new(lines)
        .block(Block::default().title(" Response ").borders(Borders::ALL))
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

fn render_history(frame: &mut Frame, app: &App, area: Rect) {
    let Some(tab) = app.active_repeater_tab() else {
        return;
    };

    if app.repeater_ai_mode == RepeaterAiMode::Prompt {
        render_ai_prompt(frame, app, area);
        return;
    }

    if app.repeater_ai_mode == RepeaterAiMode::DraftPreview {
        render_ai_draft_controls(frame, app, area);
        return;
    }

    let rename = if app.renaming_repeater {
        format!("  renaming: {}_", app.rename_buffer)
    } else {
        String::new()
    };
    let mut spans = vec![
        Span::styled(" Ctrl+T ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" new from selection  "),
        Span::styled(" Ctrl+W ", Style::default().fg(Color::Black).bg(Color::Red)),
        Span::raw(" close  "),
        Span::styled(" F2 ", Style::default().fg(Color::Black).bg(Color::Yellow)),
        Span::raw(" rename  "),
        Span::styled(" Ctrl+←/→ ", Style::default().fg(Color::Black).bg(Color::Green)),
        Span::raw(" tab  "),
        Span::raw(rename),
    ];

    if !tab.history.is_empty() {
        spans.push(Span::raw(" history: "));
        for entry in tab.history.iter().rev().take(5) {
            let label = if let Some(error) = &entry.error {
                format!(" ERR:{} ", truncate(error, 18))
            } else {
                format!(
                    " {} {}ms {}b ",
                    entry.status.unwrap_or_default(),
                    entry.duration_ms.unwrap_or_default(),
                    entry.body_len
                )
            };
            spans.push(Span::styled(label, Style::default().fg(Color::Gray)));
        }
    }

    frame.render_widget(
        Paragraph::new(Line::from(spans))
            .block(Block::default().title(" Send History ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_ai_prompt(frame: &mut Frame, app: &App, area: Rect) {
    let input = if app.repeater_ai_input.is_empty() {
        "Describe the request change, e.g. preserve auth but set user_id to 2...".to_string()
    } else {
        format!("{} _", app.repeater_ai_input)
    };
    let lines = vec![
        Line::from(vec![
            Span::styled("AI Builder > ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(input),
        ]),
        Line::styled(
            "Enter build draft  Esc cancel  Examples: JSON content-type | SQLi payload | GraphQL introspection | CSRF test candidate",
            Style::default().fg(Color::DarkGray),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Request Builder ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_ai_draft_controls(frame: &mut Frame, app: &App, area: Rect) {
    let status = app
        .active_repeater_tab()
        .and_then(|tab| app.repeater_ai_drafts.get(&tab.id))
        .map(|state| match state {
            RepeaterAiDraftState::Loading => "building draft...",
            RepeaterAiDraftState::Ready(_) => "draft ready; review before applying",
            RepeaterAiDraftState::Error(_) => "draft failed; discard or retry",
        })
        .unwrap_or("draft mode");
    let lines = vec![
        Line::from(vec![
            Span::styled(" a ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" apply to current request  "),
            Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" open in new tab  "),
            Span::styled(" d/Esc ", Style::default().fg(Color::Black).bg(Color::Red)),
            Span::raw(" discard  "),
            Span::styled(" Ctrl+K ", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" rebuild"),
        ]),
        Line::styled(
            format!("Status: {status}. Draft is never sent automatically; apply/new tab first, then Ctrl+Enter."),
            Style::default().fg(Color::DarkGray),
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Draft Controls ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_empty(frame: &mut Frame, title: &str, message: &str, area: Rect) {
    frame.render_widget(
        Paragraph::new(message)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn status_color(status: u16) -> Color {
    match status {
        200..=299 => Color::Green,
        300..=399 => Color::Yellow,
        400..=499 => Color::LightRed,
        500..=599 => Color::Red,
        _ => Color::Gray,
    }
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

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        value.to_string()
    } else {
        format!("{}…", &value[..max])
    }
}
