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

use crate::{app::App, models::repeater::HttpResponse};

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
            .title(" Raw HTTP Request  Ctrl+Enter send ")
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
