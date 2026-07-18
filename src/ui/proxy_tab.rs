use bytes::Bytes;
use hyper::{header::CONTENT_TYPE, HeaderMap};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Scrollbar, ScrollbarOrientation, ScrollbarState, Table, TableState, Wrap},
    Frame,
};

use crate::{app::App, models::flow::HttpFlow};

pub fn render_proxy_tab(frame: &mut Frame, app: &App, area: Rect) {
    let flows = app.flow_store.snapshot();
    let filtered_indices = flows
        .iter()
        .enumerate()
        .filter_map(|(index, flow)| flow.matches_query(&app.search_query).then_some(index))
        .collect::<Vec<_>>();

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
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
        let style = if app.scope_engine.is_in_scope(&flow.uri) {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        Some(Row::new(vec![
            Cell::from(flow.id.to_string()),
            Cell::from(flow.method.clone()),
            Cell::from(flow.host()),
            Cell::from(flow.path()),
            Cell::from(flow.status.map(|s| s.to_string()).unwrap_or_else(|| "-".into())),
            Cell::from(flow.response_len().to_string()),
            Cell::from(flow.duration_ms.map(|ms| format!("{ms}ms")).unwrap_or_else(|| "-".into())),
        ]).style(style))
    });

    let title = if app.search_query.is_empty() {
        " Traffic ".to_string()
    } else {
        format!(" Traffic /{} ", app.search_query)
    };

    let table = Table::new(
        rows,
        [
            Constraint::Length(5),
            Constraint::Length(7),
            Constraint::Percentage(26),
            Constraint::Percentage(34),
            Constraint::Length(6),
            Constraint::Length(7),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(["#", "Method", "Host", "Path", "Status", "Length", "Time"])
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
    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    if let Some(flow) = flow {
        render_message(
            frame,
            " Request ",
            &flow.request_headers,
            &flow.request_body,
            app.request_scroll,
            panes[0],
        );

        if let (Some(headers), Some(body)) = (&flow.response_headers, &flow.response_body) {
            render_message(frame, " Response ", headers, body, app.response_scroll, panes[1]);
        } else {
            render_empty(frame, " Response ", "No response captured yet", panes[1]);
        }
    } else {
        render_empty(frame, " Request ", "No flow selected", panes[0]);
        render_empty(frame, " Response ", "No flow selected", panes[1]);
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
            Span::raw(value.to_str().unwrap_or("<binary>")),
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
