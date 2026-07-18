use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Row, Table, TableState},
    Frame,
};

use crate::{app::App, models::websocket::WebSocketDirection};

pub fn render_websocket_tab(frame: &mut Frame, app: &App, area: Rect) {
    let frames = app.flow_store.websocket_snapshot();
    let rows = frames.iter().map(|frame| {
        Row::new(vec![
            Cell::from(frame.id.to_string()),
            Cell::from(frame.timestamp.format("%H:%M:%S").to_string()),
            Cell::from(frame.direction.label()),
            Cell::from(frame.opcode.clone()),
            Cell::from(frame.length.to_string()),
            Cell::from(frame.url.clone()),
            Cell::from(frame.payload_preview.clone()),
        ])
        .style(match frame.direction {
            WebSocketDirection::ClientToServer => Style::default().fg(Color::Cyan),
            WebSocketDirection::ServerToClient => Style::default().fg(Color::Green),
        })
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(6),
            Constraint::Length(10),
            Constraint::Length(16),
            Constraint::Length(12),
            Constraint::Length(8),
            Constraint::Percentage(28),
            Constraint::Percentage(36),
        ],
    )
    .header(
        Row::new(["#", "Time", "Direction", "Opcode", "Length", "URL", "Payload Preview"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(" WebSocket Frames ").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(if frames.is_empty() {
        None
    } else {
        Some(app.websocket_selected_frame.min(frames.len() - 1))
    });
    frame.render_stateful_widget(table, area, &mut state);
}
