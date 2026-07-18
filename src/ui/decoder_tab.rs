use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, Wrap},
    Frame,
};
use ratatui_textarea::TextArea;

use crate::{
    app::App,
    models::decoder::{apply_chain, DecoderTransform},
};

pub fn render_decoder_tab(frame: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(24), Constraint::Percentage(34)])
        .split(area);
    render_input(frame, app, columns[0]);
    render_chain(frame, app, columns[1]);
    render_output(frame, app, columns[2]);
}

fn render_input(frame: &mut Frame, app: &App, area: Rect) {
    let mut textarea = TextArea::from(app.decoder_input.lines().map(ToOwned::to_owned).collect::<Vec<_>>());
    textarea.set_block(Block::default().title(" Input ").borders(Borders::ALL));
    textarea.set_line_number_style(Style::default().fg(Color::DarkGray));
    frame.render_widget(textarea.widget(), area);
}

fn render_chain(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let items = app
        .decoder_chain
        .iter()
        .enumerate()
        .map(|(index, transform)| ListItem::new(format!("{}  {}", index + 1, transform.label())))
        .collect::<Vec<_>>();
    let list = List::new(items)
        .block(Block::default().title(" Transform Chain ").borders(Borders::ALL))
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .highlight_symbol("▶ ");
    let mut state = ListState::default().with_selected((!app.decoder_chain.is_empty()).then_some(app.selected_decoder_transform));
    frame.render_stateful_widget(list, chunks[0], &mut state);

    let rows = DecoderTransform::ALL.iter().enumerate().map(|(index, transform)| {
        let key = match index {
            0..=8 => (index + 1).to_string(),
            9 => "0".to_string(),
            _ => "p".to_string(),
        };
        Row::new([Cell::from(key), Cell::from(transform.label())])
    });
    let table = Table::new(rows, [Constraint::Length(3), Constraint::Min(10)])
        .block(Block::default().title(" Add Transform ").borders(Borders::ALL));
    frame.render_widget(table, chunks[1]);
}

fn render_output(frame: &mut Frame, app: &App, area: Rect) {
    let output = apply_chain(&app.decoder_input, &app.decoder_chain)
        .unwrap_or_else(|error| format!("Transform error: {error}"));
    let help = Line::from(vec![
        Span::styled("1-0", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" add  "),
        Span::styled("Del", Style::default().fg(Color::Black).bg(Color::Red)),
        Span::raw(" remove  Alt+↑/↓ reorder  Ctrl+D from Proxy sends body here"),
    ]);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .split(area);
    frame.render_widget(
        Paragraph::new(output)
            .block(Block::default().title(" Output Preview ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(help).block(Block::default().borders(Borders::ALL)), chunks[1]);
}
