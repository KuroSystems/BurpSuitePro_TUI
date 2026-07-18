use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};

use crate::{app::App, plugins::PluginManager};

pub fn render_plugin_tab(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(35), Constraint::Length(6)])
        .split(area);
    render_plugins(frame, app, chunks[0]);
    render_logs(frame, app, chunks[1]);
    render_help(frame, app, chunks[2]);
}

fn render_plugins(frame: &mut Frame, app: &App, area: Rect) {
    let rows = app.plugin_manager.plugins.iter().map(|plugin| {
        Row::new(vec![
            Cell::from(if plugin.enabled { "yes" } else { "no" }),
            Cell::from(plugin.manifest.id.clone()),
            Cell::from(plugin.manifest.name.clone()),
            Cell::from(plugin.manifest.version.clone()),
            Cell::from(plugin.manifest.hooks.iter().map(|hook| format!("{hook:?}")).collect::<Vec<_>>().join(",")),
            Cell::from(plugin.wasm_path.display().to_string()),
        ])
        .style(if plugin.enabled { Style::default() } else { Style::default().fg(Color::DarkGray) })
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(20),
            Constraint::Length(24),
            Constraint::Length(10),
            Constraint::Length(28),
            Constraint::Percentage(40),
        ],
    )
    .header(Row::new(["Enabled", "ID", "Name", "Version", "Hooks", "WASM"]).style(Style::default().fg(Color::Cyan)))
    .block(Block::default().title(" WASM Plugins ").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(if app.plugin_manager.plugins.is_empty() {
        None
    } else {
        Some(app.selected_plugin.min(app.plugin_manager.plugins.len() - 1))
    });
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_logs(frame: &mut Frame, app: &App, area: Rect) {
    let items = app
        .plugin_manager
        .logs
        .iter()
        .rev()
        .take(12)
        .map(|entry| {
            ListItem::new(format!(
                "{} [{}] {}",
                entry.timestamp.format("%H:%M:%S"),
                entry.plugin_id,
                entry.message
            ))
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        List::new(items).block(Block::default().title(" Plugin Logs ").borders(Borders::ALL)),
        area,
    );
}

fn render_help(frame: &mut Frame, app: &App, area: Rect) {
    let exports = PluginManager::host_exports().join(", ");
    let lines = vec![
        Line::from(vec![
            Span::styled("r", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" reload  "),
            Span::styled("e/Space", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" enable/disable  j/k navigate"),
        ]),
        Line::from(format!("Plugin directory: {}", app.plugin_manager.plugin_dir.display())),
        Line::from(format!("Host exports: {exports}")),
        Line::from("Manifest sidecar: plugin.wasm + plugin.json with id/name/version/hooks."),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Plugin API ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}
