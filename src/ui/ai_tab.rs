use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::{
    app::App,
    models::ai::{AiRole, QUICK_PROMPTS},
};

pub fn render_ai_tab(frame: &mut Frame, app: &App, area: Rect) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(5)])
        .split(area);
    render_header(frame, app, outer[0]);

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(32), Constraint::Percentage(68)])
        .split(outer[1]);
    render_context(frame, app, middle[0]);
    render_conversation(frame, app, middle[1]);
    render_prompt(frame, app, outer[2]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let waiting = if app.ai_panel.is_waiting { " ⠋ thinking" } else { " ready" };
    let line = Line::from(vec![
        Span::styled(" Proxima AI Analyst ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("  model: "),
        Span::styled(&app.ai_panel.settings.model, Style::default().fg(Color::Green)),
        Span::raw("  ollama: "),
        Span::raw(&app.ai_panel.settings.ollama_url),
        Span::raw("  status: "),
        Span::styled(waiting, Style::default().fg(if app.ai_panel.is_waiting { Color::Yellow } else { Color::Gray })),
        Span::raw("  redaction: "),
        Span::styled(
            if app.ai_panel.settings.redaction_enabled { "on" } else { "off" },
            Style::default().fg(Color::Magenta),
        ),
    ]);
    frame.render_widget(Paragraph::new(line).block(Block::default().borders(Borders::ALL)), area);
}

fn render_context(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    if let Some(context) = &app.ai_panel.attached_context {
        lines.push(Line::styled(&context.title, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
        lines.push(Line::raw(""));
        lines.extend(context.summary.lines().map(|line| Line::raw(line.to_string())));
        lines.push(Line::raw(""));
        lines.push(Line::styled("Raw context is redacted and hidden by default.", Style::default().fg(Color::DarkGray)));
    } else {
        lines.push(Line::styled("No context attached", Style::default().fg(Color::Yellow)));
        lines.push(Line::raw("Select a Proxy flow and press Ctrl+A here, or Ctrl+D/Ctrl+M from Proxy for other AI-assisted workflows."));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled("Quick prompts", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    for (index, prompt) in QUICK_PROMPTS.iter().enumerate() {
        lines.push(Line::from(vec![
            Span::styled(format!("Alt+{} ", index + 1), Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(*prompt),
        ]));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Attached Context ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_conversation(frame: &mut Frame, app: &App, area: Rect) {
    let items = app
        .ai_panel
        .messages
        .iter()
        .rev()
        .take(24)
        .rev()
        .map(|message| {
            let style = match message.role {
                AiRole::User => Style::default().fg(Color::Green),
                AiRole::Assistant => Style::default().fg(Color::Cyan),
                AiRole::System => Style::default().fg(Color::DarkGray),
            };
            ListItem::new(vec![
                Line::from(vec![
                    Span::styled(message.role.label(), style.add_modifier(Modifier::BOLD)),
                    Span::raw(format!("  {}", message.timestamp.format("%H:%M:%S"))),
                ]),
                Line::raw(message.content.clone()),
                Line::raw(""),
            ])
        })
        .collect::<Vec<_>>();

    frame.render_widget(
        List::new(items).block(Block::default().title(" Conversation ").borders(Borders::ALL)),
        area,
    );
}

fn render_prompt(frame: &mut Frame, app: &App, area: Rect) {
    let help = "Enter/Ctrl+Enter send  Alt+Enter newline  Ctrl+A attach flow  Alt+1..6 quick prompts  Left/Right tabs";
    let input = if app.ai_panel.input.is_empty() {
        "Ask about selected flow, finding impact, next safe step, or payload ideas...".to_string()
    } else {
        app.ai_panel.input.clone()
    };
    let lines = vec![
        Line::styled(help, Style::default().fg(Color::DarkGray)),
        Line::raw(input),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Prompt ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}
