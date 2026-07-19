use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, Wrap},
    Frame,
};
use ratatui_textarea::TextArea;

use crate::{
    app::{App, DecoderAiMode},
    models::{
        ai::{DecoderAgentResult, DecoderAgentState, DecoderChainSuggestion, DecoderChainSuggestionState},
        decoder::{apply_chain, DecoderTransform},
    },
};

pub fn render_decoder_tab(frame: &mut Frame, app: &App, area: Rect) {
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(24), Constraint::Percentage(34)])
        .split(area);
    render_input(frame, app, columns[0]);
    match app.decoder_ai_mode {
        DecoderAiMode::SuggestionPreview => render_ai_suggestion(frame, app, columns[1]),
        DecoderAiMode::AgentPreview => render_agent_workflow(frame, app, columns[1]),
        DecoderAiMode::Editing => render_chain(frame, app, columns[1]),
    }
    render_output(frame, app, columns[2]);
}

fn render_input(frame: &mut Frame, app: &App, area: Rect) {
    let mut textarea = TextArea::from(app.decoder_input.lines().map(ToOwned::to_owned).collect::<Vec<_>>());
    textarea.set_block(Block::default().title(" Input ").borders(Borders::ALL));
    textarea.set_line_number_style(Style::default().fg(Color::DarkGray));
    frame.render_widget(&textarea, area);
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

fn render_ai_suggestion(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    match &app.decoder_ai_suggestion {
        Some(DecoderChainSuggestionState::Loading) => {
            let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(app.tick_count as usize) % 10];
            lines.push(Line::styled(format!("{spinner} AI detecting encoding chain..."), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            lines.push(Line::styled("Checking JWT, Base64, URL, Hex, HTML entities, JSON...", Style::default().fg(Color::DarkGray)));
        }
        Some(DecoderChainSuggestionState::Error(error)) => {
            lines.push(Line::styled("AI decoder suggestion failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw(error.clone()));
            lines.push(Line::styled("Ctrl+K retry  d/Esc discard", Style::default().fg(Color::DarkGray)));
        }
        Some(DecoderChainSuggestionState::Ready(suggestion)) => push_decoder_suggestion_lines(&mut lines, suggestion),
        None => lines.push(Line::raw("No AI suggestion available")),
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Decode Assistant  a apply  n append  d discard ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn push_decoder_suggestion_lines(lines: &mut Vec<Line<'static>>, suggestion: &DecoderChainSuggestion) {
    let detected = if suggestion.detected_type.trim().is_empty() { "Unknown" } else { suggestion.detected_type.as_str() };
    lines.push(Line::from(vec![
        Span::styled(format!(" {detected} "), Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        confidence_span(suggestion.confidence),
    ]));
    if !suggestion.summary.trim().is_empty() {
        lines.push(Line::raw(suggestion.summary.clone()));
    }
    lines.push(Line::raw(""));
    lines.push(Line::styled("Suggested Chain", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    if suggestion.suggested_chain.is_empty() {
        lines.push(Line::styled("No transform suggested", Style::default().fg(Color::Yellow)));
    } else {
        for (index, item) in suggestion.suggested_chain.iter().enumerate() {
            lines.push(Line::from(vec![
                Span::styled(format!("{}. {}", index + 1, item.transform), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]));
            if !item.reason.trim().is_empty() {
                lines.push(Line::styled(format!("   {}", item.reason), Style::default().fg(Color::DarkGray)));
            }
        }
    }
    if !suggestion.expected_output.trim().is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Expected Output", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
        lines.push(Line::raw(suggestion.expected_output.clone()));
    }
    if !suggestion.warnings.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Warnings", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        for warning in suggestion.warnings.iter().take(4) {
            lines.push(Line::raw(format!("• {warning}")));
        }
    }
}

fn confidence_span(confidence: Option<f32>) -> Span<'static> {
    let Some(mut value) = confidence else {
        return Span::styled("confidence: n/a", Style::default().fg(Color::DarkGray));
    };
    if value > 1.0 {
        value /= 100.0;
    }
    Span::styled(format!("confidence: {:.0}%", value.clamp(0.0, 1.0) * 100.0), Style::default().fg(Color::Green))
}

fn render_agent_workflow(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    match &app.decoder_agent_result {
        Some(DecoderAgentState::Loading) => {
            let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(app.tick_count as usize) % 10];
            lines.push(Line::styled(format!("{spinner} agentic decoder running..."), Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
            lines.push(Line::styled("Trying local probes, nested chains, token structures, escapes, and AI reasoning.", Style::default().fg(Color::DarkGray)));
        }
        Some(DecoderAgentState::Error(error)) => {
            lines.push(Line::styled("AI decoder agent failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw(error.clone()));
            lines.push(Line::styled("Ctrl+G/F2 retry  d/Esc discard", Style::default().fg(Color::DarkGray)));
        }
        Some(DecoderAgentState::Ready(result)) => push_agent_result_lines(&mut lines, result),
        None => lines.push(Line::raw("No agent result available")),
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Agentic Decode Workflow  a move output  d discard ").borders(Borders::ALL).border_style(Style::default().fg(Color::Magenta)))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn push_agent_result_lines(lines: &mut Vec<Line<'static>>, result: &DecoderAgentResult) {
    let detected = if result.detected_type.trim().is_empty() { "Agent Decode" } else { result.detected_type.as_str() };
    lines.push(Line::from(vec![
        Span::styled(format!(" {detected} "), Style::default().fg(Color::Black).bg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        confidence_span(result.confidence),
    ]));
    lines.push(Line::raw(result.workflow_summary.clone()));
    lines.push(Line::raw(""));
    if !result.steps.is_empty() {
        lines.push(Line::styled("Workflow Steps", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
        for (index, step) in result.steps.iter().take(6).enumerate() {
            lines.push(Line::raw(format!("{}. {} -> {}", index + 1, step.action, step.result)));
        }
    }
    if !result.artifacts.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Artifacts", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
        for artifact in result.artifacts.iter().take(4) {
            lines.push(Line::raw(format!("• {}: {}", artifact.name, artifact.value.chars().take(120).collect::<String>())));
        }
    }
    if !result.warnings.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Warnings", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        for warning in result.warnings.iter().take(5) {
            lines.push(Line::raw(format!("• {warning}")));
        }
    }
}

fn render_output(frame: &mut Frame, app: &App, area: Rect) {
    let (title, output) = if app.decoder_ai_mode == DecoderAiMode::AgentPreview {
        match &app.decoder_agent_result {
            Some(DecoderAgentState::Ready(result)) if !result.decoded_output.trim().is_empty() => {
                (" AI Agent Decoded Output ", result.decoded_output.clone())
            }
            Some(DecoderAgentState::Ready(_)) => (" AI Agent Decoded Output ", "No final decoded output produced.".to_string()),
            Some(DecoderAgentState::Loading) => (" AI Agent Decoded Output ", "Agent is still working...".to_string()),
            Some(DecoderAgentState::Error(error)) => (" AI Agent Error ", error.clone()),
            None => (" AI Agent Decoded Output ", "No agent output.".to_string()),
        }
    } else {
        (
            " Output Preview ",
            apply_chain(&app.decoder_input, &app.decoder_chain)
                .unwrap_or_else(|error| format!("Transform error: {error}")),
        )
    };
    let help = Line::from(vec![
        Span::styled("1-0", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" add  "),
        Span::styled("Del", Style::default().fg(Color::Black).bg(Color::Red)),
        Span::raw(" remove  Alt+↑/↓ reorder  Ctrl+K suggest  Ctrl+G/F2 agent  Ctrl+D from Proxy sends body here"),
    ]);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(2)])
        .split(area);
    frame.render_widget(
        Paragraph::new(output)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        chunks[0],
    );
    frame.render_widget(Paragraph::new(help).block(Block::default().borders(Borders::ALL)), chunks[1]);
}
