use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use ratatui_textarea::TextArea;

use crate::{
    app::{App, ComparerDetailMode},
    models::{
        ai::{ComparerSummary, ComparerSummaryState},
        comparer::CompareMode,
    },
};

pub fn render_comparer_tab(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(52), Constraint::Length(3)])
        .split(area);
    let inputs = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[0]);
    render_input(frame, " Left ", &app.comparer_left, !app.comparer_focus_right, inputs[0]);
    render_input(frame, " Right ", &app.comparer_right, app.comparer_focus_right, inputs[1]);
    if app.comparer_detail_mode == ComparerDetailMode::AiSummary {
        render_ai_summary(frame, app, rows[1]);
    } else {
        render_diff(frame, app, rows[1]);
    }
    render_help(frame, app, rows[2]);
}

fn render_input(frame: &mut Frame, title: &str, value: &str, focused: bool, area: Rect) {
    let mut textarea = TextArea::from(value.lines().map(ToOwned::to_owned).collect::<Vec<_>>());
    textarea.set_block(
        Block::default()
            .title(if focused { format!("{title} [focused]") } else { title.to_string() })
            .borders(Borders::ALL)
            .border_style(if focused { Style::default().fg(Color::Cyan) } else { Style::default() }),
    );
    textarea.set_line_number_style(Style::default().fg(Color::DarkGray));
    frame.render_widget(&textarea, area);
}

fn render_diff(frame: &mut Frame, app: &App, area: Rect) {
    let lines = match app.comparer_mode {
        CompareMode::Line => line_diff(&app.comparer_left, &app.comparer_right),
        CompareMode::Word => word_diff(&app.comparer_left, &app.comparer_right),
        CompareMode::Binary => binary_diff(&app.comparer_left, &app.comparer_right),
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Diff Output ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_ai_summary(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    match &app.comparer_ai_summary {
        Some(ComparerSummaryState::Loading) => {
            let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(app.tick_count as usize) % 10];
            lines.push(Line::styled(format!("{spinner} AI analyzing high-signal differences..."), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            lines.push(Line::styled("Looking for status, role, auth, header, token/noise, and body-length signals.", Style::default().fg(Color::DarkGray)));
        }
        Some(ComparerSummaryState::Error(error)) => {
            lines.push(Line::styled("AI comparer summary failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw(error.clone()));
            lines.push(Line::styled("Ctrl+K retry  d/Esc return to raw diff", Style::default().fg(Color::DarkGray)));
        }
        Some(ComparerSummaryState::Ready(summary)) => push_comparer_summary_lines(&mut lines, summary),
        None => lines.push(Line::raw("No AI summary available")),
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Difference Summary  d/Esc raw diff  Ctrl+K regenerate ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn push_comparer_summary_lines(lines: &mut Vec<Line<'static>>, summary: &ComparerSummary) {
    lines.push(Line::from(vec![
        Span::styled(format!(" {} ", if summary.risk_hint.is_empty() { "content_change" } else { summary.risk_hint.as_str() }), Style::default().fg(Color::Black).bg(risk_color(&summary.risk_hint)).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        confidence_span(summary.confidence),
    ]));
    lines.push(Line::raw(summary.summary.clone()));
    lines.push(Line::raw(""));
    if !summary.high_signal_changes.is_empty() {
        lines.push(Line::styled("High-signal Changes", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
        for change in summary.high_signal_changes.iter().take(8) {
            lines.push(Line::raw(format!("• {}", change.change)));
            if !change.security_relevance.trim().is_empty() {
                lines.push(Line::styled(format!("  relevance: {}", change.security_relevance), Style::default().fg(Color::DarkGray)));
            }
        }
        lines.push(Line::raw(""));
    }
    push_string_list(lines, "Likely Noise", &summary.likely_noise, Color::Yellow, 5);
    if !summary.security_interpretation.trim().is_empty() {
        lines.push(Line::styled("Security Interpretation", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
        lines.push(Line::raw(summary.security_interpretation.clone()));
        lines.push(Line::raw(""));
    }
    push_string_list(lines, "Suggested Next Steps", &summary.suggested_next_steps, Color::Magenta, 5);
    if let Some(raw_text) = &summary.raw_text {
        lines.push(Line::styled("Unstructured AI Output", Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)));
        lines.push(Line::raw(raw_text.clone()));
    }
}

fn push_string_list(lines: &mut Vec<Line<'static>>, title: &str, items: &[String], color: Color, max: usize) {
    if items.is_empty() {
        return;
    }
    lines.push(Line::styled(title.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)));
    for item in items.iter().filter(|item| !item.trim().is_empty()).take(max) {
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
    Span::styled(format!("confidence: {:.0}%", value.clamp(0.0, 1.0) * 100.0), Style::default().fg(Color::Green))
}

fn risk_color(risk_hint: &str) -> Color {
    match risk_hint {
        "possible_auth_bypass" | "possible_idor" | "possible_privilege_change" => Color::Red,
        "server_error_signal" | "header_security_change" => Color::Yellow,
        "likely_noise" | "none" => Color::Gray,
        _ => Color::Cyan,
    }
}

fn line_diff(left: &str, right: &str) -> Vec<Line<'static>> {
    let patch = diffy::create_patch(left, right);
    let formatted = diffy::PatchFormatter::new().fmt_patch(&patch).to_string();
    formatted
        .lines()
        .map(|line| {
            let style = if line.starts_with('+') {
                Style::default().fg(Color::Green)
            } else if line.starts_with('-') {
                Style::default().fg(Color::Red)
            } else if line.starts_with('@') {
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Line::styled(strip_ansi(line), style)
        })
        .collect()
}

fn word_diff(left: &str, right: &str) -> Vec<Line<'static>> {
    let left_words = left.split_whitespace().collect::<Vec<_>>();
    let right_words = right.split_whitespace().collect::<Vec<_>>();
    let mut lines = Vec::new();
    let max = left_words.len().max(right_words.len());
    for index in 0..max {
        match (left_words.get(index), right_words.get(index)) {
            (Some(a), Some(b)) if a == b => lines.push(Line::raw(format!("  {a}"))),
            (Some(a), Some(b)) => lines.push(Line::from(vec![
                Span::styled(format!("- {a}"), Style::default().fg(Color::Red)),
                Span::raw("  "),
                Span::styled(format!("+ {b}"), Style::default().fg(Color::Green)),
            ])),
            (Some(a), None) => lines.push(Line::styled(format!("- {a}"), Style::default().fg(Color::Red))),
            (None, Some(b)) => lines.push(Line::styled(format!("+ {b}"), Style::default().fg(Color::Green))),
            (None, None) => {}
        }
    }
    lines
}

fn binary_diff(left: &str, right: &str) -> Vec<Line<'static>> {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut lines = Vec::new();
    let max = left.len().max(right.len());
    for offset in (0..max).step_by(16).take(512) {
        let l = &left[offset..left.len().min(offset + 16)];
        let r = &right[offset..right.len().min(offset + 16)];
        let differs = l != r;
        let style = if differs { Style::default().fg(Color::Yellow) } else { Style::default().fg(Color::DarkGray) };
        lines.push(Line::styled(
            format!("{offset:08x}  {:<48} │ {:<48}", hex_bytes(l), hex_bytes(r)),
            style,
        ));
    }
    lines
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(" ")
}

fn strip_ansi(value: &str) -> String {
    let mut output = String::new();
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            for next in chars.by_ref() {
                if next == 'm' {
                    break;
                }
            }
        } else {
            output.push(ch);
        }
    }
    output
}

fn render_help(frame: &mut Frame, app: &App, area: Rect) {
    let help = Line::from(vec![
        Span::styled("Tab", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" focus  "),
        Span::styled("F3/w", Style::default().fg(Color::Black).bg(Color::Green)),
        Span::raw(format!(" mode: {}  ", app.comparer_mode.label())),
        Span::styled("Ctrl+K", Style::default().fg(Color::Black).bg(Color::Yellow)),
        Span::raw(" AI summary  "),
        Span::styled("Ctrl+M", Style::default().fg(Color::Black).bg(Color::Magenta)),
        Span::raw(" mark two Proxy flows to compare response/request bodies"),
    ]);
    frame.render_widget(Paragraph::new(help).block(Block::default().title(" Comparer Controls ").borders(Borders::ALL)), area);
}
