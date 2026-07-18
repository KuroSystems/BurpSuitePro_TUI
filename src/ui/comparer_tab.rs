use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};
use ratatui_textarea::TextArea;

use crate::{app::App, models::comparer::CompareMode};

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
    render_diff(frame, app, rows[1]);
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
    frame.render_widget(textarea.widget(), area);
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
        Span::styled("Ctrl+M", Style::default().fg(Color::Black).bg(Color::Magenta)),
        Span::raw(" mark two Proxy flows to compare response/request bodies"),
    ]);
    frame.render_widget(Paragraph::new(help).block(Block::default().title(" Comparer Controls ").borders(Borders::ALL)), area);
}
