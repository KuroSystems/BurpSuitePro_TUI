use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::{
    app::{AiSkillFormat, AiSkillModalField, App},
    models::ai::{AiRole, QUICK_PROMPTS},
};

pub fn render_ai_tab(frame: &mut Frame, app: &App, area: Rect) {
    if app.ai_skill_page_open {
        render_skill_page(frame, app, area);
        return;
    }

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
    let active_skill = app
        .active_ai_skill()
        .map(|(name, _)| name)
        .unwrap_or_else(|| "none".to_string());
    let line = Line::from(vec![
        Span::styled(" Proxima AI Analyst ", Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("  model: "),
        Span::styled(&app.ai_panel.settings.model, Style::default().fg(Color::Green)),
        Span::raw("  status: "),
        Span::styled(waiting, Style::default().fg(if app.ai_panel.is_waiting { Color::Yellow } else { Color::Gray })),
        Span::raw("  skill: "),
        Span::styled(active_skill, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
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
    let mut lines = Vec::new();
    for message in app.ai_panel.messages.iter().rev().take(10).rev() {
        let style = match message.role {
            AiRole::User => Style::default().fg(Color::Green),
            AiRole::Assistant => Style::default().fg(Color::Cyan),
            AiRole::System => Style::default().fg(Color::DarkGray),
        };
        lines.push(Line::from(vec![
            Span::styled(message.role.label(), style.add_modifier(Modifier::BOLD)),
            Span::raw(format!("  {}", message.timestamp.format("%H:%M:%S"))),
        ]));
        match message.role {
            AiRole::Assistant => lines.extend(render_markdown_lines(&message.content)),
            _ => lines.extend(message.content.lines().map(|line| Line::raw(line.to_string()))),
        }
        lines.push(Line::raw(""));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Conversation  Markdown rendered ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_prompt(frame: &mut Frame, app: &App, area: Rect) {
    let help = "Enter/Ctrl+Enter send  Alt+Enter newline  F2 Skills  Ctrl+A attach flow  Alt+1..6 quick prompts";
    let input = if app.ai_panel.input.is_empty() {
        "Ask about selected flow, finding impact, next safe step, or payload ideas...".to_string()
    } else {
        app.ai_panel.input.clone()
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(" Skills:F2 ", Style::default().fg(Color::Black).bg(Color::Magenta).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(help, Style::default().fg(Color::DarkGray)),
        ]),
        Line::raw(input),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Prompt ").borders(Borders::ALL))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_skill_page(frame: &mut Frame, app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(area);
    let title = Line::from(vec![
        Span::styled(" Proxima Skill Page ", Style::default().fg(Color::Black).bg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Span::raw(" hidden page • n new skill • F2/Esc close • Tab focus • Ctrl+Enter apply/close"),
    ]);
    frame.render_widget(Paragraph::new(title).block(Block::default().borders(Borders::ALL)), layout[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(layout[1]);
    render_skill_list(frame, app, body[0]);
    render_skill_editor(frame, app, body[1]);

    let footer = Line::from(vec![
        Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::Green)),
        Span::raw(" new skill  "),
        Span::styled(" ↑/↓ ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" select  "),
        Span::styled(" Tab ", Style::default().fg(Color::Black).bg(Color::Yellow)),
        Span::raw(" list/editor  "),
        Span::styled(" JSON/Markdown auto-detected ", Style::default().fg(Color::Black).bg(Color::Magenta)),
    ]);
    frame.render_widget(Paragraph::new(footer).block(Block::default().borders(Borders::ALL)), layout[2]);

    if app.ai_skill_modal_open {
        render_skill_modal(frame, app, area);
    }
}

fn render_skill_list(frame: &mut Frame, app: &App, area: Rect) {
    let skills = app.ai_skill_options();
    let items = skills
        .iter()
        .enumerate()
        .map(|(index, (name, format, body, custom))| {
            let mut lines = vec![Line::from(vec![
                Span::styled(name.clone(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format.label(), Style::default().fg(if *custom { Color::Magenta } else { Color::DarkGray })),
            ])];
            lines.push(Line::styled(body.lines().next().unwrap_or("No skill text").chars().take(80).collect::<String>(), Style::default().fg(Color::DarkGray)));
            if index + 1 < skills.len() {
                lines.push(Line::raw(""));
            }
            ListItem::new(lines)
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.ai_selected_skill.min(skills.len().saturating_sub(1))));
    let title = if app.ai_skill_editor_focused { " Available Skills " } else { " Available Skills [focused] " };
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL).border_style(if app.ai_skill_editor_focused { Style::default() } else { Style::default().fg(Color::Magenta) }))
            .highlight_symbol("▶ ")
            .highlight_style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        area,
        &mut state,
    );
}

fn render_skill_editor(frame: &mut Frame, app: &App, area: Rect) {
    let (name, format, body, custom) = app
        .selected_ai_skill_tuple()
        .unwrap_or_else(|| ("No Skill".to_string(), AiSkillFormat::Markdown, String::new(), false));
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("# {name}"), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(format.label(), Style::default().fg(Color::Magenta)),
        Span::raw(if custom { "  editable" } else { "  built-in/read-only" }),
    ]), Line::raw("")];
    if body.trim().is_empty() {
        lines.push(Line::styled("No instructions yet.", Style::default().fg(Color::DarkGray)));
    } else if detected_skill_format(&body, format) == AiSkillFormat::Json {
        lines.extend(render_json_skill_lines(&body));
    } else {
        lines.extend(render_markdown_lines(&body));
    }
    let title = if app.ai_skill_editor_focused { " Skill Instructions Editor [focused] " } else { " Skill Instructions Editor " };
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL).border_style(if app.ai_skill_editor_focused { Style::default().fg(Color::Magenta) } else { Style::default() }))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_skill_modal(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(70, 70, area);
    frame.render_widget(Clear, popup);
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(popup);
    let title_style = if app.ai_skill_modal_field == AiSkillModalField::Title { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default() };
    let format_style = if app.ai_skill_modal_field == AiSkillModalField::Format { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default() };
    let body_style = if app.ai_skill_modal_field == AiSkillModalField::Body { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default() };
    frame.render_widget(
        Paragraph::new(Line::from(vec![Span::styled("Skill Title: ", title_style), Span::raw(format!("{}{}", app.ai_skill_modal_title, if app.ai_skill_modal_field == AiSkillModalField::Title { "_" } else { "" }))]))
            .block(Block::default().title(" New Skill ").borders(Borders::ALL).border_style(Style::default().fg(Color::Magenta))),
        layout[0],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![Span::styled("Format: ", format_style), Span::styled(app.ai_skill_modal_format.label(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)), Span::raw("  (Space/←/→ toggles)")]))
            .block(Block::default().borders(Borders::ALL)),
        layout[1],
    );
    let body_lines = if app.ai_skill_modal_body.is_empty() {
        vec![Line::styled("Write JSON or Markdown skill instructions here...", Style::default().fg(Color::DarkGray))]
    } else {
        app.ai_skill_modal_body.lines().map(|line| Line::raw(line.to_string())).collect()
    };
    frame.render_widget(
        Paragraph::new(body_lines)
            .block(Block::default().title(" Instructions / Prompt ").borders(Borders::ALL).border_style(body_style))
            .wrap(Wrap { trim: false }),
        layout[2],
    );
    frame.render_widget(
        Paragraph::new("Tab next field • Ctrl+Enter save • Enter saves outside body / newline in body • Esc cancel")
            .alignment(Alignment::Center)
            .block(Block::default().borders(Borders::ALL)),
        layout[3],
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn detected_skill_format(body: &str, fallback: AiSkillFormat) -> AiSkillFormat {
    if serde_json::from_str::<serde_json::Value>(body).is_ok() {
        AiSkillFormat::Json
    } else {
        fallback
    }
}

fn render_json_skill_lines(body: &str) -> Vec<Line<'static>> {
    match serde_json::from_str::<serde_json::Value>(body)
        .and_then(|value| serde_json::to_string_pretty(&value))
    {
        Ok(pretty) => pretty.lines().map(render_code_line).collect(),
        Err(error) => vec![
            Line::styled(format!("Invalid JSON: {error}"), Style::default().fg(Color::Red)),
            Line::raw(body.to_string()),
        ],
    }
}

fn render_markdown_lines(content: &str) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut in_code = false;
    let mut code_lang = String::new();

    for raw_line in content.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim();
        if trimmed.starts_with("```") {
            in_code = !in_code;
            if in_code {
                code_lang = trimmed.trim_start_matches("```").trim().to_string();
                let label = if code_lang.is_empty() { " code ".to_string() } else { format!(" {code_lang} ") };
                lines.push(Line::styled(label, Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)));
            } else {
                code_lang.clear();
                lines.push(Line::raw(""));
            }
            continue;
        }
        if in_code {
            lines.push(render_code_line(line));
            continue;
        }
        if trimmed.is_empty() {
            lines.push(Line::raw(""));
            continue;
        }
        if trimmed.starts_with('|') && trimmed.ends_with('|') {
            if is_markdown_table_separator(trimmed) {
                lines.push(Line::styled(table_separator(trimmed), Style::default().fg(Color::DarkGray)));
            } else {
                lines.push(render_table_line(trimmed));
            }
            continue;
        }
        if let Some((level, text)) = parse_heading(trimmed) {
            let color = match level {
                1 => Color::Cyan,
                2 => Color::Green,
                _ => Color::Magenta,
            };
            lines.push(Line::styled(text.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("> ") {
            lines.push(Line::from(vec![Span::styled("▌ ", Style::default().fg(Color::DarkGray)), Span::styled(rest.to_string(), Style::default().fg(Color::Gray).add_modifier(Modifier::ITALIC))]));
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- ").or_else(|| trimmed.strip_prefix("* ")).or_else(|| trimmed.strip_prefix("+ ")) {
            lines.push(Line::from(vec![Span::styled("  • ", Style::default().fg(Color::Cyan)), Span::raw(rest.to_string())]));
            continue;
        }
        if is_numbered_list(trimmed) {
            lines.push(Line::from(vec![Span::styled("  ", Style::default()), Span::raw(trimmed.to_string())]));
            continue;
        }
        lines.push(render_inline_markdown(trimmed));
    }
    lines
}

fn parse_heading(line: &str) -> Option<(usize, &str)> {
    let hashes = line.chars().take_while(|ch| *ch == '#').count();
    if hashes > 0 && hashes <= 6 && line.chars().nth(hashes) == Some(' ') {
        Some((hashes, line[hashes + 1..].trim()))
    } else {
        None
    }
}

fn is_markdown_table_separator(line: &str) -> bool {
    line.chars().all(|ch| matches!(ch, '|' | '-' | ':' | ' ')) && line.contains('-')
}

fn table_separator(line: &str) -> String {
    let cells = split_table_cells(line);
    format!("  {}", cells.iter().map(|cell| "─".repeat(cell.len().max(3))).collect::<Vec<_>>().join("─┼─"))
}

fn render_table_line(line: &str) -> Line<'static> {
    let cells = split_table_cells(line);
    let mut spans = Vec::new();
    spans.push(Span::styled("  │ ", Style::default().fg(Color::DarkGray)));
    for (index, cell) in cells.iter().enumerate() {
        if index > 0 {
            spans.push(Span::styled(" │ ", Style::default().fg(Color::DarkGray)));
        }
        spans.push(Span::styled(cell.clone(), Style::default().fg(Color::Yellow)));
    }
    spans.push(Span::styled(" │", Style::default().fg(Color::DarkGray)));
    Line::from(spans)
}

fn split_table_cells(line: &str) -> Vec<String> {
    line.trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_string())
        .collect()
}

fn is_numbered_list(line: &str) -> bool {
    let mut chars = line.chars();
    let mut seen_digit = false;
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() {
            seen_digit = true;
            continue;
        }
        return seen_digit && ch == '.' && chars.next() == Some(' ');
    }
    false
}

fn render_code_line(line: &str) -> Line<'static> {
    let keywords = ["fn", "let", "mut", "const", "pub", "struct", "enum", "impl", "async", "await", "return", "if", "else", "match", "for", "while", "use", "import", "def", "class", "function", "var"];
    let mut spans = vec![Span::styled("  ", Style::default().bg(Color::Black))];
    for token in line.split_inclusive(' ') {
        let plain = token.trim_matches(|ch: char| !ch.is_alphanumeric() && ch != '_');
        let style = if keywords.contains(&plain) {
            Style::default().fg(Color::Magenta).bg(Color::Black).add_modifier(Modifier::BOLD)
        } else if token.trim_start().starts_with("//") || token.trim_start().starts_with('#') {
            Style::default().fg(Color::DarkGray).bg(Color::Black)
        } else if token.contains('"') || token.contains('\'') {
            Style::default().fg(Color::Green).bg(Color::Black)
        } else {
            Style::default().fg(Color::LightCyan).bg(Color::Black)
        };
        spans.push(Span::styled(token.to_string(), style));
    }
    Line::from(spans)
}

fn render_inline_markdown(line: &str) -> Line<'static> {
    let mut spans = Vec::new();
    let mut rest = line;
    while let Some(start) = rest.find('`') {
        let (before, after_start) = rest.split_at(start);
        if !before.is_empty() {
            spans.push(Span::raw(before.to_string()));
        }
        let after_start = &after_start[1..];
        if let Some(end) = after_start.find('`') {
            let (code, after_end) = after_start.split_at(end);
            spans.push(Span::styled(format!(" {code} "), Style::default().fg(Color::Black).bg(Color::Green)));
            rest = &after_end[1..];
        } else {
            spans.push(Span::raw("`".to_string()));
            rest = after_start;
            break;
        }
    }
    if !rest.is_empty() {
        spans.push(Span::raw(rest.replace("**", "")));
    }
    Line::from(spans)
}
