use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::{
    app::{AgentApprovalSelection, AiAgentModalField, AiPromptMode, AiSkillFormat, AiSkillModalField, App},
    models::ai::AiAgentPlanState,
    models::ai::{AiRole, QUICK_PROMPTS},
};

pub fn render_ai_tab(frame: &mut Frame, app: &App, area: Rect) {
    if app.ai_agent_page_open {
        render_agent_page(frame, app, area);
        return;
    }
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
        Span::raw("  mode: "),
        Span::styled(app.ai_prompt_mode.label(), Style::default().fg(if app.ai_prompt_mode == AiPromptMode::Agent { Color::Magenta } else { Color::Cyan }).add_modifier(Modifier::BOLD)),
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
    for message in app.ai_panel.messages.iter().rev().take(12).rev() {
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
    if app.ai_panel.is_waiting {
        if app.ai_prompt_mode == AiPromptMode::Agent {
            push_agent_planning_animation(&mut lines, app.tick_count);
        } else {
            push_skill_processing_animation(&mut lines, app);
        }
    }
    if matches!(app.ai_agent_plan_state, Some(AiAgentPlanState::AwaitingApproval(_))) {
        lines.push(Line::raw(""));
        lines.push(Line::styled("Plan Approval", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
        let accept_selected = app.ai_agent_approval_selection == AgentApprovalSelection::Accept;
        lines.push(Line::styled(if accept_selected { "▶ [a] Accept" } else { "  [a] Accept" }, Style::default().fg(if accept_selected { Color::Green } else { Color::Gray }).add_modifier(if accept_selected { Modifier::BOLD } else { Modifier::empty() })));
        lines.push(Line::styled(if !accept_selected { "▶ [d] Decline" } else { "  [d] Decline" }, Style::default().fg(if !accept_selected { Color::Red } else { Color::Gray }).add_modifier(if !accept_selected { Modifier::BOLD } else { Modifier::empty() })));
        lines.push(Line::styled("Tab toggles • Enter confirms", Style::default().fg(Color::DarkGray)));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Conversation Markdown Rendered  PageUp/PageDown scroll ").borders(Borders::ALL))
            .scroll((app.ai_conversation_scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn push_skill_processing_animation(lines: &mut Vec<Line<'static>>, app: &App) {
    let tick = app.tick_count;
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(tick as usize) % 10];
    let stages = [
        "Reading prompt",
        "Loading selected skill",
        "Checking attached context",
        "Separating evidence from assumptions",
        "Drafting structured answer",
        "Rendering Markdown",
    ];
    let current = ((tick / 6) as usize) % stages.len();
    let skill_name = app
        .active_ai_skill()
        .map(|(name, _)| name)
        .unwrap_or_else(|| "General Analyst".to_string());
    lines.push(Line::raw(""));
    lines.push(Line::styled("✦ Skill Mode", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    lines.push(Line::from(vec![
        Span::styled("Skill: ", Style::default().fg(Color::DarkGray)),
        Span::styled(skill_name, Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::styled(progress_rail(current + 1, stages.len()), Style::default().fg(Color::Cyan)));
    for (index, stage) in stages.iter().enumerate() {
        if index < current {
            lines.push(Line::styled(format!("✓ {stage}"), Style::default().fg(Color::Green)));
        } else if index == current {
            lines.push(Line::styled(format!("{spinner} {stage}"), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        } else {
            lines.push(Line::styled(format!("• {stage}"), Style::default().fg(Color::DarkGray)));
        }
    }
}

fn push_agent_planning_animation(lines: &mut Vec<Line<'static>>, tick: u64) {
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(tick as usize) % 10];
    let stages = ["Routing request", "Scoring custom agents", "Mapping app tools", "Checking safety gates", "Building execution plan"];
    let current = ((tick / 6) as usize) % stages.len();
    lines.push(Line::raw(""));
    lines.push(Line::styled("◈ Agent Mode", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)));
    lines.push(Line::styled("Tools: [Proxy] [Scanner] [WebSockets] [Repeater] [AI Report]", Style::default().fg(Color::Cyan)));
    lines.push(Line::styled(progress_rail(current + 1, stages.len()), Style::default().fg(Color::Magenta)));
    for (index, stage) in stages.iter().enumerate() {
        if index < current {
            lines.push(Line::styled(format!("✓ {stage}"), Style::default().fg(Color::Green)));
        } else if index == current {
            lines.push(Line::styled(format!("{spinner} {stage}"), Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
        } else {
            lines.push(Line::styled(format!("• {stage}"), Style::default().fg(Color::DarkGray)));
        }
    }
}

fn progress_rail(done: usize, total: usize) -> String {
    let width = 12;
    let filled = ((done * width) / total.max(1)).min(width);
    format!("[{}{}] {}/{}", "█".repeat(filled), "░".repeat(width - filled), done.min(total), total)
}

fn render_prompt(frame: &mut Frame, app: &App, area: Rect) {
    let help = "Enter send  Tab Skill/Agent  F2 Skills  F3/Ctrl+G Agents  PageUp/PageDown scroll  Ctrl+A attach flow";
    let input = if app.ai_panel.input.is_empty() {
        "Ask about selected flow, finding impact, next safe step, or payload ideas...".to_string()
    } else {
        app.ai_panel.input.clone()
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(format!(" Mode:{} ", app.ai_prompt_mode.label()), Style::default().fg(Color::Black).bg(if app.ai_prompt_mode == AiPromptMode::Agent { Color::Magenta } else { Color::Cyan }).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(" Skills:F2 ", Style::default().fg(Color::Black).bg(Color::Magenta).add_modifier(Modifier::BOLD)),
            Span::raw("  "),
            Span::styled(" Agents:F3/Ctrl+G ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
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

fn render_agent_page(frame: &mut Frame, app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(area);
    let title = Line::from(vec![
        Span::styled(" Proxima Agent Page ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw(" hidden page • n new agent • F3/Esc close • Tab focus"),
    ]);
    frame.render_widget(Paragraph::new(title).block(Block::default().borders(Borders::ALL)), layout[0]);
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(layout[1]);
    render_agent_list(frame, app, body[0]);
    render_agent_editor(frame, app, body[1]);
    let footer = Line::from(vec![
        Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::Green)),
        Span::raw(" new agent  "),
        Span::styled(" ↑/↓ ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" select  "),
        Span::styled(" Tab ", Style::default().fg(Color::Black).bg(Color::Yellow)),
        Span::raw(" list/editor  Agent Mode auto-selects relevant agents"),
    ]);
    frame.render_widget(Paragraph::new(footer).block(Block::default().borders(Borders::ALL)), layout[2]);
    if app.ai_agent_modal_open {
        render_agent_modal(frame, app, area);
    }
}

fn render_agent_list(frame: &mut Frame, app: &App, area: Rect) {
    let agents = app.ai_agent_options();
    let items = agents
        .iter()
        .enumerate()
        .map(|(index, (name, format, body))| {
            let mut lines = vec![Line::from(vec![
                Span::styled(name.clone(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::raw("  "),
                Span::styled(format.label(), Style::default().fg(Color::DarkGray)),
            ])];
            lines.push(Line::styled(body.lines().next().unwrap_or("No agent instructions").chars().take(80).collect::<String>(), Style::default().fg(Color::DarkGray)));
            if index + 1 < agents.len() {
                lines.push(Line::raw(""));
            }
            ListItem::new(lines)
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.ai_selected_agent.min(agents.len().saturating_sub(1))));
    let title = if app.ai_agent_editor_focused { " Agents " } else { " Agents [focused] " };
    frame.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL).border_style(if app.ai_agent_editor_focused { Style::default() } else { Style::default().fg(Color::Green) }))
            .highlight_symbol("▶ ")
            .highlight_style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        area,
        &mut state,
    );
}

fn render_agent_editor(frame: &mut Frame, app: &App, area: Rect) {
    let (name, format, body) = app
        .selected_ai_agent_tuple()
        .unwrap_or_else(|| ("No Agent".to_string(), AiSkillFormat::Markdown, String::new()));
    let mut lines = vec![Line::from(vec![
        Span::styled(format!("# {name}"), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(format.label(), Style::default().fg(Color::Magenta)),
    ]), Line::raw("")];
    if detected_skill_format(&body, format) == AiSkillFormat::Json {
        lines.extend(render_json_skill_lines(&body));
    } else {
        lines.extend(render_markdown_lines(&body));
    }
    let title = if app.ai_agent_editor_focused { " Agent Definition Editor [focused] " } else { " Agent Definition Editor " };
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL).border_style(if app.ai_agent_editor_focused { Style::default().fg(Color::Green) } else { Style::default() }))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_agent_modal(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(70, 70, area);
    frame.render_widget(Clear, popup);
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(popup);
    let title_style = if app.ai_agent_modal_field == AiAgentModalField::Title { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default() };
    let format_style = if app.ai_agent_modal_field == AiAgentModalField::Format { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default() };
    let body_style = if app.ai_agent_modal_field == AiAgentModalField::Body { Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD) } else { Style::default() };
    frame.render_widget(
        Paragraph::new(Line::from(vec![Span::styled("Agent Title: ", title_style), Span::raw(format!("{}{}", app.ai_agent_modal_title, if app.ai_agent_modal_field == AiAgentModalField::Title { "_" } else { "" }))]))
            .block(Block::default().title(" New Agent ").borders(Borders::ALL).border_style(Style::default().fg(Color::Green))),
        layout[0],
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![Span::styled("Format: ", format_style), Span::styled(app.ai_agent_modal_format.label(), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)), Span::raw("  (Space/←/→ toggles)")]))
            .block(Block::default().borders(Borders::ALL)),
        layout[1],
    );
    let body_lines = if app.ai_agent_modal_body.is_empty() {
        vec![Line::styled("Write JSON or Markdown agent instructions here...", Style::default().fg(Color::DarkGray))]
    } else {
        app.ai_agent_modal_body.lines().map(|line| Line::raw(line.to_string())).collect()
    };
    frame.render_widget(
        Paragraph::new(body_lines)
            .block(Block::default().title(" Agent Instructions / Tools / Safety ").borders(Borders::ALL).border_style(body_style))
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
