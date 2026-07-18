use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState, Wrap},
    Frame,
};
use ratatui_textarea::TextArea;

use crate::{
    app::{App, IntruderAiMode},
    models::{
        ai::{IntruderAttackPlan, IntruderAttackPlanState, IntruderPayloadSuggestion, IntruderPayloadSuggestionState},
        intruder::parse_positions,
    },
};

pub fn render_intruder_tab(frame: &mut Frame, app: &App, area: Rect) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(3)])
        .split(area);
    render_progress(frame, app, outer[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(outer[1]);
    render_request_editor(frame, app, body[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(body[1]);
    render_config(frame, app, right[0]);
    render_results(frame, app, right[1]);
    render_controls(frame, app, outer[2]);
}

fn render_progress(frame: &mut Frame, app: &App, area: Rect) {
    let completed = app.intruder_results.len();
    let total = app.intruder_total.max(completed).max(1);
    let ratio = completed as f64 / total as f64;
    let state = if app.intruder_running {
        if app.intruder_paused { "paused" } else { "running" }
    } else {
        "idle"
    };
    frame.render_widget(
        Gauge::default()
            .block(Block::default().title(" Intruder Progress ").borders(Borders::ALL))
            .gauge_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .ratio(ratio)
            .label(format!("{completed}/{total} {state}")),
        area,
    );
}

fn render_request_editor(frame: &mut Frame, app: &App, area: Rect) {
    let mut textarea = TextArea::from(
        app.intruder_request_text
            .lines()
            .map(|line| line.to_string())
            .collect::<Vec<_>>(),
    );
    let positions = parse_positions(&app.intruder_request_text);
    textarea.set_block(
        Block::default()
            .title(format!(" Target Request - {} positions marked with § § ", positions.len()))
            .borders(Borders::ALL),
    );
    textarea.set_line_number_style(Style::default().fg(Color::DarkGray));
    textarea.set_cursor_line_style(Style::default().bg(Color::Black));
    frame.render_widget(&textarea, area);
}

fn render_config(frame: &mut Frame, app: &App, area: Rect) {
    if app.intruder_ai_mode == IntruderAiMode::PayloadSuggestionPreview {
        render_ai_payload_lab(frame, app, area);
        return;
    }
    if app.intruder_ai_mode == IntruderAiMode::PlanPreview {
        render_ai_attack_plan(frame, app, area);
        return;
    }

    let positions = parse_positions(&app.intruder_request_text);
    let payload_count = app.intruder_payloads_text.lines().filter(|line| !line.trim().is_empty()).count();
    let preview = app
        .intruder_payloads_text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(2)
        .collect::<Vec<_>>()
        .join(", ");
    let ai_sets = if app.intruder_plan_payload_sets.is_empty() {
        String::new()
    } else {
        format!("   AI sets: {}", app.intruder_plan_payload_sets.len())
    };
    let lines = vec![
        Line::from(vec![Span::styled("Attack: ", Style::default().fg(Color::Yellow)), Span::raw(app.intruder_attack_type.label())]),
        Line::from(format!("Positions: {}   Concurrency: {}   RPS: {}", positions.len(), app.intruder_concurrency, app.intruder_rps)),
        Line::from(format!("Payload source: SimpleList / AI-ready   Payloads: {payload_count}{ai_sets}")),
        Line::from(format!("Preview: {}", if preview.is_empty() { "<empty>" } else { preview.as_str() })),
        Line::from("Ctrl+K AI Payload Generator   Filters: 0 all, 2 xx, 4 xx, 5 xx"),
        Line::from(format!("Status filter: {}", app.intruder_filter_status.map(|s| format!("{}xx", s / 100)).unwrap_or_else(|| "all".to_string()))),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" Payload Sets / AI Payload Lab ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_ai_payload_lab(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    match &app.intruder_ai_suggestion {
        Some(IntruderPayloadSuggestionState::Loading) => push_ai_payload_loading(&mut lines, app.tick_count),
        Some(IntruderPayloadSuggestionState::Error(error)) => {
            lines.push(Line::styled("AI payload generation failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw(error.clone()));
            lines.push(Line::styled("Ctrl+K retry  d/Esc discard", Style::default().fg(Color::DarkGray)));
        }
        Some(IntruderPayloadSuggestionState::Ready(suggestion)) => push_ai_payload_suggestion(&mut lines, suggestion),
        None => {
            lines.push(Line::styled("AI Payload Lab", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw("Press Ctrl+K to generate safe payloads for the marked positions."));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Payload Lab  a replace  n append  d discard ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn push_ai_payload_loading(lines: &mut Vec<Line<'static>>, tick_count: u64) {
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(tick_count as usize) % 10];
    let stage = [
        "Reading marked positions",
        "Selecting safe payload category",
        "Filtering destructive patterns",
        "Building rationale and safety notes",
    ][((tick_count / 8) as usize) % 4];
    lines.push(Line::from(vec![
        Span::styled(format!("{spinner} "), Style::default().fg(Color::Cyan)),
        Span::styled("AI generating safe payloads", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::raw(format!("{stage}...")));
    lines.push(Line::styled("Payloads will not run automatically. Destructive payloads are disabled.", Style::default().fg(Color::DarkGray)));
}

fn push_ai_payload_suggestion(lines: &mut Vec<Line<'static>>, suggestion: &IntruderPayloadSuggestion) {
    let category = if suggestion.category.is_empty() {
        "Custom"
    } else {
        suggestion.category.as_str()
    };
    lines.push(Line::from(vec![
        Span::styled(format!(" {category} "), Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(" SAFE-ONLY ", Style::default().fg(Color::Black).bg(Color::Green)),
        Span::raw(format!(" {} payloads", suggestion.payloads.len())),
    ]));
    if let Some(rps) = suggestion.recommended_rps {
        lines.push(Line::raw(format!("Recommended RPS: {rps}")));
    }
    if let Some(attack) = &suggestion.recommended_attack_type {
        lines.push(Line::raw(format!("Recommended attack type: {attack}")));
    }
    if !suggestion.target_parameter_hint.trim().is_empty() {
        lines.push(Line::raw(format!("Target hint: {}", suggestion.target_parameter_hint)));
    }
    lines.push(confidence_line(suggestion.confidence));
    lines.push(Line::raw(""));
    push_list(lines, "Payload Preview", &suggestion.payloads, Color::Green, 8);
    push_list(lines, "Rationale", &suggestion.rationale, Color::Cyan, 3);
    push_list(lines, "Safety Notes", &suggestion.safety_notes, Color::Yellow, 3);
    push_list(lines, "Warnings", &suggestion.warnings, Color::Red, 3);
    if !suggestion.blocked_payloads.is_empty() {
        lines.push(Line::styled(format!("Blocked by safety filter: {}", suggestion.blocked_payloads.len()), Style::default().fg(Color::Red)));
    }
}

fn push_list(lines: &mut Vec<Line<'static>>, title: &str, items: &[String], color: Color, max: usize) {
    if items.is_empty() {
        return;
    }
    lines.push(Line::styled(title.to_string(), Style::default().fg(color).add_modifier(Modifier::BOLD)));
    for item in items.iter().filter(|item| !item.trim().is_empty()).take(max) {
        lines.push(Line::raw(format!("• {item}")));
    }
    if items.len() > max {
        lines.push(Line::styled(format!("… {} more", items.len() - max), Style::default().fg(Color::DarkGray)));
    }
}

fn confidence_line(confidence: Option<f32>) -> Line<'static> {
    let Some(mut value) = confidence else {
        return Line::styled("Confidence: n/a", Style::default().fg(Color::DarkGray));
    };
    if value > 1.0 {
        value /= 100.0;
    }
    Line::styled(format!("Confidence: {:.0}%", value.clamp(0.0, 1.0) * 100.0), Style::default().fg(Color::Green))
}

fn render_ai_attack_plan(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    match &app.intruder_ai_plan {
        Some(IntruderAttackPlanState::Loading) => push_ai_plan_loading(&mut lines, app.tick_count),
        Some(IntruderAttackPlanState::Error(error)) => {
            lines.push(Line::styled("AI attack planning failed", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw(error.clone()));
            lines.push(Line::styled("Ctrl+P retry  d/Esc discard", Style::default().fg(Color::DarkGray)));
        }
        Some(IntruderAttackPlanState::Ready(plan)) => push_ai_attack_plan(&mut lines, plan),
        None => {
            lines.push(Line::styled("AI Attack Planner", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
            lines.push(Line::raw("Press Ctrl+P to plan markers, attack type, and payload sets."));
        }
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Attack Planner  a apply  d discard ").borders(Borders::ALL).border_style(Style::default().fg(Color::Magenta)))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn push_ai_plan_loading(lines: &mut Vec<Line<'static>>, tick_count: u64) {
    let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][(tick_count as usize) % 10];
    let stage = ["Detecting parameters", "Placing §position§ markers", "Choosing attack type", "Selecting safe payload sets", "Explaining result signals"][((tick_count / 8) as usize) % 5];
    lines.push(Line::from(vec![
        Span::styled(format!("{spinner} "), Style::default().fg(Color::Magenta)),
        Span::styled("AI planning Intruder setup", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
    ]));
    lines.push(Line::raw(format!("{stage}...")));
    lines.push(Line::styled("Draft only. The attack will not start automatically.", Style::default().fg(Color::DarkGray)));
}

fn push_ai_attack_plan(lines: &mut Vec<Line<'static>>, plan: &IntruderAttackPlan) {
    let name = if plan.plan_name.trim().is_empty() { "AI Intruder Plan" } else { plan.plan_name.as_str() };
    lines.push(Line::from(vec![
        Span::styled(format!(" {name} "), Style::default().fg(Color::Black).bg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(format!(" {} ", if plan.recommended_attack_type.is_empty() { "Sniper" } else { plan.recommended_attack_type.as_str() }), Style::default().fg(Color::Black).bg(Color::Cyan)),
    ]));
    lines.push(confidence_line(plan.confidence));
    lines.push(Line::raw(format!("Positions after apply: {}", parse_positions(&plan.marked_request).len())));
    if let Some(rps) = plan.recommended_rps {
        lines.push(Line::raw(format!("Recommended RPS: {rps}")));
    }
    push_detected_parameters(lines, &plan.detected_parameters);
    push_plan_payload_sets(lines, &plan.payload_sets);
    push_list(lines, "Expected Result Signals", &plan.expected_result_columns, Color::Green, 4);
    push_list(lines, "Success Indicators", &plan.success_indicators, Color::Cyan, 3);
    push_list(lines, "Safety Notes", &plan.safety_notes, Color::Yellow, 3);
    push_list(lines, "Warnings", &plan.warnings, Color::Red, 3);
}

fn push_detected_parameters(lines: &mut Vec<Line<'static>>, params: &[crate::models::ai::IntruderDetectedParameter]) {
    if params.is_empty() {
        return;
    }
    lines.push(Line::styled("Detected Parameters", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)));
    for param in params.iter().take(4) {
        let name = if param.name.trim().is_empty() { "parameter" } else { param.name.trim() };
        lines.push(Line::raw(format!("• {name} [{}] — {}", param.location, param.reason)));
    }
    if params.len() > 4 {
        lines.push(Line::styled(format!("… {} more", params.len() - 4), Style::default().fg(Color::DarkGray)));
    }
}

fn push_plan_payload_sets(lines: &mut Vec<Line<'static>>, sets: &[crate::models::ai::IntruderPlanPayloadSet]) {
    if sets.is_empty() {
        return;
    }
    lines.push(Line::styled("Payload Sets", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    for set in sets.iter().take(3) {
        let preview = set.payloads.iter().take(4).cloned().collect::<Vec<_>>().join(", ");
        let name = if set.name.is_empty() { "Set" } else { set.name.as_str() };
        lines.push(Line::raw(format!("• {name}: {} payloads [{}]", set.payloads.len(), preview)));
    }
    if sets.len() > 3 {
        lines.push(Line::styled(format!("… {} more sets", sets.len() - 3), Style::default().fg(Color::DarkGray)));
    }
}

fn render_results(frame: &mut Frame, app: &App, area: Rect) {
    let results = app.filtered_intruder_results();
    let rows = results.iter().map(|result| {
        let status = result.status.map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
        let error = result.error.clone().unwrap_or_default();
        Row::new(vec![
            Cell::from(result.payload_label.clone()),
            Cell::from(status),
            Cell::from(result.length.to_string()),
            Cell::from(format!("{}ms", result.time_ms)),
            Cell::from(error),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Percentage(32),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Percentage(35),
        ],
    )
    .header(
        Row::new(["Payload", "Status", "Length", "Time", "Error"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(Block::default().title(" Results ").borders(Borders::ALL))
    .row_highlight_style(Style::default().bg(Color::DarkGray).add_modifier(Modifier::BOLD))
    .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(if results.is_empty() {
        None
    } else {
        Some(app.intruder_selected_result.min(results.len() - 1))
    });
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_controls(frame: &mut Frame, app: &App, area: Rect) {
    if matches!(app.intruder_ai_mode, IntruderAiMode::PayloadPrompt | IntruderAiMode::PlannerPrompt) {
        render_ai_prompt(frame, app, area);
        return;
    }
    if app.intruder_ai_mode == IntruderAiMode::PayloadSuggestionPreview {
        render_ai_suggestion_controls(frame, app, area);
        return;
    }
    if app.intruder_ai_mode == IntruderAiMode::PlanPreview {
        render_ai_plan_controls(frame, app, area);
        return;
    }

    let controls = Line::from(vec![
        Span::styled(" Ctrl+K ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" AI payloads  "),
        Span::styled(" Ctrl+P ", Style::default().fg(Color::Black).bg(Color::Magenta)),
        Span::raw(" AI plan  "),
        Span::styled(" F5 ", Style::default().fg(Color::Black).bg(Color::Green)),
        Span::raw(" start/resume  "),
        Span::styled(" F6 ", Style::default().fg(Color::Black).bg(Color::Yellow)),
        Span::raw(" pause  "),
        Span::styled(" F7 ", Style::default().fg(Color::Black).bg(Color::Red)),
        Span::raw(" stop  "),
        Span::styled(" F8 ", Style::default().fg(Color::Black).bg(Color::Cyan)),
        Span::raw(" attack type  "),
        Span::styled(" F9 ", Style::default().fg(Color::Black).bg(Color::Magenta)),
        Span::raw(" export CSV  "),
        Span::raw(app.project_message.clone()),
    ]);
    frame.render_widget(
        Paragraph::new(controls).block(Block::default().title(" Attack Controls ").borders(Borders::ALL)),
        area,
    );
}

fn render_ai_prompt(frame: &mut Frame, app: &App, area: Rect) {
    let is_planner = app.intruder_ai_mode == IntruderAiMode::PlannerPrompt;
    let placeholder = if is_planner {
        "Setup safe fuzzing for this request"
    } else {
        "Generate safe SQLi/XSS/IDOR/path traversal/JWT/SSRF payloads..."
    };
    let input = if app.intruder_ai_input.is_empty() {
        placeholder.to_string()
    } else {
        format!("{} _", app.intruder_ai_input)
    };
    let label = if is_planner { "AI Planner > " } else { "AI Payloads > " };
    let title = if is_planner { " AI Intruder Attack Planner " } else { " AI Payload Generator " };
    let help = if is_planner {
        "Enter plan  Esc cancel  AI will draft markers/payloads only; F5 remains manual"
    } else {
        "Enter generate  Esc cancel  Destructive payloads disabled by default"
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(label, Style::default().fg(Color::Black).bg(if is_planner { Color::Magenta } else { Color::Cyan }).add_modifier(Modifier::BOLD)),
            Span::raw(input),
        ]),
        Line::styled(help, Style::default().fg(Color::DarkGray)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(title).borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_ai_plan_controls(frame: &mut Frame, app: &App, area: Rect) {
    let status = match &app.intruder_ai_plan {
        Some(IntruderAttackPlanState::Loading) => "planning markers, attack type, and payload sets...",
        Some(IntruderAttackPlanState::Ready(_)) => "review plan, then apply before F5",
        Some(IntruderAttackPlanState::Error(_)) => "planning failed; discard or retry",
        None => "planner mode",
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(" a ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" apply plan  "),
            Span::styled(" d/Esc ", Style::default().fg(Color::Black).bg(Color::Red)),
            Span::raw(" discard  "),
            Span::styled(" Ctrl+P ", Style::default().fg(Color::Black).bg(Color::Magenta)),
            Span::raw(" replan  "),
            Span::styled(" Ctrl+K ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" payload lab"),
        ]),
        Line::styled(format!("Status: {status}. Applying updates markers/payloads only; F5 remains manual."), Style::default().fg(Color::DarkGray)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Plan Controls ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_ai_suggestion_controls(frame: &mut Frame, app: &App, area: Rect) {
    let status = match &app.intruder_ai_suggestion {
        Some(IntruderPayloadSuggestionState::Loading) => "generating safe payloads...",
        Some(IntruderPayloadSuggestionState::Ready(_)) => "review payloads, then replace or append",
        Some(IntruderPayloadSuggestionState::Error(_)) => "generation failed; discard or retry",
        None => "suggestion mode",
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(" a ", Style::default().fg(Color::Black).bg(Color::Green)),
            Span::raw(" replace payload list  "),
            Span::styled(" n ", Style::default().fg(Color::Black).bg(Color::Cyan)),
            Span::raw(" append  "),
            Span::styled(" d/Esc ", Style::default().fg(Color::Black).bg(Color::Red)),
            Span::raw(" discard  "),
            Span::styled(" Ctrl+K ", Style::default().fg(Color::Black).bg(Color::Yellow)),
            Span::raw(" regenerate  "),
            Span::styled(" Ctrl+P ", Style::default().fg(Color::Black).bg(Color::Magenta)),
            Span::raw(" plan"),
        ]),
        Line::styled(format!("Status: {status}. Payloads are not run automatically; apply first, then F5 manually."), Style::default().fg(Color::DarkGray)),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().title(" AI Payload Controls ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}
