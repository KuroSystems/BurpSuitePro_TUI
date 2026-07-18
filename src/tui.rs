use std::{
    io::{self, Stdout},
    time::Duration,
};

use color_eyre::eyre::{Context, Result};
use crossterm::{
    event::{
        DisableMouseCapture, EnableMouseCapture, Event as CrosstermEvent, EventStream,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use futures_util::StreamExt;
use ratatui::{backend::CrosstermBackend, Terminal};
use tokio::time::{self, Interval};

use tokio::sync::mpsc;

use crate::{
    app::App,
    events::{Event, ProxyEvent, RepeaterEvent},
    models::{ai::AiEvent, intruder::IntruderEvent},
    scanner::ActiveScannerEvent,
    ui,
};

pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    events: EventStream,
    tick_interval: Interval,
    render_interval: Interval,
    proxy_events: mpsc::Receiver<ProxyEvent>,
    repeater_events: mpsc::Receiver<RepeaterEvent>,
    intruder_events: mpsc::Receiver<IntruderEvent>,
    active_scanner_events: mpsc::Receiver<ActiveScannerEvent>,
    ai_events: mpsc::Receiver<AiEvent>,
    restored: bool,
}

impl Tui {
    pub fn new(
        tick_rate: Duration,
        frame_rate: Duration,
        proxy_events: mpsc::Receiver<ProxyEvent>,
        repeater_events: mpsc::Receiver<RepeaterEvent>,
        intruder_events: mpsc::Receiver<IntruderEvent>,
        active_scanner_events: mpsc::Receiver<ActiveScannerEvent>,
        ai_events: mpsc::Receiver<AiEvent>,
    ) -> Result<Self> {
        enable_raw_mode().wrap_err("failed to enable raw mode")?;

        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
            .wrap_err("failed to enter alternate screen")?;

        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).wrap_err("failed to create terminal")?;

        Ok(Self {
            terminal,
            events: EventStream::new(),
            tick_interval: time::interval(tick_rate),
            render_interval: time::interval(frame_rate),
            proxy_events,
            repeater_events,
            intruder_events,
            active_scanner_events,
            ai_events,
            restored: false,
        })
    }

    pub fn draw(&mut self, app: &App) -> Result<()> {
        self.terminal
            .draw(|frame| ui::render(frame, app))
            .wrap_err("failed to draw UI")?;
        Ok(())
    }

    pub async fn next_event(&mut self) -> Result<Event> {
        loop {
            tokio::select! {
                _ = self.tick_interval.tick() => return Ok(Event::Tick),
                _ = self.render_interval.tick() => return Ok(Event::Render),
                maybe_proxy_event = self.proxy_events.recv() => {
                    if let Some(event) = maybe_proxy_event {
                        return Ok(Event::ProxyEvent(event));
                    }
                }
                maybe_repeater_event = self.repeater_events.recv() => {
                    if let Some(event) = maybe_repeater_event {
                        return Ok(Event::RepeaterEvent(event));
                    }
                }
                maybe_intruder_event = self.intruder_events.recv() => {
                    if let Some(event) = maybe_intruder_event {
                        return Ok(Event::IntruderEvent(event));
                    }
                }
                maybe_active_scanner_event = self.active_scanner_events.recv() => {
                    if let Some(event) = maybe_active_scanner_event {
                        return Ok(Event::ActiveScannerEvent(event));
                    }
                }
                maybe_ai_event = self.ai_events.recv() => {
                    if let Some(event) = maybe_ai_event {
                        return Ok(Event::AiEvent(event));
                    }
                }
                maybe_event = self.events.next() => {
                    match maybe_event {
                        Some(Ok(event)) => {
                            if let Some(event) = Self::map_crossterm_event(event) {
                                return Ok(event);
                            }
                        }
                        Some(Err(error)) => return Err(error).wrap_err("failed to read terminal event"),
                        None => return Ok(Event::Tick),
                    }
                }
            }
        }
    }

    pub fn restore(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }

        disable_raw_mode().wrap_err("failed to disable raw mode")?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )
        .wrap_err("failed to leave alternate screen")?;
        self.terminal
            .show_cursor()
            .wrap_err("failed to show cursor")?;
        self.restored = true;
        Ok(())
    }

    fn map_crossterm_event(event: CrosstermEvent) -> Option<Event> {
        match event {
            CrosstermEvent::Key(key) => Some(Event::Key(key)),
            CrosstermEvent::Mouse(mouse) => Some(Event::Mouse(mouse)),
            CrosstermEvent::Resize(width, height) => Some(Event::Resize(width, height)),
            CrosstermEvent::FocusGained
            | CrosstermEvent::FocusLost
            | CrosstermEvent::Paste(_) => None,
        }
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
