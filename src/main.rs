mod app;
mod db;
mod events;
mod models;
mod plugins;
mod proxy;
mod scanner;
mod store;
mod tui;
mod ui;

use std::{env, fs, io, time::Duration};

use color_eyre::eyre::{Context, Result};
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use tokio::sync::mpsc;

use crate::{app::App, events::Event, store::FlowStore, tui::Tui};

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    init_logging()?;

    info!("starting proxima-tui");

    let (flow_store, proxy_events) = FlowStore::new();
    let (repeater_tx, repeater_events) = mpsc::channel(128);
    let (intruder_tx, intruder_events) = mpsc::channel(1024);
    let (active_scanner_tx, active_scanner_events) = mpsc::channel(256);
    let (ai_tx, ai_events) = mpsc::channel(64);
    let mut app = App::new(flow_store, repeater_tx, intruder_tx, active_scanner_tx, ai_tx);
    let mut tui = Tui::new(
        Duration::from_millis(250),
        Duration::from_millis(16),
        proxy_events,
        repeater_events,
        intruder_events,
        active_scanner_events,
        ai_events,
    )?;
    tui.draw(&app)?;

    let app_result = run(&mut tui, &mut app).await;
    let restore_result = tui.restore();

    if let Err(error) = &app_result {
        error!(?error, "application loop failed");
    }

    restore_result?;
    app_result
}

async fn run(tui: &mut Tui, app: &mut App) -> Result<()> {
    while !app.should_quit {
        let event = tui.next_event().await?;
        match event {
            Event::Render => tui.draw(app)?,
            event => app.handle_event(event),
        }
    }

    Ok(())
}

fn init_logging() -> Result<()> {
    fs::create_dir_all("logs").wrap_err("failed to create logs directory")?;
    let log_file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("logs/proxima-tui.log")
        .wrap_err("failed to open log file")?;

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = fmt::layer()
        .with_ansi(false)
        .with_writer(move || {
            log_file
                .try_clone()
                .expect("failed to clone proxima-tui log file handle")
        });

    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    if env::var_os("PROXIMA_STDOUT_LOG").is_some() {
        subscriber
            .with(fmt::layer().with_ansi(true).with_writer(io::stdout))
            .init();
    } else {
        subscriber.init();
    }

    Ok(())
}
