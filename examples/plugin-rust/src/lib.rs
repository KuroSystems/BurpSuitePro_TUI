use std::collections::BTreeMap;

use extism_pdk::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct FlowEvent {
    id: u64,
    method: String,
    uri: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Metrics {
    counts_by_host: BTreeMap<String, u64>,
}

#[plugin_fn]
pub fn on_new_flow(input: String) -> FnResult<String> {
    let event: FlowEvent = serde_json::from_str(&input)?;
    let host = event
        .uri
        .split("//")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("unknown")
        .to_string();

    let mut metrics = load_metrics()?;
    *metrics.counts_by_host.entry(host.clone()).or_default() += 1;
    save_metrics(&metrics)?;

    log_message(&format!(
        "flow #{} {} counted for host {}",
        event.id, event.method, host
    ))?;

    Ok(serde_json::to_string(&metrics)?)
}

fn load_metrics() -> FnResult<Metrics> {
    if let Some(raw) = var::get("metrics")? {
        Ok(serde_json::from_slice(raw.as_bytes())?)
    } else {
        Ok(Metrics::default())
    }
}

fn save_metrics(metrics: &Metrics) -> FnResult<()> {
    var::set("metrics", serde_json::to_string(metrics)?)?;
    Ok(())
}

#[host_fn]
extern "ExtismHost" {
    fn log_message(message: &str);
}
