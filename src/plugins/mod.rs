use std::{fs, marker::PhantomData, path::{Path, PathBuf}};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::{models::flow::HttpFlow, scanner::Finding};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub hooks: Vec<PluginHook>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginHook {
    OnRequest,
    OnResponse,
    OnNewFlow,
}

#[derive(Debug, Clone)]
pub enum HostExport {
    GetSelectedFlow,
    SendRequest,
    LogMessage,
    AddFinding,
}

impl HostExport {
    pub const ALL: [Self; 4] = [
        Self::GetSelectedFlow,
        Self::SendRequest,
        Self::LogMessage,
        Self::AddFinding,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Self::GetSelectedFlow => "get_selected_flow",
            Self::SendRequest => "send_request",
            Self::LogMessage => "log_message",
            Self::AddFinding => "add_finding",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PluginLogEntry {
    pub timestamp: DateTime<Local>,
    pub plugin_id: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PluginInfo {
    pub manifest: PluginManifest,
    pub wasm_path: PathBuf,
    pub manifest_path: Option<PathBuf>,
    pub enabled: bool,
    pub loaded_at: DateTime<Local>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PluginManager {
    pub plugin_dir: PathBuf,
    pub plugins: Vec<PluginInfo>,
    pub logs: Vec<PluginLogEntry>,
    _runtime_marker: PhantomData<extism::Manifest>,
}

impl PluginManager {
    pub fn load_default() -> Self {
        let plugin_dir = std::env::var_os("PROXIMA_PLUGIN_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(default_plugin_dir);
        let mut manager = Self {
            plugin_dir,
            plugins: Vec::new(),
            logs: Vec::new(),
            _runtime_marker: PhantomData,
        };
        manager.reload();
        manager
    }

    pub fn reload(&mut self) {
        self.plugins.clear();
        if let Err(error) = fs::create_dir_all(&self.plugin_dir) {
            self.log("plugin-manager", format!("failed to create plugin dir: {error}"));
            return;
        }

        let Ok(entries) = fs::read_dir(&self.plugin_dir) else {
            self.log("plugin-manager", "failed to read plugin directory");
            return;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("wasm") {
                continue;
            }
            let manifest_path = path.with_extension("json");
            let manifest = load_manifest(&path, &manifest_path);
            self.plugins.push(PluginInfo {
                manifest,
                wasm_path: path,
                manifest_path: manifest_path.exists().then_some(manifest_path),
                enabled: true,
                loaded_at: Local::now(),
                last_error: None,
            });
        }

        let count = self.plugins.len();
        self.log("plugin-manager", format!("loaded {count} wasm plugin(s)"));
    }

    pub fn toggle(&mut self, index: usize) {
        let mut log: Option<(String, String)> = None;
        if let Some(plugin) = self.plugins.get_mut(index) {
            plugin.enabled = !plugin.enabled;
            log = Some((
                plugin.manifest.id.clone(),
                format!(
                    "plugin {}",
                    if plugin.enabled { "enabled" } else { "disabled" }
                ),
            ));
        }
        if let Some((id, message)) = log {
            self.log(&id, message);
        }
    }

    pub fn on_new_flow(&mut self, flow: &HttpFlow) -> Vec<Finding> {
        let mut logs = Vec::new();
        for plugin in self.plugins.iter().filter(|plugin| plugin.enabled) {
            if plugin.manifest.hooks.contains(&PluginHook::OnNewFlow) {
                logs.push((
                    plugin.manifest.id.clone(),
                    format!("on_new_flow received flow #{} {} {}", flow.id, flow.method, flow.uri),
                ));
            }
        }
        for (id, message) in logs {
            self.log(&id, message);
        }
        Vec::new()
    }

    pub fn log(&mut self, plugin_id: impl Into<String>, message: impl Into<String>) {
        self.logs.push(PluginLogEntry {
            timestamp: Local::now(),
            plugin_id: plugin_id.into(),
            message: message.into(),
        });
        if self.logs.len() > 1_000 {
            let overflow = self.logs.len() - 1_000;
            self.logs.drain(0..overflow);
        }
    }

    pub fn host_exports() -> Vec<&'static str> {
        HostExport::ALL.iter().map(HostExport::name).collect()
    }
}

fn default_plugin_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".proxima")
        .join("plugins")
}

fn load_manifest(wasm_path: &Path, manifest_path: &Path) -> PluginManifest {
    if manifest_path.exists() {
        if let Ok(content) = fs::read_to_string(manifest_path) {
            if let Ok(manifest) = serde_json::from_str::<PluginManifest>(&content) {
                return manifest;
            }
        }
    }

    let id = wasm_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("plugin")
        .to_string();
    PluginManifest {
        name: id.clone(),
        id,
        version: "0.0.0".to_string(),
        description: "WASM plugin without sidecar manifest".to_string(),
        hooks: vec![PluginHook::OnNewFlow],
    }
}
