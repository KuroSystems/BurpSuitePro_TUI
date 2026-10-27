# Proxima TUI

Terminal-first HTTP/HTTPS interception proxy and web-security testing workbench
(Rust + ratatui) for a Burp-style workflow.

## Run

```bash
cargo run     # TUI; press `s` in the Settings tab to start the proxy
cargo test    # unit tests: no sockets, no display, no root
```

## Status

Proxima is pre-1.0 and some tabs are further along than others. Rather than let the
controls below overstate the tool:

| Area | State |
|---|---|
| Proxy (HTTP/1.1 + HTTP/2 MITM), Repeater, Intruder, Decoder, Comparer | Working |
| Passive scanner, project persistence, findings export | Working |
| Active scanner | Working, but three fixed probes and a non-configurable 100 ms throttle |
| WebSockets | Records upgrade handshakes only |
| Plugins | Discovers and lists WASM manifests; no runtime is wired in yet |
| AI assistant | Working with a local Ollama endpoint; redaction is best-effort, not a security boundary |
| Scope rules | Advisory: used for highlighting and UI guards, **not** enforced by the proxy |

Test coverage is thin (it is being built up); treat this as a tool for authorized
lab work and your own targets, not as a hardened production service. See
[`SECURITY.md`](SECURITY.md) for the limitations that matter.

## Keyboard controls

- `Left` / `Right` or `Shift+Tab` / `Tab`: switch tabs
- Proxy tab: `j`/`k` or arrow keys select flows, `g`/`G` jump to first/last, `/` searches, mouse wheel scrolls details
- Repeater tab: edit raw HTTP text, `Ctrl+Enter` sends, `Ctrl+T` opens a new tab from the selected proxy flow, `Ctrl+W` closes, `F2` renames, `Ctrl+Left`/`Ctrl+Right` switches sub-tabs
- Scope tab: `a` add regex, `e` edit, `d` delete, `Space` enable/disable, `i` include, `o` exclude, `t` test URL
- Intruder tab: mark payload positions with `§value§`, `F5` starts/resumes, `F6` pauses, `F7` stops, `F8` cycles attack type, `F9` exports CSV, `0/2/4/5` filters results
- Decoder tab: type input, `1-0` add transforms, `Delete` removes, `Alt+Up/Down` reorders; `Ctrl+D` from Proxy sends selected body to Decoder
- Comparer tab: edit left/right panes, `Tab` switches pane focus, `F3`/`w` toggles line/word/binary mode; `Ctrl+M` from Proxy marks two flows to compare
- Scanner tab: passive findings from YAML/JSON definitions; `Enter` jumps to flow, `i/l/m/h/c` filter severity, `1/2/3` filter confidence, `[/]` select check, `e` toggles check, `r` reloads definitions, `x` exports JSON/HTML
- Active tab: opt-in safe active checks with `e`, add selected in-scope proxy target with `a`, start with `F5`, stop with `F7`
- WebSockets tab: shows recorded WebSocket upgrade handshakes; `j/k` navigates
- AI tab: local Ollama assistant; `Ctrl+A` attaches selected Proxy flow, `Alt+1..6` loads quick prompts, `Ctrl+Enter` sends prompt
- Plugins tab: loads WASM plugins from `~/.proxima/plugins` or `PROXIMA_PLUGIN_DIR`; `r` reloads, `e`/`Space` toggles, `j/k` navigates
- Settings tab: `s` starts the local proxy, `x` stops it, `Ctrl+S` saves, `Ctrl+O` opens
- `Ctrl+C`, `Esc`, or `q`: quit cleanly

## Proxy and Repeater

The AI tab provides a local Ollama-powered Proxima AI Analyst for natural-language questions, selected-flow explanations, risk reasoning, and safe next-step suggestions. The Proxy tab shows a live traffic table and split request/response detail pane for captured flows. In-scope flows are highlighted according to regex rules in the Scope tab. The Repeater tab can open the selected flow as editable raw HTTP, send it asynchronously, and show response status, headers, body, timing, size, and recent send history. The Intruder tab runs payload attacks using `§position§` markers with Sniper, Battering Ram, Pitchfork, and Cluster Bomb generation strategies and streams results into a sortable table. Decoder chains Base64/hex/URL/HTML/hash/JWT/JSON transforms with live preview. Comparer provides line, word, and binary hex diff views for two text or HTTP message inputs. Scanner runs passive YAML/JSON issue definitions against captured traffic and persists findings to the project database. Active Scanner is opt-in and scope-gated, running only safe probes with a 10 req/s target throttle. The proxy serves MITM connections over whichever protocol ALPN negotiated (`h2` or `http/1.1`), and records WebSocket upgrade handshakes in the WebSockets tab (frames are not proxied yet). Captured bodies are stored exactly as they arrived; anything that reads them for display, scanning, or analysis goes through a bounded decoder for `gzip`, `br`, `deflate`, and `zstd`, and the detail pane labels which coding was unwrapped.

Captured flows are written by a background thread, so a slow disk does not stall the
interface; `Ctrl+S` and quitting both drain the queue before touching the project file.

Projects are SQLite `.db` files. On startup, Proxima opens `PROXIMA_PROJECT` if set, otherwise it creates an untitled project in the system temp directory. Set `PROXIMA_SAVE_AS=/path/to/project.db` before pressing `Ctrl+S` to copy the current project to a single database file. Set `PROXIMA_OPEN_PROJECT=/path/to/project.db` before pressing `Ctrl+O` to open another project.

The proxy listens on `127.0.0.1:8080` by default. Override it with `PROXIMA_PROXY_LISTEN=127.0.0.1:9090 cargo run`. Configure your browser or OS HTTP/HTTPS proxy to use that address, then start the proxy from the Settings tab.

On first start, Proxima generates a local MITM CA at:

- `certs/proxima-ca.pem`
- `certs/proxima-ca-key.pem`

Import `certs/proxima-ca.pem` into your browser or system trust store to avoid HTTPS certificate warnings during interception.

Traffic metadata is emitted with `tracing` under the `proxy::traffic` target. Logs are written to `logs/proxima-tui.log` so stdout is not corrupted while the TUI is active. If you explicitly want stdout traffic logs for proxy testing, run with `PROXIMA_STDOUT_LOG=1 cargo run`.

## Build and release

Development build:

```bash
cargo run
```

Release build:

```bash
cargo build --release
```

Static Linux binary:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

Tagged releases are built by GitHub Actions (`.github/workflows/release.yml`) for:

- `x86_64-unknown-linux-musl`
- `x86_64-pc-windows-gnu`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Install latest release:

```bash
curl -fsSL https://raw.githubusercontent.com/KuroSystems/BurpSuitePro_TUI/main/scripts/install.sh | sh
```

## Plugin development

Plugins are WebAssembly modules loaded from `~/.proxima/plugins/` or `PROXIMA_PLUGIN_DIR`. For each `plugin.wasm`, optionally place `plugin.json` beside it:

```json
{
  "id": "my-plugin",
  "name": "My Plugin",
  "version": "0.1.0",
  "hooks": ["on_new_flow"]
}
```

Plugins are currently **discovered and listed, not executed**: the manager scans the
directory and shows manifests and hooks in the Plugins tab. The host functions below
are the intended ABI and are not yet linked into a runtime:

- `get_selected_flow`
- `send_request`
- `log_message`
- `add_finding`

Example Rust plugin source lives in `examples/plugin-rust/`. Build it for WASM, then copy the `.wasm` and sidecar JSON into your plugin directory:

```bash
cd examples/plugin-rust
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
mkdir -p ~/.proxima/plugins
cp target/wasm32-unknown-unknown/release/proxima_host_counter_plugin.wasm ~/.proxima/plugins/proxima-host-counter.wasm
cp proxima-host-counter.json ~/.proxima/plugins/proxima-host-counter.json
```

Reload plugins from the Plugins tab with `r`.

## Security testing ethics

Only intercept, scan, or actively probe systems you own or are explicitly authorized to test. Active checks in Proxima are designed to be safe and non-destructive, but they still send traffic to targets and may trigger monitoring. Keep scope rules narrow, obtain written authorization, respect rate limits, and stop immediately if a target behaves unexpectedly.

## License

Dual-licensed under either the [MIT License](LICENSE-MIT) or the
[Apache License 2.0](LICENSE-APACHE), at your option. Contributions are accepted
under the same terms — see [`LICENSE`](LICENSE) and [`CONTRIBUTING.md`](CONTRIBUTING.md).
