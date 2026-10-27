# Proxima — Feature Strategy for a Defensible Open-Source Contribution

**Status:** analysis + proposal · **Date:** 2026-10-27 · **Codebase analysed:** `main@9dad462` (6,664 lines of Rust, 35 files, 12 TUI tabs, 0 tests)

> **Update, same day — Phase 0 partially landed.** The two credibility blockers that
> change behaviour (B1 HTTP/2 dispatch, B2 content decoding) are fixed, along with
> the licensing and CI scaffolding. See [§9 Phase 0 progress](#9-phase-0-progress).
> The analysis below is left as written at review time so the delta is visible.

---

## 0. TL;DR

Proxima already has the shape of a Burp-class workbench in a terminal: a MITM proxy, Repeater, Intruder, Decoder, Comparer, passive/active scanning, a WASM plugin surface, SQLite projects, and a local Ollama assistant. Almost every one of those is **implemented to the depth of a demo**, not to the depth of a tool someone would trust on a client engagement. Competing on "Burp, but in a terminal" is a losing frame: Caido already owns "lighter than Burp" and has a head start on polish.

The winning frame is different, and the codebase is unusually well positioned for it:

> **Proxima should be the proxy you can *prove* things with.**
> Every byte is attributable, every action is authorized, every claim is cited, every extension is sandboxed, and every artefact is machine-readable.

That thesis produces five features that no competitor ships together, and — critically — each produces a **reusable artefact for the wider ecosystem** (a spec, a crate, a conformance suite, a corpus), which is what actually distinguishes "meaningful open-source contribution" from "a personal tool on GitHub".

| # | Feature | One-line pitch | Why nobody else has it | Ecosystem artefact |
|---|---------|----------------|------------------------|--------------------|
| **F1** | **Evidence Ledger & deterministic replay** | Every session becomes a git-diffable, hash-chained, redaction-marked bundle you can re-run against staging and semantically diff | Burp/ZAP/Caido record traffic; none replay a whole engagement deterministically with semantic diffing + SARIF | `proxima-ledger` crate + bundle JSON Schema + public flow corpus |
| **F2** | **Capability-sandboxed WASM extension platform** | A real plugin runtime with a versioned ABI, fuel metering, per-plugin network/flow capabilities, signed registry, and snapshot conformance tests | Burp = JVM Montoya; ZAP = in-process Jython/JS; Caido = web JS. None sandbox, meter, or conformance-test extensions | ABI spec + Rust/Python/TS SDKs + plugin conformance harness |
| **F3** | **Grounded local AI** | An analyst whose every statement must cite a flow/header/body anchor, whose actions arrive as reviewable diffs, and which cannot phone home | Burp AI / Caido AI are cloud-first and unverifiable; nothing enforces citations or egress policy | Redaction benchmark corpus + citation-verification harness |
| **F4** | **Enforceable engagement envelope** | Authorization, scope, time window, RPS/budget, method denylist and halt conditions as a *signed file enforced in the proxy kernel* — not a UI hint | Every competitor treats scope as advisory; enforcement is manual discipline | `engagement.yaml` spec + audit-log format others can implement |
| **F5** | **Headless control plane (`serve` + MCP)** | The same engine driven by a typed JSON-RPC API and an MCP server, so CI and LLM agents can use it — TUI optional | TUI tools are keyboard dead-ends; mitmproxy's API is Python-only and loosely typed; Burp needs Java | Published RPC schema + `proxima-core` crate for third-party front-ends |

**But first** there is Phase 0 work that must precede any of this, because four things currently make the project hard to take seriously: browsers will fail against the MITM (ALPN negotiates `h2`, the server speaks HTTP/1.1), no content-encoding is ever decoded (so scanners and AI analyse gzip bytes), there is no license file, and the repo is named after someone else's trademark. See §2.4.

---

## 1. Method

I read every file in the repository rather than the README. Concretely:

- All 35 Rust sources under `src/` (proxy core, models, scanner, UI, DB, app state machine), plus `Cargo.toml`, `resources/passive/*.yaml`, `examples/plugin-rust/`, `scripts/install.sh`, `docs/release-workflow.yml`, and README claims.
- Traced the two hot paths that determine whether this is a toy or a tool: the proxy request lifecycle (`src/proxy/server.rs:96-250`) and the event/render loop (`src/tui.rs:83-130`, `src/app.rs:451`).
- Cross-checked every README claim against code, to separate *working*, *scaffolded*, and *claimed-but-absent* (table below).
- Benchmarked the competitive field (Burp Suite Pro, OWASP ZAP, Caido, mitmproxy) on the axes that matter for differentiators, not on feature-count checklists.

### Repo facts

| Metric | Value |
|---|---|
| Rust LOC | 6,664 across 35 files |
| Largest file | `src/app.rs` — 2,063 lines (31% of the codebase, a single `App` struct with ~60 public fields) |
| Tests | **0** (`grep -rn "#\[test\]"` → no matches) |
| CI | one workflow, and it is misplaced at `docs/release-workflow.yml` (no `.github/` directory), so tagged releases do not run |
| License | **none** (`licenseInfo: null` on GitHub) |
| Stars / forks / description | 1 / 0 / *(empty)* |
| Dependencies | 35 direct; extism, tungstenite, diffy, csv, reqwest, hyper, rusqlite |
| Config surface | environment variables only (`PROXIMA_*`), no config file, no flags, no `--help` |

---

## 2. What the tool is today

### 2.1 Architecture (as built)

```
main.rs ──► Tui (crossterm EventStream, 250 ms tick, 60 fps render)
        └─► App (all state, all keybindings, all actions)  ← 2,063 lines
              ├── FlowStore     Arc<RwLock<Vec<HttpFlow>>> + mpsc → TUI
              ├── Database      rusqlite, WAL, msgpack blobs per flow/response
              ├── proxy::run_proxy   hyper http1 + rustls MITM + rcgen CA
              ├── models::{repeater,intruder,decoder,comparer,scope,ai,websocket}
              ├── scanner::{engine (YAML regex), active (3 fixed probes)}
              └── plugins::PluginManager  (directory scan only)
```

The proxy is a `CONNECT` → per-domain TLS → hyper `service_fn` chain, forwarding via `reqwest`. Data flow is one-directional and clean; the `InterceptHandler` trait is the right seam for a policy layer, and it is currently occupied by `LoggingHandler`, which always returns `Decision::Continue` (`src/proxy/handler.rs:22-45`).

### 2.2 Capability reality check

| Claimed in README | Reality in code | Verdict |
|---|---|---|
| Intercepting proxy with HTTPS MITM | CONNECT + rcgen CA + rustls works; advertises `h2` in ALPN but serves HTTP/1.1 (`src/proxy/server.rs:175`, `:192`) | **Broken for modern browsers** |
| Live traffic table, request/response detail | Clones the entire flow vector (bodies included) on every 60 fps frame (`src/ui/proxy_tab.rs:14`, `src/ui/mod.rs:197`) | **Works, will collapse > ~5-10k flows** |
| Repeater with history | Works, async send, status/timing/size | **Works** |
| Intruder, 4 attack types | Payload generation is correct and complete; "pause" aborts the task and *restarts from scratch* (`src/app.rs:979-985`, `:1347-1351`) | **Works, pause is a lie** |
| Passive scanner, YAML/JSON definitions | Works, but no decompression, no MIME/context gating, no per-issue dedupe across flows (`db.rs:102` only dedupes per flow) | **Works, high FP rate** |
| Active scanner, scope-gated, 10 req/s | 3 hardcoded probes; rate limit is a fixed 100 ms interval (`scanner/active.rs:116`); targets are auto-confirmed at enqueue (`app.rs:1621`); the *proxy itself* never checks scope (`server.rs:302-337`) | **Safety claim is not enforced** |
| WebSockets tab | Records the upgrade handshake only (`server.rs:367`); `tungstenite` is imported but never proxies a frame | **Scaffold** |
| WASM plugins with host APIs | Directory scan + logging. `extism` appears only as `PhantomData` (`plugins/mod.rs:75`); `on_new_flow` returns `Vec::new()` (`:143-157`); README says host exports are "planned" | **Scaffold** |
| AI Analyst (local Ollama) | Single non-streaming POST; naive line-based "redaction" that rewrites whole lines (`app.rs:1906-1917`); no citation requirement; any URL accepted | **Works, unsafe to trust** |
| Project files, `Ctrl+S` save-as | SQLite with WAL; save-as copies the DB | **Works** |
| HTML/JSON findings export | Works, but destinations come from env vars (`app.rs:1578`), no SARIF, no bundle | **Works, non-composable** |

### 2.3 Where the engineering debt actually bites

1. **Rendering is O(n) clones per frame.** `App::filtered_flow_indices()` clones every flow; `ui::render` clones again; both run at 60 fps *and* on every keystroke. Each `HttpFlow` owns full `Bytes` bodies. At 10k flows this is hundreds of MB of `memcpy` per second — on a tool whose entire selling point is "Rust, so it stays light".
2. **SQLite writes happen on the UI thread.** `app.rs:345` calls `database.save_flow` synchronously inside the event handler; a slow disk stalls input.
3. **`App` is a god object.** 60+ public fields, all actions are key-handler methods. There is no way to invoke a behaviour without synthesising a keystroke, which is precisely what blocks F5.
4. **No seam for policy.** `reqwest::Client` is constructed in at least four places (proxy forward, Intruder, active scanner, AI). Any safety or egress guarantee must be *architecturally* enforced at one choke point or it will be bypassed.
5. **Zero tests.** For a security tool, untested parsing of hostile bytes (`ParsedRequest::parse`, `decode_blob`, `jwt_decode`, regex definitions) is both a bug risk and a credibility problem — reviewers judge security projects by test density first.

### 2.4 Four credibility blockers (fix before or alongside any feature)

| # | Problem | Evidence | Fix |
|---|---|---|---|
| B1 | **HTTPS busted for modern clients.** ALPN offers `h2`; the accepted stream is then served with `http1::Builder` — Chrome/Firefox/curl negotiating `h2` get a protocol violation. | `server.rs:175` vs `:192` | Either serve with `hyper::server::conn::http2::Builder` when ALPN resolves `h2`, or drop `h2` from ALPN until it is real. Do not ship the middle. |
| B2 | **Bodies are never decoded.** `Accept-Encoding` is forwarded verbatim and the response body is stored/analysed as wire bytes. Every regex check and every AI prompt sees gzip/br binary. | `server.rs:302-337` | Split `WireMessage` (raw, for replay/fidelity) from `View` (decoded: gzip/br/deflate/zstd, charset, structured JSON/form/multipart). This split is a prerequisite for F1 and F3. |
| B3 | **No license.** Without one, nobody may legally use, fork, or contribute. `licenseInfo: null`. | GitHub metadata | Dual MIT / Apache-2.0, plus `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, DCO, issue templates. An hour of work that changes the project's legal status. |
| B4 | **Repo name uses a third-party trademark.** `BurpSuitePro_TUI` implies affiliation with PortSwigger's "Burp Suite Professional". This caps credibility with exactly the audience you want (pentesters, OSS maintainers) and could force a rename later at the worst moment. | repo name | Rename to `proxima`; describe comparisons only in prose ("a Burp-style workflow"), never in the name. Verify the new name's crate/npm/trademark availability before publishing crates. |

Also worth fixing cheaply: move the workflow to `.github/workflows/release.yml` (currently `docs/`), add a `test` job with `cargo clippy -- -D warnings` and `cargo fmt --check`, publish a real `--help`, and add a config file so users stop needing `PROXIMA_*` env vars for basic settings.

---

## 3. Where the white space is

| Axis | Burp Suite Pro ($475–499/yr, Java, GUI) | OWASP ZAP (Apache-2.0, Java, GUI/daemon) | Caido (Rust core, web UI, freemium, closed source) | mitmproxy (MIT, Python, TUI) | **Proxima's opening** |
|---|---|---|---|---|---|
| Interface | Swing desktop | Swing desktop + daemon | Browser SPA | TUI (console) | **TUI + headless: one binary over SSH, zero deps** |
| Extensions | 500+ BApps, JVM Montoya | in-process Jython/JS | web JS plugins | Python addons | **WASM: language-agnostic, sandboxed, metered, signed registry** |
| Reasoning about traffic | Filters + Bambdas | Filters | HTTPQL | Python scripts | **Typed query API + deterministic diff, no DSL to learn** |
| Reproducibility | Manual; Repeater history | Baseline scan JSON (not deterministic replay) | No | `mitmdump -w` capture, no replay semantics | **Hash-chained bundle + deterministic replay + semantic diff + SARIF** |
| Safety enforcement | User discipline | User discipline | User discipline | User discipline | **Signed, kernel-enforced engagement envelope** |
| AI | Burp AI (cloud) | — | AI features (cloud/plugin) | via addons | **Local-first, citation-enforced, egress-policed, diff-based actions** |
| Automation | Extender / DAST edition | Automation framework, CI-friendly | Headless API (API-first) | Python API | **JSON-RPC + MCP, typed schema, agent-native** |

*Sources for competitor positions (accessed 2026-10-27): Caido vs Burp comparisons and licensing status — <https://afine.com/blogs/caido-vs-burp-suite-a-penetration-testers-comparison>, <https://breachfolio.com/compare/burp-vs-caido/>, <https://www.penligent.ai/hackinglabs/burp-suite-alternatives/>; ZAP licence/automation and extension ecosystem — <https://appsecsanta.com/dast-tools/burp-suite-vs-zap>; mitmproxy protocols and scripting — <https://docs.mitmproxy.org/stable/concepts/protocols/>, <https://docs.mitmproxy.org/stable/addons/overview/>.*

Three observations drive the five features:

1. **Everyone is GUI or browser-UI; nobody is deliberately terminal-first with a headless control plane.** Caido proved Rust beats Java on resource use; Proxima can prove terminal-first beats both on *composability*.
2. **Everyone treats safety and provenance as documentation problems.** No mainstream proxy can *prove* which requests were authorized by which engagement, or that a finding was produced under a given scope. That is a gap that consultancies, educators, and CI teams feel painfully.
3. **Every AI feature in the space is unverifiable by construction.** The moment a security tool "suggests" something without grounding it in evidence, professionals stop trusting the whole tool. A citation-enforced assistant is a defensible niche.

---

## 4. The five features

Each feature is specified as: thesis → current evidence → why it differentiates → concrete design → measurable acceptance criteria → effort/risk → ecosystem artefact.

---

### F1 — Evidence Ledger and deterministic replay

> **Thesis:** A session should be a portable, verifiable artefact — not a proprietary DB in `$TMPDIR`. Capture once; replay anywhere; diff semantically; export to CI.

#### Current state

- Flows live in memory (`Arc<RwLock<Vec<HttpFlow>>>`, `src/store.rs:11-17`) and are persisted per-flow to SQLite as msgpack blobs (`db.rs:113`, `encode_blob` at `:398`). `HttpFlow` has no stable identity beyond a monotonic `u64` (`store.rs:33`), no schema version, no redaction marker, no hash, no tags.
- Autosave every 120 ticks (`app.rs:333`) writes repeater tabs, settings, Intruder results and scope rules — **but not flows** (they are saved incrementally at `app.rs:345`).
- Export paths are env-var-gated and minimal: Intruder CSV (`app.rs:1409`), findings JSON/HTML (`app.rs:1578`, `findings_html` at `:1920`). No HAR, no JSONL, no curl, no SARIF, no import.
- Nothing can be replayed: Repeater sends one hand-edited request; there is no "send these 800 captured flows again and tell me what changed".

#### Why it differentiates

This is the single largest capability gap versus every competitor *and* the most useful thing a terminal tool can own. Burp can export items; it cannot deterministically re-drive an engagement and produce a machine-diffable verdict. ZAP's baseline scan is a fresh scan, not a replay of observed traffic. mitmproxy can write a flow file but defines no replay semantics, no volatile-field normalisation, and no tamper evidence. Meanwhile the CI/CD world has settled formats — **SARIF** for results, **HAR** for traffic — that a proxy is perfectly placed to produce and no OSS proxy produces well.

#### Design

```
crates/proxima-ledger/
  record.rs    LedgerRecord { schema, uid (uuidv7), session, seq, ts (UTC),
                              req: Message {wire, view_hash, labels}, resp, timing,
                              redaction: ProfileId, prev: Digest, digest }
  bundle.rs    Bundle = header + records; JSONL, one record per line, chain-validated
  replay.rs    ReplayMode = Exact | Normalized | Assertive
  diff.rs      SemanticDiff { status, headers, body, structure, volatile_ignored }
  export.rs    har | sarif | jsonl | curl | markdown
  normalize.rs Volatile rules: Date, Age, Set-Cookie values, x-request-id,
               cf-ray, ETag, timing, ephemeral JWTs (configurable, versioned)
```

CLI (shared with the TUI; requires F5's engine extraction):

```bash
proxima export --project eng.db --format jsonl --out run-42.jsonl
proxima export --project eng.db --format har  --out run-42.har
proxima replay run-42.jsonl --target https://staging.acme.test --mode normalized \
        --concurrency 8 --rps 5 --report out/sarif.json
proxima diff run-41.jsonl run-42.jsonl --only-changed --md
proxima verify run-42.jsonl            # hash-chain + schema + redaction profile
```

Semantics that make it trustworthy:

- **Stable identity:** `uid = uuidv7()` assigned at capture; `seq` orders the session; replay keeps `uid`, so `uid → uid` diffs survive reordering and retries.
- **Hash chain:** `digest = blake3(canonical(record) || prev)`. `proxima verify` detects truncation, reordering, or hand-editing — cheap tamper evidence, no signatures required (signing is opt-in).
- **Volatile normalisation is explicit and versioned**, printed in the report header, so a diff can never silently "explain away" a real change. Every ignored field is listed with its rule.
- **Assertive mode** turns a flow into a regression test: `--expect status=200, header:content-type~json, body~"\"ok\":true"`. This is what makes the tool usable in CI (`exit 1` on drift).
- **Redaction profile** is recorded in the bundle header, so a shared bundle can be proven to have been redacted before it left the machine.

Rendering: reuse the existing Comparer (`models/comparer.rs`) for side-by-side flow diffs, but at the flow level: a table of `changed / unchanged / new / missing` with per-flow drill-down.

#### Acceptance criteria

1. 1,000-flow bundle: export < 2 s, `verify` < 1 s, replay at 5 rps completes without memory growth > 200 MB.
2. Three consecutive replays of a static target with `--mode normalized` produce **zero** diffs; the same target with a changed header produces exactly one diff, correctly attributed.
3. Emitted SARIF validates against the official schema and is accepted by GitHub code scanning (`upload-sarif`).
4. HAR round-trips through Chrome DevTools import and `har2warc`.
5. Property test: for any bundle, `parse(serialize(x)) == x`, and mutating any byte breaks `verify`.

#### Effort / risk

~5–7 person-weeks (depends on B2 decode split and F5 engine extraction). Risk: normalisation rules becoming a place to hide regressions — mitigate with the explicit rule printout and an "exact" mode that ignores nothing.

#### Ecosystem artefact

`proxima-ledger` as a standalone crate plus a published **bundle JSON Schema** and a **public corpus** of ~200 synthetic-but-realistic flows (auth cookies, gzip bodies, h2, multipart, SSE, WebSocket handshakes) usable by any proxy's test suite. If the schema is good, other tools will emit it — that is the contribution.

---

### F2 — Capability-sandboxed WASM extension platform

> **Thesis:** Extensions are how a security tool scales, and every existing plugin API is either heavyweight (JVM), unsafe (in-process Jython), or web-only. Ship a *real* runtime: versioned ABI, metered, capability-scoped, signed, with conformance tests.

#### Current state

- `PluginManager::reload()` scans a directory for `*.wasm` + optional sidecar JSON and pushes `PluginInfo` structs (`plugins/mod.rs:84-140`).
- The runtime is a marker: `_runtime_marker: PhantomData<extism::Manifest>` (`:75`). No module is ever instantiated.
- `on_new_flow` iterates manifests and logs a string, then returns `Vec::new()` (`:143-157`). No host functions are registered; `host_exports()` (`:171`) is a static string list.
- `README.md:92` says "Host exports planned". `examples/plugin-rust/` declares a `log_message` host fn that would fail at instantiation because it is never linked.
- There is no manifest schema validation, no hook dispatch from the proxy, no error surfacing beyond the Plugins tab's log pane, no signing, no versioning, no permissions.

#### Why it differentiates

Extension ecosystems are the moat in this category (Burp: 500+ BApps; ZAP: hundreds of add-ons), and they are also the biggest weakness of the newcomers (Caido's plugin ecosystem is still small; ZAP add-ons can take down the JVM). A WASM runtime gives three things none of them have simultaneously:

- **Language neutrality with isolation** — Rust, Go (TinyGo), TypeScript (AssemblyScript/jco), and **Python (componentize-py)** all compile to the same ABI. ZAP's huge Python-fluent community gets a migration path; that is an adoption lever, not a feature bullet.
- **Capability security** — a plugin declares exactly which hosts it may talk to, whether it can mutate requests, and how many findings it may emit. Enforced by the host, not by review.
- **Metering** — fuel/epoch limits mean a buggy plugin cannot freeze the UI or wedge the proxy.

#### Design

Manifest (`plugin.json`, schema-validated, semver-checked against `abi_version`):

```json
{
  "id": "proxima/jwt-auditor",
  "name": "JWT auditor",
  "version": "1.2.0",
  "abi": 1,
  "hooks": ["on_response"],
  "capabilities": {
    "flow_read": ["request.headers", "response.body"],
    "flow_write": false,
    "http": { "allow": ["https://jwks.acme.test/*"], "budget_per_minute": 30 },
    "findings": { "max_severity": "high", "max_per_flow": 5 },
    "emit_commands": true
  },
  "limits": { "fuel": 50000000, "memory_mb": 64, "timeout_ms": 1500 }
}
```

Host ABI (v1, deterministic, JSON in/out over Extism memory; WIT interface published for the component-model path):

```
on_request(mut RequestView) -> Decision        // continue | modify | drop
on_response(ResponseView) -> [Mutation]        // header/body edits, only if flow_write
on_flow(FlowView) -> [Finding] | []
on_finding(FindingView) -> [Annotation]
on_command() -> [CommandDef]                   // registers TUI palette entries
on_start(ConfigView) / on_stop()
```

Host functions exposed to plugins (all capability-checked, all logged):
`log(level, msg)`, `get_flow(uid)`, `query_flows(query) -> [uid]`, `send_request(req) -> resp` (subject to the F4 envelope), `add_finding(...)`, `kv_get/kv_set` (namespaced, bounded), `now()`.

Operational surface:

```bash
proxima plugin new jwt-auditor --lang rust|python|ts|go
proxima plugin dev ./jwt-auditor        # hot reload on rebuild, live log tail in TUI
proxima plugin test ./jwt-auditor --corpus corpus/flows --expect snapshots/
proxima plugin pack ./jwt-auditor --sign ~/.proxima/keys/ed25519.key
proxima plugin install proxima/jwt-auditor@1.2.0   # verifies hash + signature from registry index
```

Registry: a static git repo (`proxima-plugins/index`) with a JSON index (`id`, versions, digest, signature, min-abi, capabilities). Signing is Ed25519 over the module digest; the index is signed by maintainers. Install refuses unsigned plugins by default, with an explicit `--allow-unsigned` for local development.

Failure containment: a plugin that traps, exceeds fuel, or times out is disabled for the session with a structured error in the Plugins tab and a `tracing` event — never a panic in the proxy path.

#### Acceptance criteria

1. Conformance suite proves **capability enforcement**: a plugin that calls `send_request` to a non-allowlisted host is denied (assert on error + audit entry); one that writes flow fields with `flow_write: false` is denied; one that emits 100 findings is capped.
2. An infinite-loop plugin is terminated in < 2 s with the UI responsive and the proxy still serving.
3. ABI v1 has three working sample plugins in three languages (Rust, AssemblyScript, Python) that pass the same conformance harness.
4. Hot reload propagates a rebuild in < 300 ms and does not drop in-flight requests.
5. Installer rejects a tampered module (digest mismatch) and an unsigned module without the flag.

#### Effort / risk

~6–8 person-weeks (Extism integration is straightforward; the ABI, SDK templates, and conformance harness are the work). Risks: WASM cold-start cost on the request path (mitigate with instance pooling and async hooks off the hot path); supply-chain trust (mitigate with signatures + capability display on install, "this plugin can contact jwks.acme.test and read response bodies").

#### Ecosystem artefact

The **ABI v1 specification** (versioned, with a changelog and a deprecation policy), three SDK templates, a `proxima-plugin-test` conformance harness that runs headlessly, and a starter registry with 10 reference plugins (JWT auditor, WAF detector, GraphQL operations inventory, Spring Actuator finder, CORS auditor, rate-limit mapper, SAML decoder, OpenAPI diff, Spring4Shell canary, secret scanner). That is a body of work others can build on without touching the proxy.

---

### F3 — Grounded, local-first AI analyst

> **Thesis:** In security work, an unverifiable claim is worse than no claim. Make the assistant *cite* or stay silent, make its actions *diffs* rather than sentences, and make exfiltration structurally impossible by default.

#### Current state

- One-shot, non-streaming `POST /api/chat` to `PROXIMA_OLLAMA_URL` with `stream: false` (`models/ai.rs:117`; request built at `app.rs:1758-1805`, `stream: false` at `app.rs:1797`). Responses appear only when the whole answer is done; a 7B model on CPU means a frozen-looking panel.
- Redaction is a line-rewrite loop: any line containing `token`, `secret`, `password`, etc. is replaced with `"<key>: REDACTED"` (`app.rs:1895-1917`). This destroys JSON structure, drops the surrounding evidence, and *misses* secrets that don't contain those substrings (Bearer values, cookies on other lines, base64 blobs, AWS keys, JWTs, phone numbers).
- Header redaction is a fixed five-name list (`app.rs:1883-1894`); `Proxy-Authorization`, custom `X-Company-Token`, `X-Amz-Security-Token` pass through.
- Context is a truncated string (`max_context_chars: 12_000`) with no notion of *what part of the flow* the model is talking about.
- Any URL is accepted as the provider; there is no egress policy, no audit of what was sent, no provider abstraction beyond Ollama's chat format.
- The 6 quick prompts (`models/ai.rs:141-148`) are good, and the system prompt's refusal of destructive actions (`ai_system_prompt`, `app.rs:1825`) is the right instinct — but both are unenforced text.

#### Why it differentiates

Burp AI and Caido's AI features are cloud-first and produce prose. Practitioners' actual objections are: (a) "I can't send client traffic to a vendor", (b) "It hallucinates endpoints and CVEs I have to double-check", (c) "I can't tell what it actually looked at". A local-first assistant with **citation enforcement** and **egress policy** answers all three, and the diff-based action model makes it non-destructive by construction. No tool in the category enforces any of this.

#### Design

**(a) Grounding and citation enforcement.**

Every flow is turned into an addressable *evidence graph*:

```
flow:1234
  req.method / req.path / req.query[name]
  req.header[authorization] / resp.header[set-cookie]
  req.body.json[$.user.role] / resp.body.span[1024..2048]
  finding:7 (issue=missing-csp, severity=low)
```

Prompts require citations in a strict form: `[flow:1234 resp.header[content-security-policy]]`. After generation, a **validator** checks each citation against the graph; uncited or invalid statements are re-labelled `UNVERIFIED` in the UI, and the answer is rejected-and-retried once with a corrective prompt. The AI tab renders a two-column view: prose on the left, a clickable claim/citation table on the right that jumps the Proxy pane to that anchor. This makes the model's output *navigable* — a real workflow gain, not a gimmick.

**(b) Actions are diffs.**

The model may return a structured proposal, never an action:

```json
{ "proposal": "test-idor", "target": "flow:1234",
  "repeater": { "patch": [
      {"op":"replace","path":"request.line","from":"GET /api/user/42","to":"GET /api/user/43"},
      {"op":"add","path":"request.header[x-proxima-test]","value":"idor-1"}]},
  "rationale": "…", "citations": ["flow:1234 resp.body.json[$.id]"],
  "risk": "read-only", "expected": "200 with different user object = candidate IDOR" }
```

The TUI shows it as a unified diff on the Repeater pane; `y` applies, `n` rejects, `e` edits. Nothing is sent automatically, ever — and every applied proposal is recorded in the ledger with its citations, so a finding's provenance includes "which hypothesis produced it".

**(c) Egress policy and provider abstraction.**

```yaml
ai:
  providers:
    local:  { kind: ollama,  url: "http://127.0.0.1:11434", allowed: true }
    remote: { kind: openai-compatible, url: "https://…", allowed: false,
              require_explicit_opt_in: true, redaction: strict }
  default_provider: local
  log_prompts: true            # content-addressed hash + redaction report, never raw secrets
```

Requests to a non-allowlisted endpoint require an interactive confirmation that names the destination and the exact payload size, and are logged. The point isn't paternalism; it's that "did this tool send client data anywhere?" must have an auditable answer.

**(d) A redaction engine worth the name.**

Format-aware (JSON, form-urlencoded, multipart, cookies, JWT, YAML, XML), detector-based (entropy + known patterns: AWS/GCP keys, JWTs, private keys, emails, phone numbers, IBAN, session-looking hex), with **reversible placeholders**: the model sees `<SECRET:7>`, and the response is re-hydrated locally so you can still read your own answer. Plus a per-request redaction report in the status line (`12 secrets masked, 0 detector errors`) so masking is visible rather than assumed.

**(e) Streaming.**

`stream: true` with token events on the existing `ai_events` channel; first token renders in < 1 s instead of a 30 s blank pane.

#### Acceptance criteria

1. **Citation integrity:** on a golden set of 50 answers, 0 claims labelled VERIFIED lack a resolvable anchor; the validator's unit tests cover malformed, out-of-range, and stale anchors.
2. **Leak test:** a published corpus of 120 fixtures (headers, JSON, multipart, JWTs, PEM, query strings) yields 0 raw secrets in the outbound payload, with a per-fixture expected-redaction assertion in CI. This is a test the whole ecosystem can reuse.
3. **Egress:** with the default config, no packet leaves `127.0.0.1`; enabling a remote provider requires explicit opt-in and produces an audit entry.
4. **Non-destructiveness:** no code path sends a request derived from model output without an explicit user confirmation (enforced by a test that greps for the constructor, or better, by making the send path require a `Confirmed<T>` token — see F4).
5. p95 first-token < 1.5 s on a 7B model at Q4 with 8 GB RAM.

#### Effort / risk

~4–6 person-weeks. Risks: smaller models handle strict citation poorly — mitigate by making the grounded features (evidence extraction, checklist generation, "what changed between these two flows") work deterministically *without* the LLM, and treating generation as an add-on. Also: don't turn the prompt into a jailbreak surface — the tool never executes model output as code, only as data.

#### Ecosystem artefact

The **redaction benchmark** (fixtures + expected results + a runner) and the **citation-verification harness**. Both are small, unglamorous, genuinely useful artefacts that other security-AI projects can adopt — exactly the kind of contribution that earns credibility rather than stars.

---

### F4 — Enforceable engagement envelope (authorization as code)

> **Thesis:** Scope in every mainstream proxy is a UI hint that the tool happily ignores. Make authorization a signed, machine-checked document that the *proxy kernel* enforces for every outbound byte, and emit a tamper-evident audit log that proves what happened.

#### Current state — and why the current safety story doesn't hold

- Scope is regex include/exclude in `models/scope.rs:54-88`. It is consulted only for *display* (`ui/proxy_tab.rs:39`, `ui/mod.rs:198`) and for two UI actions (`app.rs:1610`, `:1642`).
- The proxy forwards everything it receives: `forward_request` (`server.rs:302-337`) has no scope check at all. Any in-scope-looking client can send traffic to any host through it.
- Intruder (`models/intruder.rs:220-262`) builds its own `reqwest::Client` and sends everything, with no scope check beyond the pre-send guard at `app.rs:1642` (which is only on the *target* URL, not on redirects or absolute-form request lines).
- Active scanner targets are created **already confirmed**: `confirmed: true` (`app.rs:1621`), which defeats the purpose of the "confirmed" column and the `e` opt-in ritual. A reviewer will notice this in five minutes.
- Rate limiting is a hardcoded `Duration::from_millis(100)` interval (`scanner/active.rs:116`), not configurable and not applied to Intruder-with-rps-0 or Repeater.
- Nothing records *who* initiated a request or under what authorization; `tracing` logs go to `logs/proxima-tui.log` with no integrity guarantee.

#### Why it differentiates

Every competitor's answer to "how do you prevent an accidental scan of production?" is discipline, training, and a scope tab. An *enforced* envelope is a different product category:

- **Consultancies:** attach the SOW. The envelope carries the authorization reference, the window, and the budget; the exported evidence bundle embeds the envelope hash, so every finding is provably produced inside the agreed scope. That is a compliance artefact, not a feature.
- **Educators and students:** hand out an envelope with a 3 rps cap, a time window, and a method denylist so a lab mistake cannot become an incident. No other free tool offers this.
- **Bug bounty:** program scope as code, imported from a YAML you keep in the repo.
- **CI:** `DELETE`/`PUT` denylisted in pipelines where a regression suite must never mutate data.
- **AI/agents (F3, F5):** an agent cannot exceed a boundary you never granted it. This is the precondition for letting an LLM near a proxy.

#### Design

`engagement.yaml` (signed, versioned, schema-validated):

```yaml
apiVersion: proxima.dev/v1alpha1
kind: Engagement
metadata:
  id: acme-staging-2026-10
  operator: alice@example.com
  authorization: { reference: "SOW-2291 §3", date: 2026-10-01 }
scope:
  include: ['^https://staging\.acme\.test(/|$)']
  exclude: ['/logout', '/billing', '^https://staging\.acme\.test/admin']
limits:
  window: { from: 2026-10-27T00:00:00Z, to: 2026-11-10T18:00:00Z }
  max_rps: 5
  max_requests_total: 20000
  burst: 10
  methods: [GET, POST, PUT, PATCH, HEAD, OPTIONS]
  deny_methods: [DELETE, TRACE, CONNECT-to-non-scope]
  halt_on: { status_429: 3, status_5xx_rate: 0.05, latency_ms_p95: 5000 }
data:
  no_store_hosts: ['^https://payments\.acme\.test']
  redact: strict
audit:
  log: .proxima/audit-2026-10.log     # hash-chained, append-only
  require_signed_actions: true
```

Enforcement architecture — the important part:

```rust
// crates/proxima-core/src/policy.rs
pub struct Policy { envelope: Verified<Envelope>, budget: Budget, clock: Clock }

/// The ONLY way to obtain an HTTP client in the workspace.
/// `proxima-core` re-exports no raw client; other crates depend on `Policy`.
pub fn client(&self) -> Result<PolicyClient, PolicyError>;

pub struct PolicyClient { /* wraps reqwest::Client */ }
impl PolicyClient {
    pub async fn send(&self, req: Request) -> Result<Response, PolicyError>;
    // checks: window, scope(include/exclude), method, budget, rps/burst,
    // records: audit entry {who, what, why, envelope_id, prev_hash, hash}
}
```

- **Single choke point.** `reqwest` becomes a private dependency of `proxima-core`; a workspace lint (or a `cargo-deny`-style check in CI) fails the build if any other crate constructs a client. That converts "we promise to respect scope" into "it does not compile if you bypass it".
- **Everything goes through it:** proxy forwarding, Repeater, Intruder, active checks, plugin `send_request`, AI proposals. Denials are *visible* (status line + audit entry), never silent.
- **Preflight blast radius.** Before any multi-request action, show the estimated request count (Intruder already computes `total_requests()`), the budget remaining, and anything the envelope would block. `F5` on Intruder shows "1,200 requests · 4 min at 5 rps · 18% of remaining budget · DELETE requests blocked" before the first packet.
- **Halt conditions** are checked by the policy layer, which returns a typed error that stops the task and requires a human to resume — no auto-retry storms.
- **Audit log** is hash-chained JSONL (`prev`, `hash`, monotonic seq) with entries for every request, denial, plugin install, AI prompt, and envelope change. `proxima audit verify` and `proxima audit export --format md` make it something you can hand over.
- **Tamper evidence:** signing the envelope (Ed25519/minisign) and pinning its hash into the F1 bundle header links evidence to authorization. Changing scope invalidates the signature and requires re-approval.

#### Acceptance criteria

1. **Compile-time bypass prevention:** a CI check (workspace test or `cargo metadata` assertion) proves no crate other than `proxima-core` depends on `reqwest` directly.
2. **Enforcement matrix test:** for each egress path (proxy, Repeater, Intruder, active scanner, plugin HTTP, AI), the same suite asserts allow / deny / budget-exhausted / window-expired behaviour and that each denial produces exactly one audit entry.
3. Budget exhaustion halts within one request of the limit (no overshoot under 8-way concurrency).
4. `audit verify` detects a single flipped byte in a 10k-line log.
5. Preflight estimate is within ±1% of actual request count for all four Intruder attack types.

#### Effort / risk

~3–4 person-weeks (this is the cheapest feature with the loudest story). Risks: users will hate being blocked mid-test — mitigate with a "raise limit" flow that requires re-signing the envelope (which is the point), plus a clearly-labelled `--no-envelope` local-only mode for throwaway lab work. Never allow silent override.

#### Ecosystem artefact

Publish `engagement.yaml` as a small **specification** with a JSON Schema and a reference implementation, plus adapters so ZAP's automation framework and nuclei runs can *consume* the same file for scope and rate limits. A safety envelope that only Proxima honours is a feature; one that other tools honour is a contribution — and a plausible path to being cited by teams' internal standards.

---

### F5 — Headless control plane: `serve`, typed actions, MCP

> **Thesis:** The TUI should be one front-end over a typed engine, not the only way to use the engine. A single binary that can be a TUI, a daemon, a CI step, and an agent tool multiplies every other feature's reach.

#### Current state

- Every behaviour is a keyboard branch in `App::handle_key_event` (`app.rs:451`, ~1,700 lines of match arms). There is no `Action`, no command registry, no palette, no way to invoke anything programmatically.
- `App` is 2,063 lines with ~60 public fields; state changes, persistence, network side effects, and UI copy are interleaved (e.g. `autosave_project` writes settings for a UI message at `app.rs:1479-1490`).
- No CLI subcommands at all: `main.rs:29` goes straight into raw mode; `cargo run -- --help` would start the proxy UI. Configuration is env-only.
- Async work is spawned ad hoc (`tokio::spawn` for proxy, Intruder, active scan, AI) with results funnelled through five separate `mpsc` channels (`main.rs:31-35`) — close to what an event bus needs, but not addressable or cancellable by id.

#### Why it differentiates

- **Composability.** A typed JSON-RPC surface makes Proxima a component: `proxima serve` + a shell script replaces a pile of curl, and `proxima replay` (F1) becomes a CI step. TUI-first tools (mitmproxy aside) are dead ends for automation; this is the single highest-leverage structural change.
- **Agent-native.** An MCP server lets Claude/Cursor/any assistant drive a proxy *within the F4 envelope* — with every action attributed in the audit log. That is a genuinely new capability in this space and a strong reason for the project to be noticed.
- **Testability.** Extracting actions is the only path to the test suite this project needs: `Engine::apply(Action) -> Vec<Event>` is unit-testable without a terminal, which is how you get from 0 to a few hundred tests.
- **Third-party front-ends.** Publishing `proxima-core` lets someone build a web UI, a VS Code panel, or a Go TUI on the same engine. That is how a project becomes infrastructure.

#### Design

**1. Crate split (mechanical but decisive):**

```
crates/
  proxima-core/     Engine, Action, Event, Policy, FlowStore (bounded), Scanner, Repeater,
                    Intruder, Ledger, PluginHost — no ratatui, no crossterm
  proxima-ledger/   F1
  proxima-plugin-abi/ F2
  proxima-tui/      renders Engine state, maps keys → Action
  proxima-cli/      clap: tui | serve | mcp | replay | diff | export | report | plugin | engage | audit
```

`Action` is a closed enum with serde derives, so the CLI, RPC, MCP, and TUI all speak one vocabulary:

```rust
pub enum Action {
    Flow(FlowAction),        // select, filter, tag, annotate, export
    Repeater(RepeaterAction),// open_from_flow, edit, send{confirmed: bool}, close
    Intruder(IntruderAction),// configure, start, pause, resume, stop, export
    Scan(ScanAction),        // passive{defs}, active{target, checks, budget}
    Scope(ScopeAction), Plugin(PluginAction), Ai(AiAction), Project(ProjectAction),
}

pub struct Event { seq: u64, at: DateTime<Utc>, kind: EventKind, action: Option<ActionId> }
```

`Engine::submit(Action) -> ActionId` and `Engine::events() -> broadcast::Receiver<Event>`: one ordered, addressable stream. The TUI subscribes; `serve` streams the same events as SSE; the audit log subscribes too. Cancellation and progress become uniform instead of per-subsystem.

**2. `proxima serve` (JSON-RPC 2.0 over Unix socket; optional localhost TCP with a token):**

```
flow.list   {filter, limit, cursor}        flow.get    {uid}
flow.tag    {uid, labels}                  flow.export {format, query}
repeater.send {request, confirm}           intruder.run {config} / .status {id} / .stop {id}
scan.passive {query}                       scan.active  {target, confirm}
report.build {format: sarif|html|md}       policy.check {request}
plugin.install / .list / .reload           ledger.diff / .replay
```
Schema published as JSON Schema + a generated OpenAPI document; a Rust client and a Python client in the repo. SSE channel `events` mirrors the internal event stream.

**3. `proxima mcp` (stdio and SSE transports):** tools map 1:1 onto safe actions — `list_flows`, `get_flow`, `search_flows(query)`, `propose_test(flow_uid, hypothesis)`, `send_repeater(request, confirm_token)`, `export_report(format)`, `run_passive_scan(query)`. Every destructive or traffic-generating tool requires a confirmation token that the *human* grants in the TUI (or that is pre-authorized by the envelope in CI mode). The MCP surface is the safety story for agentic testing: an agent can look freely, but sending requires a grant that is logged with its rationale.

**4. Config and discoverability:** `proxima.toml` + flags + `--help`; a `:`-prefixed command palette in the TUI that shares the `Action` vocabulary (so every feature is discoverable without memorising 40 keybindings); a `?` help overlay generated from the same registry. This alone fixes the "keyboard archaeology" problem that makes TUI tools hard to adopt.

#### Acceptance criteria

1. **Parity test:** for every TUI action in the registry, a headless RPC/CLI equivalent exists, and a generated matrix test asserts it (missing coverage fails CI).
2. **Action log replay:** a JSONL of `Action` records reproduces a session's state in a headless harness (`proxima script run session.jsonl`) with identical resulting flows.
3. **MCP conformance:** the official MCP inspector lists and invokes all tools; a confirmation-required tool fails closed without a token.
4. **No UI leakage into core:** `proxima-core` does not depend on ratatui/crossterm (CI dependency assertion); `Engine` is exercised by ≥ 150 unit tests with no terminal.
5. `proxima serve` sustains 500 events/s to two subscribers with < 50 MB RSS overhead.

#### Effort / risk

~5–7 person-weeks including the refactor (and it *retires* debt: the 2,063-line `App`, the five channels, the O(n) render clone via a bounded/ring-buffered store with `Arc<Flow>` sharing). Risk: refactor churn mid-feature — sequence it immediately after Phase 0 and before F1's CLI, because F1/F4 both need the choke point.

#### Ecosystem artefact

The published **RPC schema** and the `proxima-core` crate; an MCP server other security tools can copy; a GitHub Action (`proxima-verify`) that replays a bundle, diffs it, and uploads SARIF. Each of these makes the project useful to people who will never open the TUI.

---

## 5. Candidates considered and rejected

Rigor means showing what was ruled out, and why.

| Candidate | Why it's tempting | Why not (now) |
|---|---|---|
| Built-in crawler / spider | Obvious next tab; needed for coverage | Commoditised (katana, ZAP), high effort, low differentiation; better as an *ingested* flow source via F1 import |
| Full DAST engine | "Burp Pro parity" | Unbounded scope; the field's own benchmark showed a newcomer scanner finding 12 unique issues vs Burp's 17 — a credibility risk, not a win |
| Web/GUI front-end | Wider audience | Throws away the only structural advantage (terminal/SSH/single binary) and doubles UI work; F5 lets others build one |
| HTTP/3 + QUIC | Real gap (Caido lacks it) | Only matters after HTTP/2 is correct (B1); narrow value relative to cost |
| HTTPQL/Bambda-style DSL | Caido's stand-out feature | Crowded; a typed query API inside F5 + plugin hooks covers 80% at 20% of the cost |
| Multiplayer/team server | Enterprise appeal | Operational burden far beyond a solo OSS project; naturally enabled later by F5's daemon |
| Mobile app proxying helpers | Real pain point | Ecosystem is solved (Proxydroid, simulators) and OS-level; low leverage |
| Built-in secrets scanner tab | Trendy | Better as a reference plugin (F2) — proves the platform instead of bloating the core |
| Rewriting the proxy on `h2`+`hyper` streaming first | Correctness | It's Phase 0 hygiene, not a differentiator; do it, but don't market it |

---

## 6. Sequencing

```
Phase 0  (3–4 pw)  Hygiene & credibility
  ├─ B1 HTTP/2 correctness (or drop h2 from ALPN)         ← blocks everything factual about "MITM works"
  ├─ B2 wire/view split + gzip/br/deflate/zstd decode     ← blocks F1 fidelity + F3 usefulness
  ├─ B3 license, CONTRIBUTING, SECURITY, templates
  ├─ B4 rename away from trademark; verify name availability
  ├─ tests: fix the misplaced workflow, add clippy/fmt/test CI, first 100 unit tests
  └─ perf: bounded store + Arc sharing, move SQLite off the UI thread

Phase 1  (4–5 pw)  The spine
  ├─ F5a crate split + Action/Event engine (headless first)  ← unblocks F1, F4, tests
  └─ F4  policy choke point + engagement envelope + audit log

Phase 2  (5–7 pw)  The evidence story
  ├─ F1  ledger, bundle, replay, diff, SARIF/HAR export, verify
  ├─ F5b serve + JSON-RPC + MCP
  └─ `proxima-verify` GitHub Action + demo GIF (60 s: capture → diff → SARIF in CI)

Phase 3  (6–8 pw)  The ecosystem story
  └─ F2  WASM host, ABI v1, 3 SDKs, registry, 10 reference plugins, conformance harness

Phase 4  (4–6 pw)  The intelligence story
  └─ F3  streaming, evidence graph, citation validator, redaction engine, egress policy,
         leak corpus, action diffs (wired through F4)

Total ≈ 22–30 person-weeks of focused work. Ship a release at the end of each phase;
the narrative ("provable") is complete only after Phase 2, which is the right moment
for a public launch post.
```

Rationale for the order: Phase 0 makes claims true; Phase 1 builds the seam every other feature needs; Phase 2 delivers a complete, demo-able story that needs no plugin ecosystem or LLM to be compelling; Phase 3 and 4 then attach to stable seams instead of inventing them.

---

## 7. Turning features into recognized contribution

Features alone do not constitute meaningful open-source contribution — reusable artefacts, tests, specs, and responsiveness do. Concretely, each feature above should ship with a matching public good:

| Feature | Artefact | Audience | Success signal |
|---|---|---|---|
| F1 | Bundle JSON Schema + `proxima-ledger` crate + 200-flow public corpus | anyone testing proxies, CI authors | other tools emit/consume the bundle; corpus PRs from outsiders |
| F2 | ABI v1 spec + conformance harness + 3 SDKs + signed registry | plugin authors, ZAP Python community | third-party plugins not written by you |
| F3 | Redaction fixture corpus + citation validator | security-AI projects | reuse of the corpus; citations in papers/posts |
| F4 | `engagement.yaml` spec + audit format + adapters | consultancies, educators, bug-bounty programs | another tool honours the file |
| F5 | RPC schema + `proxima-core` crate + MCP server + GitHub Action | integrators, agent developers | a third-party front-end or CI integration |

Supporting work that reviewers actually weigh:

- **Governance hygiene:** LICENSE (MIT/Apache-2.0), CONTRIBUTING with a "good first issue" path, CODE_OF_CONDUCT, SECURITY.md with a disclosure policy and a threat model (STRIDE over the proxy/plugin/AI surfaces), DCO, release notes and a compatibility policy for the ABI and bundle schema.
- **Documentation as a product:** a docs site (not just README), a WSTG-mapped catalogue of passive checks, a plugin cookbook, an operator's guide to the envelope, and recorded terminal casts (asciinema/GIF) per tab — TUI projects live or die on demo-ability.
- **Distribution:** Homebrew tap, AUR, nixpkgs, a scratch-based Docker image, `cargo install`, and the existing (fixed) static-binary releases for musl/macOS/Windows. Every packaging channel is a discovery channel.
- **Benchmarks that can be reproduced:** memory and throughput on the same laptop for 1k/10k/100k flows; time-to-first-token for local AI; replay throughput. Publish the harness, not just numbers — defensive claims age badly, harnesses stay useful.
- **Community cadence:** monthly release, a public roadmap of the five features, `help wanted` labels per feature, and an RFC directory (`docs/rfcs/0001-engagement-envelope.md`, `0002-plugin-abi.md`) so design happens in the open. RFCs are the cheapest, most credible form of contribution a solo maintainer can make.

**Honest framing.** If the goal is "show I contributed meaningfully", the strongest evidence will be: a spec someone else implements, a corpus someone else uses, a plugin someone else writes, and a CI action someone else adds to their pipeline. Stars follow demos; adoption follows specs and tests. Both matter, but only the second is what maintainers respect — and it is what the five features above are deliberately designed to produce.

---

## 8. Suggested immediate next steps (in this repo, in order)

1. `LICENSE` + `CONTRIBUTING.md` + `SECURITY.md`; move `docs/release-workflow.yml` → `.github/workflows/release.yml`; add a `ci.yml` with fmt/clippy/test. (≈ half a day, unblocks everything socially.)
2. Fix B1 (HTTP/2 or ALPN) and add the wire/view split for gzip — the two correctness bugs that make every downstream feature honest.
3. Land the `Action`/`Event` skeleton and `proxima-core` extraction (F5a) while the codebase is still small enough (35 files) to move cheaply.
4. Then the policy choke point + `engagement.yaml` (F4), because it is the smallest feature that produces the loudest, most defensible story.

I can start on any of these — item 1 and item 2 are self-contained and would make the repository materially more credible this week.

---

## 9. Phase 0 progress

Landed in this pass (`arena/744bd531-burpsuitepro-tui`):

| Item | Status | Where |
|---|---|---|
| **B1** ALPN/h2 mismatch | **Fixed.** The MITM stream is now served with the protocol ALPN selected: `hyper`'s HTTP/2 server when `h2` is negotiated, HTTP/1.1 otherwise (with header-case preservation for replay fidelity). | `src/proxy/server.rs` |
| **B2** no content decoding | **Fixed.** New bounded decoder for `gzip`/`x-gzip`/`deflate` (zlib *and* raw fallback)/`br`/`zstd`, stacked codings unwrapped in reverse order, 32 MiB output cap. Wire bytes are still stored untouched; the detail pane, passive scanner, AI context, Decoder hand-off and Comparer all read the decoded view, and the pane title shows which coding was removed. | `src/net/decode.rs`, `HttpFlow::request_view`/`response_view` |
| **B3** no license | **Fixed.** Dual MIT / Apache-2.0 with a `LICENSE` explainer; `license`/`description`/`keywords` in `Cargo.toml`. | `LICENSE`, `LICENSE-MIT`, `LICENSE-APACHE` |
| Governance docs | **Added** `CONTRIBUTING.md` (codebase ground rules: wire bytes are sacred, no panics on parsed input, no blocking I/O on the UI thread), `SECURITY.md` (scope + an honest "limitations you should not rely on" section), Contributor Covenant 2.1. | repo root |
| CI | **Fixed.** Release workflow moved to `.github/workflows/release.yml` (it was in `docs/`, so tagged releases never ran). New `ci.yml`: build + test on Linux/macOS/Windows, advisory fmt/clippy, and a guard job that fails if the release workflow moves back to `docs/` or the governance files disappear. | `.github/` |
| Issue/PR templates | **Added** bug report (with a security redirect), feature request (mapped to F1–F5), PR checklist. | `.github/ISSUE_TEMPLATE/` |
| SQLite on the UI thread | **Fixed.** Flow writes are queued to a dedicated writer thread with its own connection (WAL + 5 s busy timeout); `flush()` is a barrier used before `save_as` and on quit; failures are counted and surfaced in the autosave message. | `src/db_writer.rs` |
| WebSocket detection | **Fixed.** Requires `Connection: Upgrade` *and* `Upgrade: websocket`; previously any `Connection: upgrade` header was recorded as a WebSocket. | `src/proxy/server.rs` |
| README honesty | **Fixed.** Added a Status table stating which tabs are working vs. scaffold, corrected the plugin ("discovered, not executed") and WebSocket claims, documented decoding. | `README.md` |
| Tests | **Started:** ~30 unit tests covering decoding (fixtures for gzip/zlib/raw-deflate/double-gzip, corrupt/hostile input, header rewriting), ALPN dispatch, hop-by-hop filtering, URI normalisation, WebSocket detection, and the writer's flush/drop durability contract. | `src/**/tests` |

Still open from Phase 0:

- **B4 rename.** The repository is named after a third-party trademark; that decision
  belongs to the owner, not to a patch. Recommendation stands.
- **Perf: bounded flow store with `Arc<HttpFlow>`.** The 60 fps full-vector clone is
  still there; it needs the `FlowStore` refactor that Phase 1 (F5a) also wants, so it
  should land with that rather than be done twice.
- **Test depth.** ~30 tests is a start, not the "first 100" the plan called for. The
  highest-value next targets are `ParsedRequest::parse`, `parse_positions`,
  `jwt_decode`, `ScopeEngine::is_in_scope`, and `decode_blob`.
- **Config file and `--help`.** Still environment-variables-only; belongs with the
  CLI work in F5.

## 10. F4 landed: the choke point is real

The policy layer is in `src/policy/` — `envelope.rs` (parse + compile + validate),
`audit.rs` (hash-chained JSONL), `mod.rs` (the gate). What changed is not the
existence of scope, it is *where* scope is decided.

**One gate, four entry points.** `Policy::authorize(traffic, method, uri)` is called
from `proxy/server.rs` (after the intercept handler, so a rewrite cannot smuggle a
request past the check), `app.rs::send_raw_request` (Repeater), `models/intruder.rs`
(per payload, before the request is spawned) and `scanner/active.rs` (per probe, on
the exact URL and method — a probe that appends `/../../../etc/passwd` is a different
request and is checked as one). The AI assistant's Ollama calls are deliberately
*not* gated: they go to the operator's model endpoint, not to the target.

**Three modes, one of which is failure.** `Unrestricted` (no envelope: allow, audit
nothing, say so in the UI), `Enforced`, and `Broken` (envelope requested but
unloadable: deny everything). There is no "envelope set but ignored" state, which is
the state every other tool's scope UI is effectively in.

**Rate limiting is asymmetric on purpose.** `limits.max_rps` becomes a minimum gap
for *generated* traffic only (Intruder, active checks, Repeater). Delaying the
operator's browser does not reduce risk, it just makes the proxy feel broken, so
proxied traffic is never throttled — and the envelope's ceiling still wins over a
tab's own `rps` setting.

**Audit.** `sha256(prev || "\n" || payload)` per line, genesis is 64 zeros. `open()`
re-verifies the file before appending, so a tampered log refuses to grow. Documented
blind spots, kept in the module header rather than in a changelog: tail truncation is
undetectable without an external anchor, and the chain proves integrity, not
authorship. Signing an envelope bundle is the natural next layer.

**Specified for other tools.** `docs/engagement-envelope.md` writes the file format
and the log format down as a specification (validation rules, decision order, fail-closed
states, canonical JSON, chaining), and `tools/verify_audit_log.py` is an independent
verifier with its own self-test. `tests/fixtures/audit-sample.jsonl` was written by that
verifier and is checked by a Rust test, which is the cheapest available way to find out
whether the format is *specified* or merely *implemented*.

**Still open on F4:** envelope signing/attestation; an `--envelope` flag once the CLI
exists (today it is `PROXIMA_ENVELOPE` or `.proxima/engagement.yaml`); exporting the
audit chain to a bundle for the F1 Evidence Ledger; and a "resume engagement" action,
since a tripped halt currently requires a restart (deliberate for now — the point of a
halt is that it is not one keystroke away from being ignored).
