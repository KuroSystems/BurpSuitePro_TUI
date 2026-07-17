
# Let me create a comprehensive research report document
report = """
# Terminal-Native (TUI) Web Security Testing Proxy — Research & Build Plan

> **Research Report & Architecture Plan** | July 2026  
> **Author**: Senior Security Tooling Architect  
> **Audience**: Final-year security student / bug bounty hunter building clean-room intercepting proxy  
> **Constraint**: Clean-room implementation only. No decompilation or reverse-engineering of proprietary tools.

---

## Deliverable 1: Research Report

### 1.1 Burp Suite Professional Feature Audit (as of 2025/2026)

Burp Suite Professional (PortSwigger) is the de facto standard for web application security testing. The following is a module-by-module enumeration based on publicly documented features from PortSwigger's documentation, release notes, and community knowledge. This represents the **target feature-parity baseline** for this project.

#### Core Proxy Module
| Feature | Description | Notes |
|---------|-------------|-------|
| **Intercept** | Hold/modify requests and responses in real-time | Toggle on/off with hotkey; granular interception rules |
| **HTTP History** | Log all HTTP traffic with search/filter | Supports regex, status code, method, URL filters |
| **WebSocket History** | Log WebSocket messages | Separate tab from HTTP history |
| **Match & Replace** | Regex-based find/replace on traffic | Can target request/response, headers, body |
| **Response Modification** | Modify responses before they reach the browser | Includes auto-decode of gzip/deflate |
| **Invisble Proxying** | Transparent proxy mode | For clients that don't support explicit proxy config |
| **Upstream Proxy Chains** | Route through additional proxies | Supports SOCKS and HTTP upstream proxies |
| **Certificate Handling** | Auto-generated per-host certs from root CA | Supports custom CA import |

#### Repeater
| Feature | Description |
|---------|-------------|
| **Multi-tab** | Unlimited request tabs |
| **Request Editor** | Raw HTTP request editing with syntax highlighting |
| **Response Viewer** | Syntax-highlighted response with search |
| **Response Diff** | Compare two responses side-by-side |
| **Parameter Highlighting** | Auto-highlight URL params, cookies, body params |
| **Send to Repeater** | One-click from Proxy history |

#### Intruder
| Feature | Description |
|---------|-------------|
| **Attack Types** | Sniper, Battering ram, Pitchfork, Cluster bomb |
| **Payload Types** | Simple list, Runtime file, Numbers, Dates, Brute forcer, Bit flipper, etc. |
| **Payload Processing** | Encode, decode, hash, regex extract, prefix/suffix |
| **Grep - Extract** | Extract values from responses using regex |
| **Grep - Match** | Flag responses containing specific strings |
| **Resource Pools** | Throttle concurrent requests to avoid overwhelming target |
| **Results Table** | Sortable results with response time, length, status |

#### Scanner (Crawl & Audit)
| Feature | Description |
|---------|-------------|
| **Crawler** | Navigate application, build site map |
| **Active Scanning** | Send crafted payloads to find vulnerabilities |
| **Passive Scanning** | Analyze traffic without sending additional requests |
| **Issue Taxonomy** | Categorized findings (OWASP-aligned) |
| **Scan Configurations** | Customizable scan rules and insertion points |
| **Live Scanning** | Scan traffic as it passes through proxy |

#### Decoder
| Feature | Description |
|---------|-------------|
| **Encoding/Decoding** | URL, Base64, Hex, HTML entities, Gzip, etc. |
| **Smart Decode** | Auto-detect and decode recursively |
| **Hashing** | MD5, SHA1, SHA256, etc. |

#### Comparer
| Feature | Description |
|---------|-------------|
| **Byte-level Diff** | Visual diff of raw bytes |
| **Word-level Diff** | Word-by-word comparison |
| **Request/Response Compare** | Compare any two messages |

#### Sequencer
| Feature | Description |
|---------|-------------|
| **Token Analysis** | Statistical randomness analysis of session tokens |
| **Sample Collection** | Auto-collect tokens from responses |
| **Entropy Tests** | FIPS 140-2, monobit, runs, etc. |

#### Target / Site Map
| Feature | Description |
|---------|-------------|
| **Site Map Tree** | Hierarchical view of discovered content |
| **Scope Rules** | In-scope/out-of-scope host/path definitions |
| **Content Discovery** | Discover hidden content via wordlists |
| **Issue Aggregation** | Group findings by endpoint |

#### Extender (BApp Store Equivalent)
| Feature | Description |
|---------|-------------|
| **Extension API** | Java/Python/Ruby extension interfaces |
| **Custom Scan Checks** | Add new vulnerability checks |
| **Custom Intruder Payloads** | Programmatic payload generation |
| **Message Editor Tabs** | Add custom UI tabs to request/response viewers |
| **HTTP Handler** | Intercept/modify traffic programmatically |

#### Organizer & Logger
| Feature | Description |
|---------|-------------|
| **Project Notes** | Annotate requests with findings |
| **Color Coding** | Highlight requests by severity/color |
| **Commenting** | Add notes to individual requests |
| **Export** | HAR, XML, CSV export formats |

#### Project Persistence
| Feature | Description |
|---------|-------------|
| **Project Files** | Save all traffic, settings, and findings |
| **Auto-save** | Periodic auto-save to prevent data loss |
| **Configuration Profiles** | Switch between different tool configurations |

**Recent Changes (2025-2026)**: Burp has continued to expand its AI-assisted scanning capabilities, improved HTTP/2 and HTTP/3 support, and added enhanced WebSocket interception. The BApp Store has grown to 200+ extensions. The "Organizer" feature (added ~2024) provides a Kanban-style board for tracking findings.

---

### 1.2 Prior Art Analysis

#### mitmproxy
| Aspect | Detail |
|--------|--------|
| **Language** | Python (core proxy) + Rust (mitmproxy-rs for performance-critical paths) |
| **CA Generation** | Auto-generates 2048-bit RSA root CA on first run; stored in `~/.mitmproxy/mitmproxy-ca.pem`. Uses `cryptography` library for cert generation. |
| **HTTP/2** | Full HTTP/2 support via `h2` library; transparent upgrade from HTTP/1.1 CONNECT |
| **WebSocket** | Intercepted via `wsproto`; messages shown in flow detail view |
| **Request/Response Store** | In-memory by default (flows kept in memory). File-based storage via `-w` flag in mitmdump. Uses msgpack for serialization. |
| **Plugin/Extension Model** | Python addon API with `mitmproxy.addons` module. Scripts loaded via `-s` flag. Full access to flow lifecycle hooks. |
| **TUI** | urwid-based console UI; curses-like. All flows in memory. |
| **Key Lesson** | The addon API is extremely powerful but Python's GIL limits proxy throughput. The Rust core (`mitmproxy-rs`) addresses this for the proxy engine while keeping Python for scripting. |

Source: [mitmproxy docs](https://docs.mitmproxy.org/stable/), [GitHub](https://github.com/mitmproxy/mitmproxy)

#### Hetty
| Aspect | Detail |
|--------|--------|
| **Language** | Go (backend) + React/TypeScript (web UI) |
| **Architecture** | Single binary with embedded web server; GraphQL API between proxy and UI |
| **CA Generation** | Auto-generates CA cert/key pair on first run; stored in `~/.hetty/` |
| **Storage** | SQLite (`hetty.db`) for all request/response data |
| **Features** | Proxy logs, request replay, scope management, intercept (edit/send/receive/cancel) |
| **Key Lesson** | Go backend is fast and single-binary deployable. Web UI is accessible but not terminal-native. SQLite is a solid choice for embedded storage. The project is actively maintained but has a smaller feature set than Burp. |

Source: [Hetty docs](https://hetty.xyz/docs/), [GitHub](https://github.com/dstotijn/hetty)

#### Caido
| Aspect | Detail |
|--------|--------|
| **Language** | Rust (backend) + TypeScript/Vue (web UI) |
| **Architecture** | Rust proxy engine with web-based UI; designed for performance and memory efficiency |
| **Features** | Intercept, replay, scope, automation (Intruder-like), convert (Decoder-like), host anywhere |
| **Key Lesson** | Rust provides excellent performance for the proxy engine. The "fluid layout" grid-based UI is innovative. Being web-based means it works over network but loses the terminal-native feel. |

Source: [Caido overview](https://medium.com/@pedro.correia_8569/what-is-caido-f8b296c1a292)

#### OWASP ZAP
| Aspect | Detail |
|--------|--------|
| **Language** | Java |
| **Architecture** | Desktop GUI + API daemon mode. Headless mode available via `-daemon` flag. |
| **Plugin Model** | Extensive add-on marketplace; extensions in Java, Python (via Jython), JavaScript |
| **Proxy** | Full intercepting proxy with TLS support |
| **Scanner** | Active and passive scanners with extensive rule sets |
| **Key Lesson** | The API-first design (REST API) allows headless automation. The add-on model is mature but Java-based. The proxy engine is solid but the UI is Swing-based and dated. |

---

### 1.3 TUI Framework Comparison

| Criterion | Bubbletea + Bubbles + Lipgloss (Go) | ratatui + crossterm (Rust) | Textual (Python) |
|-----------|-------------------------------------|----------------------------|------------------|
| **Render Performance** | Good for moderate data; `Viewport` has high-performance mode. Table supports virtual scrolling. Known to become sluggish with very large scrollable content. | Excellent. Sub-millisecond rendering, zero-cost abstractions. Pure Rust, no GC pauses. | Good with `FastDataTable` (Apache Arrow backend). Built-in DataTable struggles with >10k rows (62s+ load time vs 0.077s with FastDataTable for 538k rows). |
| **Large Tables (10k+ rows)** | Table widget supports pagination. Virtual scrolling exists but community reports sluggishness with heavy scrolling. | Excellent. Immediate-mode rendering handles large datasets well. `tui-rs` legacy had good table performance; ratatui improved further. | Built-in DataTable: poor. FastDataTable (third-party): excellent with Arrow backend. |
| **Split-pane/Tab Support** | No native tabs. Must build custom with nested models. Layout via Lipgloss flexbox-like constraints. | Built-in layout constraints (Flexbox-like). Tabs must be custom but layout system is mature. | Excellent. Built-in tabs, screens, CSS-like layouts with `tcss`. |
| **Async Event Handling** | Message-based (Elm architecture). Commands run concurrently via goroutines. `tea.Batch()` for parallel commands. | Event-driven with crossterm. Async via tokio integration. | Async built-in. `Worker` class for background tasks. Reactive state model. |
| **Plugin/Theming Ecosystem** | Lipgloss theming is flexible. Bubbles components are reusable. Smaller ecosystem than Textual. | Growing ecosystem. Many real-world apps (k9s, gitui, bottom). Themes via style structs. | Rich ecosystem. CSS-like theming. Many widgets. Active community. |
| **SSH/Terminal Compatibility** | Excellent. Pure terminal output. | Excellent. Pure terminal output. | Good, but requires Python runtime. Heavier dependency chain. |
| **Binary Size** | Small (~5-15MB for typical app) | Small (~5-15MB) | Large (Python + dependencies) |
| **Build Complexity** | Simple `go build`. Single binary. | Cargo build. Single binary. | Requires Python environment. `pyinstaller` for single binary. |

**Verdict for this project**: **Go + Bubbletea** is the recommended choice. It aligns with the operator's existing Go tooling (scopeHound), produces single binaries, and the performance concerns with large tables can be mitigated by:
1. Using the `Viewport` high-performance mode
2. Implementing virtual scrolling with lazy loading from SQLite
3. Keeping only metadata in memory; full request/response bodies in DB
4. Using `tea.Batch()` for concurrent proxy event handling

Textual is ruled out for production proxy engine (Python GIL + performance). Rust/ratatui is excellent but adds friction for embedded scripting (Starlark/Lua integration is harder in Rust than Go).

Sources: [Bubbletea Bubbles Table](https://github.com/charmbracelet/bubbles), [Bubbletea pkg docs](https://pkg.go.dev/github.com/charmbracelet/bubbletea), [Ratatui](https://ratatui.rs/), [Textual FastDataTable benchmarks](https://pypi.org/project/textual-fastdatatable/), [Textual DataTable perf discussion](https://github.com/Textualize/textual/discussions/5953)

---

### 1.4 MITM Engine Research

#### TLS Intercepting Proxy Mechanics

**1. Root CA Generation & Installation**
- Generate a 2048-bit (or 4096-bit) RSA root CA on first run
- Store CA cert and key in `~/.<toolname>/` directory
- Provide a subcommand to install the CA into system trust stores (macOS Keychain, Linux `update-ca-certificates`, Windows certmgr)
- The CA cert must have `CA:TRUE` basic constraint and key usage for cert signing

**2. On-the-Fly Leaf Certificate Generation**
- When a client sends `CONNECT host:443`, the proxy:
  1. Parses the hostname from the CONNECT target
  2. Generates a leaf certificate for that hostname, signed by the root CA
  3. Includes the hostname in Subject Alternative Names (SAN)
  4. Presents the leaf cert to the client during TLS handshake
- SNI (Server Name Indication) is read from the ClientHello to determine the target hostname for transparent proxying
- Certificate caching: Cache generated certs in memory (with TTL) to avoid regenerating for the same host

**3. HTTP/1.1 Keep-Alive Handling**
- After CONNECT, the proxy maintains the TCP connection
- Uses `http.ReadRequest` + `resp.Write()` in a loop until connection close
- Must handle `Connection: keep-alive` and `Connection: close` properly

**4. HTTP/2 Interception**
- HTTP/2 over TLS (h2): Negotiated via ALPN during TLS handshake. The proxy must advertise `h2` in its ALPN protocols when acting as the "server" to the client
- HTTP/2 cleartext (h2c): Upgrade via `Upgrade: h2c` header or prior knowledge
- Go's `golang.org/x/net/http2` can be used for both client and server sides
- The proxy acts as an HTTP/2 server to the client and an HTTP/2 client to the upstream
- Key challenge: HTTP/2 multiplexing means multiple requests share one connection. The proxy must maintain stream state.

**5. WebSocket Upgrade Interception**
- Detect `Upgrade: websocket` header in HTTP/1.1 requests
- After 101 Switching Protocols response, the connection becomes a raw TCP tunnel
- WebSocket frames must be parsed if inspection is needed; otherwise proxy as raw bytes
- `github.com/gorilla/websocket` or `nhooyr/websocket` for frame parsing

**6. HSTS / Certificate Pinning Edge Cases**
- HSTS (HTTP Strict Transport Security): Cannot be bypassed by the proxy. The proxy relies on the CA being trusted.
- Certificate pinning (e.g., HPKP, mobile app pinning): Will cause SSL errors. The proxy cannot intercept pinned connections without additional client-side configuration (Frida, Objection, etc.)
- Apps using `NSURLPinningValidator` (iOS) or `NetworkSecurityConfig` (Android) will reject the proxy's leaf cert

**7. Concurrency Model**
- **Go (recommended)**: One goroutine per client connection. Additional goroutines for upstream connections. Use `sync.Pool` for buffer reuse. Channel-based communication between proxy and UI.
- **Rust (alternative)**: Tokio async runtime with tasks. One task per connection. `tokio::spawn` for handling concurrent streams.
- For thousands of simultaneous connections, Go's goroutines (2KB stack, growable) are more memory-efficient than OS threads and easier to reason about than async/await in complex stateful protocols.

Sources: [Eli Bendersky - Go HTTPS Proxies](https://eli.thegreenplace.net/2022/go-and-proxy-servers-part-2-https-proxies/), [jar3b/mitm Go package](https://pkg.go.dev/github.com/jar3b/mitm)

---

### 1.5 Data Storage & Extensibility Research

#### Storage Layer Options

| Store | Type | Pros | Cons | Best For |
|-------|------|------|------|----------|
| **SQLite** | Embedded SQL | Mature, ACID, full-text search (FTS5), JSON support, widely known | Write contention under heavy concurrent load; single-writer lock | Queryable history, complex filters, relational data |
| **bbolt** (etcd) | Embedded KV (B+tree) | Pure Go, fast reads, MVCC, transactional | No built-in querying; must build indexes manually | Configuration, simple key-value data |
| **Badger** (dgraph) | LSM-tree KV | Extremely fast writes, concurrent, compression | More complex, GC overhead, larger binary | High-throughput write workloads |
| **Pebble** (CockroachDB) | LSM-tree KV | Go-native, RocksDB-compatible, well-maintained | Newer, smaller ecosystem | Alternative to Badger |

**Recommendation**: **SQLite with WAL mode** for the primary request/response store. SQLite's FTS5 extension enables fast full-text search over headers and bodies. WAL mode (Write-Ahead Logging) allows concurrent reads during writes. For configuration and scope rules, bbolt is a fine lightweight option, but SQLite can handle both.

#### Scripting Layer Options

| Language | Embedding in Go | Security | Familiarity | Performance |
|----------|----------------|----------|-------------|-------------|
| **Starlark** | `go.starlark.net/starlark` | Excellent (hermetic, deterministic, no I/O by default) | Python-like syntax | Good (parallel evaluation) |
| **Lua** | `github.com/yuin/gopher-lua` | Good (sandboxable) | Less common in security tooling | Good |
| **WASM** | `wazero` | Excellent (full sandbox) | Any language compiles to WASM | Good |
| **JavaScript (V8/QuickJS)** | `rogchap/v8-go` or `quickjs-go` | Moderate (complex sandboxing) | Very familiar | Moderate |

**Recommendation**: **Starlark** is the best choice for this project:
- Python-like syntax (familiar to security researchers)
- Hermetic execution by default (safe to run untrusted scripts)
- Deterministic evaluation
- Parallel thread support
- Used by Bazel, Buck2 — battle-tested at scale
- Easy to expose domain-specific functions (e.g., `analyze_request()`, `add_issue()`)

For custom Intruder payload generators, Starlark generators can yield values lazily. For custom scan checks, Starlark functions can be called per-request and return findings.

Sources: [Starlark in Go](https://github.com/google/starlark-go), [Starlark language spec](https://github.com/bazelbuild/starlark)

---

## Deliverable 2: Feature-Parity Matrix

| Burp Module | Burp Feature | This Tool's Equivalent | Planned Phase | Notes |
|-------------|-------------|------------------------|---------------|-------|
| **Proxy** | Intercept on/off toggle | `InterceptPane` with global toggle + per-rule toggles | Phase 1 | Hotkey-driven (e.g., `Ctrl+I`) |
| **Proxy** | HTTP History table | `HistoryPane` with sortable/filterable table | Phase 1 | SQLite-backed with FTS5 search |
| **Proxy** | WebSocket History | `WebSocketPane` | Phase 3 | Frame-level inspection |
| **Proxy** | Match & Replace rules | `MatchReplaceEngine` with regex rules | Phase 2 | Pre-request and post-response hooks |
| **Proxy** | Response modification | `ResponseModifier` middleware | Phase 2 | Auto-decode gzip/deflate |
| **Proxy** | Invisible proxying | Transparent proxy mode | Phase 3 | iptables/nftables redirect support |
| **Proxy** | Upstream proxy chains | `UpstreamProxyConfig` | Phase 3 | SOCKS4/5, HTTP upstream |
| **Repeater** | Multi-tab request editor | `RepeaterPane` with tabbed interface | Phase 1 | Each tab = one request/response pair |
| **Repeater** | Response diff view | `DiffViewer` component | Phase 2 | Byte-level and word-level diff |
| **Repeater** | Parameter highlighting | `SyntaxHighlighter` with param detection | Phase 2 | URL params, cookies, form data |
| **Intruder** | Sniper attack | `SniperAttack` (single payload, single position) | Phase 2 | Sequential position targeting |
| **Intruder** | Battering ram | `BatteringRamAttack` (single payload, all positions) | Phase 2 | Same payload to all positions |
| **Intruder** | Pitchfork | `PitchforkAttack` (multiple payloads, parallel) | Phase 2 | One payload set per position |
| **Intruder** | Cluster bomb | `ClusterBombAttack` (cartesian product) | Phase 2 | All combinations |
| **Intruder** | Payload types (simple list, numbers, etc.) | `PayloadGenerator` interface + built-ins | Phase 2 | Extensible via Starlark |
| **Intruder** | Grep - Extract | `ResponseExtractor` regex engine | Phase 2 | Extract values into results table |
| **Intruder** | Grep - Match | `ResponseMatcher` string/regex matcher | Phase 2 | Flag responses in results |
| **Intruder** | Resource pools / throttling | `RateLimiter` with configurable concurrency | Phase 2 | Token bucket algorithm |
| **Scanner** | Crawler | `Spider` module | Phase 3 | Link extraction, form discovery |
| **Scanner** | Active scanning | `ActiveScanner` with check plugins | Phase 3 | Reflected XSS, SQLi probes |
| **Scanner** | Passive scanning | `PassiveScanner` analyzing proxy traffic | Phase 3 | Security headers, info disclosure |
| **Scanner** | Issue taxonomy | `IssueRegistry` with severity levels | Phase 3 | Align with CWE/OWASP |
| **Decoder** | Encode/decode (URL, Base64, Hex, HTML, Gzip) | `DecoderPane` with recursive decode | Phase 2 | Smart auto-detect mode |
| **Decoder** | Hashing | `HashTool` (MD5, SHA family) | Phase 2 | |
| **Comparer** | Byte-level diff | `ByteDiff` (myers diff or similar) | Phase 2 | Side-by-side view |
| **Comparer** | Word-level diff | `WordDiff` | Phase 2 | |
| **Sequencer** | Token randomness analysis | `SequencerPane` | Phase 3 | Entropy, chi-square, FIPS tests |
| **Target** | Site map tree | `SiteMapPane` | Phase 3 | Tree view of discovered content |
| **Target** | Scope rules | `ScopeManager` with host/path rules | Phase 1 | Regex and wildcard support |
| **Target** | Content discovery | `ContentDiscovery` wordlist brute | Phase 3 | Dirbusting equivalent |
| **Extender** | Extension API | `StarlarkEngine` with hooks | Phase 3 | `on_request`, `on_response`, `on_scan` |
| **Extender** | Custom scan checks | Starlark `check()` functions | Phase 3 | Return `Issue` objects |
| **Extender** | Custom Intruder payloads | Starlark generator functions | Phase 3 | Yield values lazily |
| **Organizer** | Kanban board for findings | `OrganizerPane` | Phase 3 | Simple todo-style board |
| **Logger** | Traffic logging | Built into `HistoryPane` | Phase 1 | All traffic auto-logged to SQLite |
| **Project** | Save/load project files | `ProjectManager` (SQLite DB file) | Phase 3 | Single `.db` file per project |
| **Project** | HAR export | `HARExporter` | Phase 3 | Standard HAR format |
| **Project** | JSON export | `JSONExporter` | Phase 3 | Custom JSON schema |

---

## Deliverable 3: System Architecture

### 3.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              TUI Layer                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │  Sidebar    │  │  Main Pane  │  │  Detail     │  │  Status/Help    │  │
│  │  (Nav)      │  │  (Table/   │  │  (Req/Res   │  │  (Key hints)    │  │
│  │             │  │   Editor)   │  │   Split)    │  │                 │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────┘  │
│                              Bubbletea (Go)                              │
├─────────────────────────────────────────────────────────────────────────┤
│                              Event Bus                                   │
│                    ┌─────────────────────────┐                            │
│                    │  Channel-based Pub/Sub  │                            │
│                    │  (proxy -> UI messages)   │                            │
│                    └─────────────────────────┘                            │
├─────────────────────────────────────────────────────────────────────────┤
│                           Proxy Engine                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐  │
│  │  MITM TLS   │  │  HTTP/1.1   │  │  HTTP/2     │  │  WebSocket      │  │
│  │  Listener   │  │  Handler    │  │  Handler    │  │  Handler        │  │
│  │  (cert gen) │  │  (CONNECT)  │  │  (ALPN h2)  │  │  (Upgrade)      │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────┘  │
│                              Go net/http + crypto/tls                     │
├─────────────────────────────────────────────────────────────────────────┤
│                           Storage Layer                                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  SQLite (WAL mode)                                              │   │
│  │  - requests table (metadata)                                    │   │
│  │  - request_bodies table (blob)                                  │   │
│  │  - response_bodies table (blob)                                 │   │
│  │  - scope_rules table                                            │   │
│  │  - issues table                                                 │   │
│  │  - notes table                                                  │   │
│  │  - FTS5 virtual tables for full-text search                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                           mattn/go-sqlite3 or modernc/sqlite             │
├─────────────────────────────────────────────────────────────────────────┤
│                        Scripting Engine                                  │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  Starlark Interpreter (go.starlark.net)                       │   │
│  │  - Custom builtins for request/response manipulation            │   │
│  │  - Hook registry: on_request, on_response, on_scan                │   │
│  │  - Sandboxed execution                                          │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Proxy Engine Details

**Language/Library**: Go with `net/http`, `crypto/tls`, `golang.org/x/net/http2`
**Concurrency Model**: Goroutines

```
Client Connection → Goroutine spawned per TCP connection
  ├── TLS Handshake (if HTTPS)
  │     ├── SNI read → Cert cache lookup or generate leaf cert
  │     └── Present leaf cert to client
  ├── HTTP Request Read Loop
  │     ├── Parse request
  │     ├── Apply match/replace rules
  │     ├── Check intercept toggle → If ON, block and send to UI via event bus
  │     ├── Forward to upstream (new goroutine or connection pool)
  │     ├── Receive response
  │     ├── Apply response match/replace
  │     ├── Store to SQLite (async via channel)
  │     └── Send to client
  └── Connection close → Goroutine exits
```

**Key Design Decisions**:
- **Connection hijacking**: Use `http.Hijacker` to take over TCP connection for CONNECT tunneling
- **Certificate cache**: In-memory `map[string]*tls.Certificate` with RWMutex; TTL-based eviction
- **Upstream connection pooling**: Reuse connections to the same upstream host to avoid TLS handshake overhead
- **Body streaming**: For large responses, stream through proxy without fully buffering in memory
- **Intercept queue**: When intercept is ON, requests are parked in a buffered channel; UI pulls from this queue

### 3.3 TUI Layer Component Breakdown

**Layout Model**: k9s/lazygit-style — sidebar navigation, main content pane, detail pane, status bar

```
┌────────────────────────────────────────────────────────────┐
│  [1] Sidebar        │  [2] Main Pane      │  [3] Detail     │
│  ─────────          │  ─────────────      │  ───────────    │
│  🌐 Proxy           │  History Table      │ Request/Response│
│  🔁 Repeater        │  (sortable,         │ Split View      │
│  🎯 Intruder        │   filterable)       │                 │
│  🗺️  Target         │                     │ Headers │ Body  │
│  🔧 Decoder         │                     │ ────────┼────── │
│  📊 Comparer        │                     │         │       │
│  🎲 Sequencer       │                     │         │       │
│  ⚙️  Settings       │                     │         │       │
│                     │                     │         │       │
├────────────────────────────────────────────────────────────┤
│  [4] Command Palette (fuzzy find, triggered by `:` or `/`) │
│  [5] Status Bar — intercept toggle, connection count, help   │
└────────────────────────────────────────────────────────────┘
```

**Component Hierarchy (Bubbletea)**:
```
App (tea.Model)
├── Sidebar (tea.Model) — nav items, key handling
├── MainPane (tea.Model)
│   ├── HistoryTable (bubbles.Table) — proxy traffic
│   ├── RepeaterTabs (custom) — tabbed request editors
│   ├── IntruderConfig (custom) — attack setup
│   ├── DecoderPane (custom) — encode/decode tools
│   ├── ComparerPane (custom) — diff viewer
│   └── ...
├── DetailPane (tea.Model)
│   ├── RequestViewer (Viewport + syntax highlight)
│   └── ResponseViewer (Viewport + syntax highlight)
├── ModalLayer (tea.Model) — intercept decision, confirm dialogs
└── StatusBar (lipgloss render) — static render, not interactive
```

**Keyboard-First UX**:
- `Tab` / `Shift+Tab` — cycle focus between panes
- `j/k` or `↑/↓` — navigate within lists/tables
- `Enter` — select/open
- `Ctrl+I` — toggle intercept
- `Ctrl+R` — send to repeater
- `Ctrl+Shift+R` — send to repeater (in new tab)
- `Ctrl+F` — fuzzy find in history
- `:` — command palette
- `?` — context-sensitive help
- `q` / `Ctrl+C` — quit (with confirm if unsaved)

### 3.4 Proxy-to-UI IPC Design

**Problem**: Proxy goroutines generate events (new request, new response, intercept hold) that must reach the TUI without blocking either side.

**Solution**: Channel-based pub/sub with bounded buffers

```go
// Event types
type ProxyEvent interface {
    Type() string
}

type RequestEvent struct {
    FlowID      string
    Method      string
    URL         string
    Headers     http.Header
    BodyPreview []byte
    Timestamp   time.Time
}

type ResponseEvent struct {
    FlowID     string
    StatusCode int
    Headers    http.Header
    Size       int64
    Duration   time.Duration
}

type InterceptEvent struct {
    FlowID  string
    Request *http.Request
    // Response channel for UI to send modified request or drop decision
    DecisionChan chan InterceptDecision
}

// Event bus
type EventBus struct {
    subscribers []chan ProxyEvent
    mu          sync.RWMutex
}

func (eb *EventBus) Subscribe() chan ProxyEvent {
    ch := make(chan ProxyEvent, 100) // bounded buffer
    eb.mu.Lock()
    eb.subscribers = append(eb.subscribers, ch)
    eb.mu.Unlock()
    return ch
}

func (eb *EventBus) Publish(event ProxyEvent) {
    eb.mu.RLock()
    defer eb.mu.RUnlock()
    for _, ch := range eb.subscribers {
        select {
        case ch <- event:
        default:
            // Buffer full — drop event or log warning
            // For intercept events, must not drop — use unbuffered or blocking
        }
    }
}
```

**Thread Safety**:
- All proxy events are immutable (copy-on-write for headers/body previews)
- The TUI's `Update()` method receives events via `tea.Cmd` that polls the event channel
- SQLite writes happen in a dedicated goroutine with a write queue to avoid WAL contention

### 3.5 Storage Layer Schema

```sql
-- Core flow table (lightweight metadata)
CREATE TABLE flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid            TEXT UNIQUE NOT NULL,        -- UUIDv4 for cross-reference
    method          TEXT NOT NULL,
    scheme          TEXT NOT NULL,               -- http or https
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    path            TEXT NOT NULL,
    query           TEXT,
    http_version    TEXT,                        -- HTTP/1.1, HTTP/2
    status_code     INTEGER,
    response_reason TEXT,
    request_size    INTEGER,
    response_size   INTEGER,
    duration_ms     INTEGER,                     -- round-trip time
    timestamp       INTEGER NOT NULL,            -- unix epoch ms
    is_websocket    INTEGER DEFAULT 0,
    is_intercepted  INTEGER DEFAULT 0,           -- was this flow intercepted?
    is_in_scope     INTEGER DEFAULT 0,
    color           TEXT,                        -- highlight color
    comment         TEXT,
    project_id      TEXT DEFAULT 'default'
);

-- Request bodies stored separately (can be large)
CREATE TABLE request_bodies (
    flow_id     INTEGER PRIMARY KEY REFERENCES flows(id) ON DELETE CASCADE,
    body        BLOB,
    body_hash   TEXT,                          -- sha256 for dedup
    encoding    TEXT                           -- gzip, deflate, br, etc.
);

-- Response bodies
CREATE TABLE response_bodies (
    flow_id     INTEGER PRIMARY KEY REFERENCES flows(id) ON DELETE CASCADE,
    body        BLOB,
    body_hash   TEXT,
    encoding    TEXT
);

-- Headers (normalized, searchable)
CREATE TABLE headers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id     INTEGER REFERENCES flows(id) ON DELETE CASCADE,
    is_request  INTEGER NOT NULL,              -- 1 = request, 0 = response
    name        TEXT NOT NULL,
    value       TEXT NOT NULL
);

-- Scope rules
CREATE TABLE scope_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  TEXT NOT NULL,
    rule_type   TEXT NOT NULL,                 -- 'include' or 'exclude'
    protocol    TEXT,                            -- http, https, any
    host        TEXT,                            -- exact, wildcard, regex
    port        INTEGER,
    path        TEXT,                            -- path prefix or regex
    is_regex    INTEGER DEFAULT 0,
    priority    INTEGER DEFAULT 0              -- higher = evaluated first
);

-- Issues / findings
CREATE TABLE issues (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id     INTEGER REFERENCES flows(id),
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,                 -- critical, high, medium, low, info
    confidence  TEXT NOT NULL,                 -- certain, firm, tentative
    description TEXT,
    remediation TEXT,
    cwe_id      INTEGER,
    timestamp   INTEGER NOT NULL
);

-- Notes / annotations
CREATE TABLE notes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id     INTEGER REFERENCES flows(id) ON DELETE CASCADE,
    note_text   TEXT NOT NULL,
    timestamp   INTEGER NOT NULL
);

-- Full-text search virtual tables
CREATE VIRTUAL TABLE flows_fts USING fts5(
    host, path, method, content='flows', content_rowid='id'
);

CREATE VIRTUAL TABLE headers_fts USING fts5(
    name, value, content='headers', content_rowid='id'
);

-- Indexes for performance
CREATE INDEX idx_flows_timestamp ON flows(timestamp DESC);
CREATE INDEX idx_flows_host ON flows(host);
CREATE INDEX idx_flows_status ON flows(status_code);
CREATE INDEX idx_flows_method ON flows(method);
CREATE INDEX idx_flows_scope ON flows(is_in_scope);
CREATE INDEX idx_headers_flow ON headers(flow_id);
CREATE INDEX idx_issues_severity ON issues(severity);
```

**Performance Considerations**:
- FTS5 for sub-second full-text search across 100k+ flows
- Body content stored in separate tables to keep `flows` table small for fast listing
- `body_hash` enables body deduplication (common for static assets)
- WAL mode + `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`
- Periodic `VACUUM` or auto-vacuum to reclaim space

---

## Deliverable 4: Phased Build Roadmap

### Phase 1: MVP — Intercept & View (Weeks 1-6)
**Goal**: A working intercepting proxy with history view and repeater. Single-binary, runs in terminal.

| Week | Tasks | Effort |
|------|-------|--------|
| 1 | Project scaffold, CA generation, basic HTTP proxy (no TLS yet) | 3 days |
| 2 | TLS MITM with on-the-fly cert generation, SNI handling | 4 days |
| 3 | Bubbletea TUI scaffold: sidebar, main pane, status bar | 3 days |
| 4 | History table with SQLite storage, basic filtering | 4 days |
| 5 | Intercept toggle: hold/modify/forward/drop requests | 4 days |
| 6 | Repeater: edit/resend, response viewer with syntax highlight | 4 days |
| **Buffer** | Bug fixes, polish, documentation | 5 days |
| **Total** | | **~6 weeks** |

### Phase 2: Attack Surface (Weeks 7-14)
**Goal**: Intruder-equivalent, Decoder, Comparer, Match & Replace.

| Week | Tasks | Effort |
|------|-------|--------|
| 7-8 | Intruder engine: Sniper, Battering Ram, Pitchfork, Cluster Bomb | 8 days |
| 9 | Payload generators (simple list, numbers, runtime file) + response grep | 5 days |
| 10 | Decoder pane: URL, Base64, Hex, HTML entities, Gzip, recursive | 4 days |
| 11 | Comparer: byte-level and word-level diff of two messages | 4 days |
| 12 | Match & Replace rules engine with regex support | 4 days |
| 13 | Scope management UI + rules engine | 3 days |
| 14 | Polish, keyboard shortcuts refinement, settings persistence | 4 days |
| **Buffer** | Testing on real targets, performance tuning | 5 days |
| **Total** | | **~8 weeks** |

### Phase 3: Intelligence (Weeks 15-24)
**Goal**: Scanner, Sequencer, scripting, project persistence, export.

| Week | Tasks | Effort |
|------|-------|--------|
| 15-16 | Passive scanner: security headers, verbose errors, reflected params, outdated JS | 8 days |
| 17 | Basic active scanner: reflected XSS, SQLi error-based probes | 5 days |
| 18 | Sequencer: token collection, entropy analysis, statistical tests | 5 days |
| 19-20 | Starlark scripting engine: hook system, custom builtins | 8 days |
| 21 | Project save/load: single `.db` file with all data | 3 days |
| 22 | HAR export, JSON export | 3 days |
| 23 | Site map / target tree view | 3 days |
| 24 | Content discovery (dirbusting) | 3 days |
| **Buffer** | Integration testing, documentation, release prep | 5 days |
| **Total** | | **~10 weeks** |

### Effort Summary
| Phase | Duration | Core Features |
|-------|----------|---------------|
| Phase 1 | ~6 weeks | Proxy, History, Repeater, Scope |
| Phase 2 | ~8 weeks | Intruder, Decoder, Comparer, Match & Replace |
| Phase 3 | ~10 weeks | Scanner, Sequencer, Scripting, Export |
| **Total** | **~24 weeks** (~6 months) | Full Burp Pro feature parity |

---

## Deliverable 5: Phase 1, Week 1 Task List

### Day 1: Project Scaffold
- [ ] Initialize Go module: `go mod init github.com/<user>/proxterm`
- [ ] Set up project structure:
  ```
  proxterm/
  ├── cmd/proxterm/          # main entry point
  ├── internal/
  │   ├── proxy/             # MITM proxy engine
  │   ├── ca/                # Certificate authority management
  │   ├── tui/               # Bubbletea TUI components
  │   ├── storage/           # SQLite layer
  │   ├── scope/             # Scope rule engine
  │   └── config/            # Configuration management
  ├── pkg/
  │   └── types/             # Shared types/interfaces
  ├── go.mod
  └── README.md
  ```
- [ ] Add dependencies:
    - `github.com/charmbracelet/bubbletea`
    - `github.com/charmbracelet/bubbles`
    - `github.com/charmbracelet/lipgloss`
    - `github.com/mattn/go-sqlite3` (or `modernc.org/sqlite` for pure Go)
    - `golang.org/x/net/http2`
- [ ] Implement basic CLI with `cobra` or stdlib `flag`: `--port`, `--listen-host`, `--ca-path`

### Day 2: CA Generation & Management
- [ ] Implement `internal/ca/ca.go`:
  - `GenerateCA(name string) (certPEM, keyPEM []byte, err error)`
  - Generate 2048-bit RSA key pair
  - Self-signed root CA with 10-year validity
  - Save to `~/.proxterm/ca-cert.pem` and `~/.proxterm/ca-key.pem`
- [ ] Implement `internal/ca/install.go`:
  - `InstallCA()` — platform-specific CA installation
  - macOS: `security add-trusted-cert`
  - Linux: copy to `/usr/local/share/ca-certificates/` + `update-ca-certificates`
  - Windows: `certmgr` or PowerShell
- [ ] CLI subcommand: `proxterm cert install`

### Day 3: Basic HTTP Forward Proxy (No TLS)
- [ ] Implement `internal/proxy/server.go`:
  - `http.Server` listening on configurable port (default 8080)
  - Handle `GET`, `POST`, etc. directly (non-CONNECT)
  - Forward requests to upstream using `http.Transport`
  - Log requests to stdout (placeholder for storage)
- [ ] Test with curl: `curl -x http://localhost:8080 http://httpbin.org/get`

### Day 4: CONNECT Tunneling + TLS MITM
- [ ] Implement CONNECT handler:
  - Hijack client connection
  - Parse hostname from `CONNECT host:port`
  - Generate leaf certificate for hostname (signed by CA)
  - Perform TLS handshake with client using leaf cert
  - Establish separate TLS connection to upstream
  - Bidirectional copy (or HTTP request parsing loop)
- [ ] Implement certificate cache:
  - `map[string]*tls.Certificate` with `sync.RWMutex`
  - Cache hit → reuse cert; miss → generate and cache
- [ ] Test with curl: `curl -x http://localhost:8080 https://httpbin.org/get --cacert ~/.proxterm/ca-cert.pem`

### Day 5: HTTP/2 Support
- [ ] Add `golang.org/x/net/http2` support:
  - Configure `tls.Config` with `NextProtos: []string{"h2", "http/1.1"}`
  - Use `http2.ConfigureServer` for the TLS server side (client-facing)
  - Use `http2.Transport` for upstream connections
- [ ] Test with browsers (Chrome, Firefox) configured to use proxy
- [ ] Verify ALPN negotiation in Wireshark or proxy logs

### Day 6: TUI Scaffold
- [ ] Implement basic Bubbletea app:
  - `App` model with `Init()`, `Update()`, `View()`
  - Sidebar with placeholder nav items
  - Main pane showing "Proxy starting..."
  - Status bar showing proxy port and connection count
- [ ] Integrate proxy startup into TUI lifecycle:
  - Proxy runs in background goroutine
  - Proxy events sent to TUI via channel
- [ ] Keyboard handling: `q` to quit, `Ctrl+C` to quit

### Day 7: Integration & Polish
- [ ] Wire proxy events to TUI:
  - New request → update a simple list in main pane
  - Show method, URL, status code (if available)
  - Update connection count in status bar
- [ ] Add basic intercept toggle (placeholder — just logs for now)
- [ ] Write README with build instructions
- [ ] Tag as `v0.0.1-alpha`

### Week 1 Deliverable
A single binary that:
1. Generates a root CA on first run
2. Provides a `cert install` subcommand
3. Runs an HTTP/HTTPS intercepting proxy on a configurable port
4. Displays live traffic in a terminal UI
5. Can be tested with curl and browsers

---

## Appendix: Key Libraries & References

### Go Libraries
| Purpose | Library | URL |
|---------|---------|-----|
| TUI Framework | Bubbletea | github.com/charmbracelet/bubbletea |
| TUI Components | Bubbles | github.com/charmbracelet/bubbles |
| TUI Styling | Lipgloss | github.com/charmbracelet/lipgloss |
| SQLite (CGO) | mattn/go-sqlite3 | github.com/mattn/go-sqlite3 |
| SQLite (Pure Go) | modernc.org/sqlite | modernc.org/sqlite |
| HTTP/2 | x/net/http2 | golang.org/x/net/http2 |
| WebSocket | gorilla/websocket | github.com/gorilla/websocket |
| Starlark | go.starlark.net | github.com/google/starlark-go |
| Diff | sergi/go-diff | github.com/sergi/go-diff |
| Syntax Highlight | alecthomas/chroma | github.com/alecthomas/chroma |

### Reference Implementations
| Tool | Language | Key Takeaway |
|------|----------|--------------|
| mitmproxy | Python + Rust | Addon API design; Rust core for performance |
| Hetty | Go + React | Go proxy + SQLite storage; single binary |
| Caido | Rust + TS/Vue | Rust performance; fluid grid UI |
| ZAP | Java | Extensive plugin model; API-first design |

### Prior Art Sources
- mitmproxy: https://docs.mitmproxy.org/stable/ | https://github.com/mitmproxy/mitmproxy
- Hetty: https://hetty.xyz/docs/ | https://github.com/dstotijn/hetty
- Caido: https://caido.io/
- OWASP ZAP: https://www.zaproxy.org/
- Burp Suite: https://portswigger.net/burp/documentation

---

*Report compiled July 2026. All feature descriptions of Burp Suite Professional are based on publicly available documentation and do not constitute reverse-engineering or decompilation of proprietary software.*
"""

