# Security Policy

## What this tool is

Proxima is an intercepting proxy: it terminates TLS with a locally generated CA,
records HTTP traffic, and can replay or mutate requests. That makes two classes of
issue especially serious here:

1. **Vulnerabilities in Proxima itself** — memory safety issues, request smuggling
   through the proxy, path traversal in project files, execution of untrusted WASM,
   or credential leakage from the AI context builder.
2. **Proxy-induced self-harm** — a bug that causes Proxima to send traffic to an
   out-of-scope host, exceed an operator's rate limit, or persist secrets that were
   meant to stay ephemeral.

## Supported versions

The project is pre-1.0. Security fixes land on `main` and in the latest release only;
there are no backports to older tags yet.

| Version | Supported |
|---|---|
| `main` + latest release | ✅ |
| older tags | ❌ |

## Reporting a vulnerability

**Do not open a public issue for a vulnerability.**

Use GitHub's private reporting flow: *Security* tab → *Report a vulnerability*
(GitHub Security Advisories). This creates a private draft where details can be
discussed before disclosure.

Please include, where applicable:

- the Proxima version/commit and OS,
- the configuration involved (`PROXIMA_*` variables that matter),
- a minimal reproduction (a capture file, a request, or a short script),
- the impact you believe it has.

### What to expect

- acknowledgement within 7 days,
- an assessment and a remediation plan within 30 days,
- credit in the advisory and release notes unless you prefer otherwise,
- coordinated disclosure: please give us 90 days before publishing details, or
  less if a fix ships sooner.

## In scope

- The proxy engine (`src/proxy/`), including CONNECT handling, per-domain CA
  issuance, HTTP/1.1 and HTTP/2 dispatch, and header forwarding.
- Content decoding (`src/net/decode.rs`) — decompression bombs, decoder panics,
  and incorrect header rewriting after decoding.
- Project persistence (`src/db.rs`) — malformed databases, unsafe deserialization.
- Plugin loading (`src/plugins/`) — the moment a WASM runtime is wired in, sandbox
  escapes and capability bypasses become in scope.
- The AI context builder (`ai_context_from_flow` and redaction helpers) — a path
  that sends a secret to a model provider that the operator asked to redact.
- Scanner rule loading (`resources/passive/`) — a rule file that causes code
  execution or unbounded work.

## Out of scope

- The fact that installing the CA certificate allows interception — that is the
  documented purpose of the tool.
- Findings produced by the passive/active scanner against *your* targets.
- Traffic you send deliberately through a proxy you started.
- Vulnerabilities that require an already-compromised host or a modified binary.
- Missing hardening that depends on terminal/OS configuration.

## Known limitations you should not rely on

Documented honestly, because they affect how much protection the tool provides:

- **AI redaction is best-effort, not a security boundary.** It is pattern based and
  will miss secrets it does not recognise. Point the AI tab at a local model you
  trust, and read `docs/feature-strategy.md` for the planned hardening.
- **Scope rules are advisory in this version.** The proxy forwards whatever it is
  asked to forward. Enforced authorization envelopes are designed but not shipped.
- **Plugins are not yet executed.** Until a sandboxed runtime is wired in, a plugin
  directory is a list, not an execution surface.

## Safe testing advice

Only intercept, scan, or actively probe systems you own or have explicit written
authorization to test. Keep scope rules narrow, respect rate limits, and stop
immediately if a target behaves unexpectedly. A proxy is an amplifier: a mistake in
your rate limit is not absorbed by the tool.
