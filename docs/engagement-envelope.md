# The engagement envelope, as a specification

This is the part of Proxima that is meant to outlive Proxima. If another proxy
honours the same file, the file becomes the portable artefact — the thing a client,
an auditor or a bug-bounty program asks for instead of a screenshot of a scope tab.

Status: implemented in `src/policy/` and enforced by this tool, but **not yet
signed**. Treat v1alpha1 as unstable until the signature layer lands.

Two artefacts are specified: the **envelope** (what is allowed) and the
**audit log** (what was done, in a form that can be checked afterwards).

---

## 1. Envelope

A single YAML (or JSON — YAML is a superset, and both parse to the same model)
document.

```yaml
apiVersion: proxima.dev/v1alpha1
kind: Engagement
metadata:
  id: ACME-2026-014
  operator: priya@example.test
  authorization:
    reference: "SOW-2026-014 §3.2"
    date: "2026-10-01"
scope:
  include: ['^https://staging\.acme\.test/']
  exclude: ['/admin']
limits:
  window: { from: 2026-10-01T00:00:00+05:30, to: 2026-10-08T00:00:00+05:30 }
  max_rps: 10
  max_requests_total: 20000
  methods: [GET, POST, PUT, PATCH, OPTIONS, HEAD]
  deny_methods: [DELETE]
  halt_on: { status_429: 25, status_5xx_rate: 0.25, min_samples: 50 }
audit:
  enabled: true
  log: .proxima/audit-ACME-2026-014.jsonl
```

### 1.1 Field reference

| Field | Required | Meaning |
|---|---|---|
| `apiVersion` | yes | Must equal `proxima.dev/v1alpha1`. |
| `kind` | yes | Must equal `Engagement`. |
| `metadata.id` | yes | Non-empty engagement identifier; copied into every audit entry. |
| `metadata.operator` | no | Who is testing. |
| `metadata.authorization.{reference,date}` | no | Free-text pointer to the paperwork. Not verified by the tool — it is there so a reader can find it. |
| `scope.include[]` | yes, ≥1 | Regular expressions matched against the **full request URI** (scheme, host, path, query). |
| `scope.exclude[]` | no | Regular expressions; a match denies, whatever `include` said. |
| `limits.window.{from,to}` | no | RFC 3339 timestamps with offset. Outside the window everything is denied. Either bound may be omitted. |
| `limits.max_rps` | no | Integer > 0. Converted to a minimum gap between *generated* requests. |
| `limits.max_requests_total` | no | Integer. Ceiling over the engagement, counted after the audit log opens. |
| `limits.methods[]` | no | Allow-list. Absent means "any method not denied". Present but empty is an error. |
| `limits.deny_methods[]` | no | Deny-list. **Beats** `methods`. |
| `limits.halt_on.status_429` | no | Halt after this many `429` responses. |
| `limits.halt_on.status_5xx_rate` | no | Halt when `5xx` responses exceed this fraction of observations. |
| `limits.halt_on.min_samples` | no | Observations required before the rate is evaluated (default 20). |
| `audit.enabled` | no | Defaults to `true` when an envelope is loaded. |
| `audit.log` | no | Path to the JSONL log; defaults to `.proxima/audit.log`. |

### 1.2 Validation rules (all of them are errors, not warnings)

Unknown fields are rejected at every level. A safety control that silently ignores
`deny_methods:` written as `denymethods:` is decoration, so a typo must fail loudly.

1. `apiVersion` and `kind` must match exactly.
2. `metadata.id` must not be blank.
3. `scope.include` must contain at least one pattern. An empty list is **not**
   "everything".
4. Every pattern must compile as a regular expression; the error names the field and
   the pattern.
5. `limits.max_rps`, when present, must be > 0.
6. If both `window.from` and `window.to` are present, `from` must be strictly before
   `to`.
7. `limits.methods`, when present, must not be empty.
8. An existing `audit.log` must verify (§2.3) before it can be appended to.

### 1.3 Decision procedure

For a request `(method, uri)`, in this order:

1. If the engagement is halted → deny `halted`.
2. If the window is configured and now is outside it → deny `outside_window`.
3. If `deny_methods` contains the method (case-insensitive) → deny `method_denied`.
4. If `methods` is present and does not contain the method → deny `method_not_allowed`.
5. If an `exclude` pattern matches the URI → deny `excluded`.
6. If no `include` pattern matches the URI → deny `out_of_scope`.
7. If the request count has reached `max_requests_total` → deny `budget_exhausted`.
8. Otherwise allow, and count the request.

Denials never consume the budget. The order matters for the reason code, not for
safety: every denial is a denial.

### 1.4 Fail-closed states

An implementation has exactly three states, and must be able to say which one it is
in at any moment:

| State | Meaning | Behaviour |
|---|---|---|
| Unrestricted | No envelope was requested. | Allow everything, audit nothing, **say so in the UI**. |
| Enforced | An envelope loaded and validated. | §1.3 on every outbound request. |
| Broken | An envelope was requested but could not be loaded. | Deny everything. |

There is deliberately no fourth state where an envelope exists but is ignored.

### 1.5 Rate limiting

`max_rps` is a floor on spacing between *generated* requests (fuzzing, active
checks, scripted replays). Proxied interactive traffic is not throttled: slowing a
human's browser reduces no risk and makes the proxy feel broken. A tool's own
per-tab rate setting may not exceed the envelope's ceiling.

---

## 2. Audit log

Append-only JSON Lines. One object per decision, including denials and halts.

```json
{"action":"deny","envelope":"ACME-2026-014","hash":"1d43…3097","method":"DELETE","reason":"method DELETE is denied by the engagement envelope","seq":2,"traffic":"generated","ts":"2026-10-01T09:00:01.200000000+00:00","uri":"https://staging.example.test/admin/wipe"}
```

### 2.1 Fields

| Field | Type | Meaning |
|---|---|---|
| `seq` | integer, 1-based | Position in the chain. Must be exactly `previous + 1`. |
| `ts` | RFC 3339 string | When the decision was made (UTC). |
| `action` | `allow` \| `deny` \| `halt` | What was decided. |
| `traffic` | `proxied` \| `generated` \| `system` | Where the request came from. `halt` entries use `system`. |
| `method` | string | Request method, or `-` for `halt`. |
| `uri` | string | Full request URI, or `-` for `halt`. |
| `reason` | string \| null | Human-readable reason for `deny`/`halt`; `null` for `allow`. |
| `envelope` | string \| null | `metadata.id` of the active envelope. |
| `hash` | 64 lowercase hex chars | See §2.2. |

### 2.2 Canonicalisation and chaining

`hash = lowercase_hex(sha256(prev_hash || 0x0A || canonical(entry_without_hash)))`

- `prev_hash` is the previous line's `hash`; the first line chains from
  `"0000…0000"` (64 zeros).
- `canonical(…)` is the entry serialised as JSON with **keys sorted**, **no
  insignificant whitespace** (`{"a":1,"b":2}`, not `{ "a": 1, "b": 2 }`), UTF-8
  without ASCII-escaping of non-ASCII characters, and `null` for absent values.
  This is exactly what `serde_json` produces for a `Value::Object`.
- The `hash` field covers every other field, so editing any of them — including
  `ts` — breaks the chain at that line.

### 2.3 Verification

Read the file line by line, recompute every hash from the first, and reject the file
if any of these is false:

1. every line parses as a JSON object,
2. `seq` is `previous_seq + 1`,
3. the recomputed hash equals the recorded `hash`.

`open()` on an existing log runs this check and refuses to append when it fails:
extending a chain you cannot verify launders tampered history into a valid-looking
one.

Two implementations of the checker exist on purpose:

- Rust: `policy::audit::verify(path)`
- Python, no dependencies: `python3 tools/verify_audit_log.py <log>`

`tests/fixtures/audit-sample.jsonl` was generated by the Python one and is verified
by a Rust test, so the canonical form is pinned across implementations.

### 2.4 What this log does **not** prove

Stated here rather than discovered later:

- **Tail truncation.** Deleting the last N lines leaves a shorter but internally
  consistent chain. Detecting it needs an external anchor: publish the head hash
  somewhere else, or export a bundle with the count.
- **Authorship.** Anyone who can write the file can recompute the whole chain. This
  is an integrity check, not a signature. Signing the envelope and the head hash is
  the next layer.
- **Completeness of Proxima's own traffic.** It records what the policy layer saw.
  Traffic that never reached the layer (a crashed process, a build with the gate
  bypassed) is outside it.

---

## 3. What another tool has to implement to be compatible

1. Parse and validate §1.1 with §1.2's strictness — reject unknown fields.
2. Route **every** outbound request through §1.3 before it leaves the process, after
   any user or plugin rewrite of the request.
3. Refuse to run in a state where an envelope is present but unenforced; report which
   of §1.4's three states it is in, visibly.
4. Append §2.1 entries, chained per §2.2, and verify before appending.
5. Ship a verifier (§2.3) that is not the writer, or is at least independently
   testable.

Two tools honouring the same envelope turn "we were in scope" from an assertion into
a checkable claim. That is the whole point of writing this down.
