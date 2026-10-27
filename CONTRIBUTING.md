# Contributing to Proxima

Thanks for looking. This document is short on ceremony and specific about what
makes a patch easy to accept.

## Quick start

```bash
git clone https://github.com/KuroSystems/BurpSuitePro_TUI
cd BurpSuitePro_TUI
cargo build            # debug binary
cargo test             # unit tests (no network, no root, no GUI required)
cargo run              # TUI; press s in the Settings tab to start the proxy
```

Requirements: Rust stable (2021 edition) and a POSIX-ish terminal. `cargo test`
deliberately avoids opening real sockets and does not need a display.

## Before you open a pull request

1. **Write a test.** Anything that can be tested without a terminal or a live
   socket should be. Pure logic (decoding, parsing, scope matching, payload
   generation, redaction, persistence) is expected to come with tests.
   `cargo test` must pass.
2. **Keep the diff focused.** One logical change per PR. A bug fix that also
   reformats 400 lines will be asked to split.
3. **Explain the "why".** The PR description should say what was wrong or missing
   before the change, and how the change was verified. "Verified by hand on macOS
   with Safari; screenshots/log excerpt attached" is a perfectly good answer.
4. **Update docs when behaviour changes.** `README.md` documents keys and env vars;
   if you add or rename one, update it in the same commit.
5. **Match the code style that is there.** `cargo fmt` is advisory right now (the
   tree is not fully formatted); don't submit formatting-only churn.

## Ground rules for this codebase

- **Never claim a capability the code does not have.** The README has been wrong
  before; correcting an overclaim is a valued contribution. If a tab is a
  scaffold, say so in the docs.
- **Wire bytes are sacred.** Captured traffic is stored exactly as it arrived on
  the wire. Anything that needs readable bytes goes through
  `net::decode::decoded_body` (bounded) rather than mutating the stored flow.
  This split is what makes replay and evidence export possible later.
- **No panics on hostile input.** The proxy parses bytes from the network and from
  project files. `unwrap()`/`expect()` is acceptable only for statically valid
  builder calls (e.g. constructing a fixed error response), never for parsed data.
- **No unbounded work on the UI thread.** Blocking disk or network calls belong on
  a worker (`src/db_writer.rs` is the model to follow).
- **Don't add a network dependency for a feature that must work offline.** Local
  analysis, scanning, and reporting must never require egress.

## Commit messages

Conventional prefixes keep the changelog readable:

```
fix(proxy): serve HTTP/2 when ALPN negotiates h2
feat(decode): bounded gzip/br/zstd content decoding
docs(security): document advisory scope rules
test(db): cover writer flush barrier
```

Body text should explain the failure mode, not restate the diff.

## Reporting bugs

Include: version or commit, OS and terminal, the exact steps, what you expected,
and what happened. If the proxy misbehaves, attach the relevant lines from
`logs/proxima-tui.log` (it is written specifically so stdout stays clean) and, if
possible, a redacted capture.

For security issues, follow [`SECURITY.md`](SECURITY.md) instead of opening an issue.

## Proposing larger work

Anything bigger than a bug fix is easier to land if the design is agreed first. Open
an issue with:

- the problem and who has it,
- the smallest version that solves it,
- what it costs (new deps, new config, new failure modes),
- how it will be tested.

`docs/feature-strategy.md` describes five larger directions the project is aiming
at; contributions that move one of those forward are especially welcome, but
smaller quality fixes are never ignored.

## Good first contributions

- Add a passive scanner definition to `resources/passive/` with a reference link.
- Add a `Decoder` transform (with tests) — the transform table is in
  `src/models/decoder.rs`.
- Improve an error message that would have confused you.
- Add a test for a parser edge case you can think of (`ParsedRequest::parse`,
  `parse_positions`, `jwt_decode`, `decode_blob`).
- Reproduce and file an issue for a README claim that does not hold.

## License of contributions

By submitting a pull request you agree your contribution is dual-licensed under
MIT and Apache-2.0 as described in [`LICENSE`](LICENSE). There is no CLA.

## Code of conduct

Participation is covered by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
