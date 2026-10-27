# Test fixtures

## `audit-sample.jsonl`

Three audit entries (allow, deny, halt) in the exact on-disk form: one JSON object
per line, keys sorted, no insignificant whitespace.

It was produced by an independent implementation
(`tools/verify_audit_log.py`), not by the Rust writer, and the Rust test
`policy::audit::tests::verifies_a_log_written_by_another_implementation` reads it.
That makes the canonical serialisation a *specified* property rather than an
accident of `serde_json`'s map type: if either side changes how it canonicalises an
entry, that test fails.

- 3 entries, head hash `0ecd054ed74844244d606bed4df605b8b92b5affd81ee1be5b5a4bdb84eb8a2e`
- `python3 tools/verify_audit_log.py tests/fixtures/audit-sample.jsonl` prints `OK`
