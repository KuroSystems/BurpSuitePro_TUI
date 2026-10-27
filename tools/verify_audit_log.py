#!/usr/bin/env python3
"""Verify a Proxima audit log, without needing the Rust toolchain.

The chain is `hash = sha256(prev_hash || "\\n" || canonical_payload_json)` where
`canonical_payload_json` is the entry with `hash` removed, serialised with sorted
keys and no insignificant whitespace (that is what `serde_json` produces for a
`Value::Object`, which is a `BTreeMap` by default). The first entry chains from 64
zeros.

This tool exists for two reasons: a reviewer should be able to check the log with
software they already trust, and a second implementation is the cheapest way to
find out whether the format is actually specified or merely implemented.

    python3 tools/verify_audit_log.py .proxima/audit-ACME-2026-014.jsonl
    python3 tools/verify_audit_log.py --self-test

Limitations are the log's limitations, not the tool's: a rewritten chain verifies,
because the chain proves integrity and not authorship; and truncating the tail
leaves a shorter but valid chain. Anchor the last hash somewhere else to catch that.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

GENESIS = "0" * 64


def canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_hash(previous: str, payload: dict) -> str:
    return hashlib.sha256(
        previous.encode() + b"\n" + canonical(payload).encode()
    ).hexdigest()


def verify(path: Path) -> tuple[int, str]:
    """Return (entry_count, last_hash). Raises ValueError on the first defect."""
    previous = GENESIS
    seq = 0

    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"line {number}: invalid JSON: {error}") from error
            if not isinstance(entry, dict):
                raise ValueError(f"line {number}: entry is not a JSON object")

            recorded_seq = entry.get("seq")
            if recorded_seq != seq + 1:
                raise ValueError(
                    f"line {number}: expected seq {seq + 1}, found {recorded_seq} "
                    "(entries removed or reordered)"
                )

            recorded_hash = entry.pop("hash", None)
            if not isinstance(recorded_hash, str):
                raise ValueError(f"line {number}: missing hash")

            if chain_hash(previous, entry) != recorded_hash:
                raise ValueError(
                    f"line {number}: hash mismatch (entry modified after it was written)"
                )

            previous = recorded_hash
            seq = recorded_seq

    return seq, previous


def self_test() -> int:
    """Build a short chain, verify it, then break it three ways."""
    import tempfile

    def write(entries: list[dict]) -> Path:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False, encoding="utf-8"
        )
        previous = GENESIS
        for index, entry in enumerate(entries, start=1):
            entry = {"seq": index, "ts": "2026-10-01T00:00:00+00:00", **entry}
            digest = chain_hash(previous, entry)
            handle.write(json.dumps({**entry, "hash": digest}, sort_keys=True) + "\n")
            previous = digest
        handle.close()
        return Path(handle.name)

    base = [
        {"action": "allow", "traffic": "proxied", "method": "GET", "uri": "https://a.test/"},
        {"action": "deny", "traffic": "generated", "method": "DELETE", "uri": "https://a.test/x"},
    ]

    good = write(base)
    count, _ = verify(good)
    assert count == 2, count
    print(f"ok   intact chain of {count} entries verifies")

    tampered = write(base)
    lines = tampered.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"DELETE"', '"GET"')
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        verify(tampered)
    except ValueError as error:
        print(f"ok   edited entry detected: {error}")
    else:
        print("FAIL edited entry accepted", file=sys.stderr)
        return 1

    reordered = write(base)
    lines = reordered.read_text(encoding="utf-8").splitlines()
    reordered.write_text("\n".join(reversed(lines)) + "\n", encoding="utf-8")
    try:
        verify(reordered)
    except ValueError as error:
        print(f"ok   reordered entries detected: {error}")
    else:
        print("FAIL reordered entries accepted", file=sys.stderr)
        return 1

    truncated = write(base)
    lines = truncated.read_text(encoding="utf-8").splitlines()
    truncated.write_text(lines[0] + "\n", encoding="utf-8")
    count, _ = verify(truncated)
    print(
        f"---  truncated tail verifies as {count} entries: known blind spot, "
        "needs an external anchor to detect"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", help="path to the JSONL audit log")
    parser.add_argument("--self-test", action="store_true", help="check the verifier itself")
    parser.add_argument(
        "--expect-entries",
        type=int,
        help="also assert the log has this many entries (catches tail truncation "
        "when you know the expected count from somewhere else)",
    )
    arguments = parser.parse_args(argv)

    if arguments.self_test:
        return self_test()
    if not arguments.log:
        parser.error("give a log path, or --self-test")

    path = Path(arguments.log)
    try:
        count, last = verify(path)
    except (OSError, ValueError) as error:
        print(f"INVALID {path}: {error}", file=sys.stderr)
        return 1

    print(f"OK {path}: {count} entries, head hash {last}")
    if arguments.expect_entries is not None and arguments.expect_entries != count:
        print(
            f"INVALID entry count: expected {arguments.expect_entries}, found {count} "
            "(tail truncated?)",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
