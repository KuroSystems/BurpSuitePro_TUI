## What was wrong or missing

<!-- The failure mode, not a restatement of the diff. -->

## What changed

<!-- Bullet points. Mention anything a reviewer should look at first. -->

## How it was verified

<!--
Tests added/updated, plus any manual verification. "cargo test passes" is not
enough on its own for behaviour that touches the proxy or the UI.
-->

## Checklist

- [ ] `cargo test` passes locally
- [ ] New pure logic has unit tests
- [ ] No new `unwrap()`/`expect()` on network, file, or user input
- [ ] No blocking I/O added to the UI thread
- [ ] `README.md` / docs updated if keys, env vars, or behaviour changed
- [ ] No capability is claimed in docs that the code does not implement

## Related issues

<!-- Fixes #... -->
