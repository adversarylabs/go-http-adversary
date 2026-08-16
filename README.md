# Go HTTP adversary

Reviews Go HTTP services for bounded requests, safe middleware, and production-ready server lifecycle.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates changed Go HTTP client and server code for timeouts, cancellation, body ownership, buffering limits, redirects, CORS, shutdown, and protocol capabilities.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns only this Go specialty. Other Go concerns remain with the corresponding `go/*` adversaries, and it does not execute or modify the target repository.
