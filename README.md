# go/http

**go/http** reviews Go HTTP services and clients for **bounded requests, safe middleware defaults, and production-ready server/client lifecycle** across `net/http`, Gin, Chi, Echo, Fiber, and framework-neutral middleware.

It is an **HTTP domain reviewer**, not a general web app scanner. It prefers silence over framework style. When it reports, production servers or outbound clients can hang, OOM, or leak security boundaries.

## What it does

1. **Discovers** non-test Go files (`*.go`, excluding `*_test.go`).
2. **Runs deterministic detectors** for timeouts, body bounds, shutdown, CORS, redirects, and WebSocket origin.
3. **Synthesizes a review** with production impact.
4. Optionally **enhances** with a model when provided.

It never executes the scanned project as the product under review, never installs dependencies into it, and never needs network access to the target repository.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)** — the audit surface for “what does this adversary look for?”

Highlights:

| Area | Examples |
| --- | --- |
| Servers | Missing `ReadHeaderTimeout`; no graceful `Shutdown` |
| Bodies | Unbounded `io.ReadAll` on request/response bodies |
| Clients | No `Timeout`; `http.Get`/`DefaultClient`; `NewRequest` without context |
| Security | Permissive CORS; open redirects; WebSocket `CheckOrigin` always true |

### Ownership boundaries

Other official adversaries own adjacent classes so findings stay non-duplicative:

| Concern | Owned by |
| --- | --- |
| TLS skip-verify, JWT, path traversal, generic crypto | [`go/security`](https://github.com/adversarylabs/go-security-adversary) |
| CLI process ownership and subprocess cancel | [`go/cli`](https://github.com/adversarylabs/go-cli-adversary) |
| DB pool/rows lifecycle | [`go/database`](https://github.com/adversarylabs/go-database-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire where graded fixtures exist.
- Prefer missing a weak signal over a false positive on normal production code.
