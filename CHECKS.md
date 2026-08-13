# Checks — what go/http detects

This file is the **public audit list** of detectors. If a rule id appears here, it is part of the product surface: it should fire on a vulnerable pattern, stay quiet on the documented clean case, and produce file:line evidence where applicable.

Runtime source of truth: [`src/domain.ts`](src/domain.ts).
Regression entry: graded fixtures and corpus under `test/`.

**Scope:** non-test `*.go` files in HTTP services and clients.

---

## High

### `go-http.server-timeouts`

| | |
| --- | --- |
| **What** | HTTP server missing header-read timeout |
| **Why** | Slowloris-style connection retention |
| **Looks for** | `http.Server` / ListenAndServe without ReadHeaderTimeout |
| **Stays quiet when** | Explicit Server with ReadHeaderTimeout (+ read/write/idle as needed) |
| **Remediation** | Always set ReadHeaderTimeout on internet-facing servers |

### `go-http.handler-body-limit`

| | |
| --- | --- |
| **What** | Handler buffers request body without limit |
| **Why** | Attacker-controlled body can OOM |
| **Looks for** | `io.ReadAll(r.Body)` without MaxBytesReader |
| **Stays quiet when** | http.MaxBytesReader before decode |
| **Remediation** | Bound every request body read |

### `go-http.client-no-timeout`

| | |
| --- | --- |
| **What** | HTTP client has no timeout budget |
| **Why** | Hung peers wedge workers |
| **Looks for** | `http.Client` without Timeout |
| **Stays quiet when** | Set Client.Timeout or per-request deadlines |
| **Remediation** | Never ship a client without a deadline |

### `go-http.cors-permissive`

| | |
| --- | --- |
| **What** | CORS allows overly broad origins/methods |
| **Why** | Browser-side cross-origin abuse |
| **Looks for** | Access-Control-Allow-Origin: * with credentials or wildcard patterns |
| **Stays quiet when** | Explicit allowlist |
| **Remediation** | Never combine * with credentials |

### `go-http.redirect-open`

| | |
| --- | --- |
| **What** | Open redirect on untrusted next URL |
| **Why** | Phishing / token theft via redirects |
| **Looks for** | Redirect to query/header URL without allowlist |
| **Stays quiet when** | Allowlisted hosts only |
| **Remediation** | Validate redirect targets |

### `go-http.websocket-origin`

| | |
| --- | --- |
| **What** | WebSocket CheckOrigin always allows |
| **Why** | CSWSH from malicious origins |
| **Looks for** | CheckOrigin: return true |
| **Stays quiet when** | Origin allowlist |
| **Remediation** | Validate Origin before upgrade |

## Medium

### `go-http.client-response-limit`

| | |
| --- | --- |
| **What** | Client buffers response without size limit |
| **Why** | Peer can return huge bodies |
| **Looks for** | `io.ReadAll(resp.Body)` unbounded |
| **Stays quiet when** | io.LimitReader with size class |
| **Remediation** | Bound response reads |

### `go-http.provider-response-buffer-limit`

| | |
| --- | --- |
| **What** | A production `http.ResponseWriter` substitute accumulates body data written by a provider, plugin, or downstream callback without a proven bound |
| **Why** | The callback controls output volume, so the intermediary can grow the process heap until failure |
| **Looks for** | A ResponseWriter-shaped type with a `bytes.Buffer`-backed `Write`, instantiated and passed across a provider/downstream callback boundary |
| **Stays quiet when** | The writer enforces a hard cap, the prepared source establishes an upstream maximum, output is streamed/backpressured or spilled, the recorder is internal/test-only, or no callback boundary is proven |
| **Remediation** | Enforce an endpoint-appropriate response cap or use streaming/backpressure/spill-to-disk for legitimately large output |

### `go-http.graceful-shutdown`

| | |
| --- | --- |
| **What** | No graceful shutdown path |
| **Why** | Deploys drop in-flight work |
| **Looks for** | ListenAndServe without Shutdown |
| **Stays quiet when** | Own Server; Shutdown on signal/ctx |
| **Remediation** | Implement graceful shutdown |

### `go-http.request-no-context`

| | |
| --- | --- |
| **What** | Request built without context |
| **Why** | Cancel does not propagate |
| **Looks for** | `http.NewRequest` without context |
| **Stays quiet when** | `NewRequestWithContext` |
| **Remediation** | Always attach owning context |

### `go-http.default-client`

| | |
| --- | --- |
| **What** | Package-level DefaultClient helpers |
| **Why** | No Timeout; shared process-wide |
| **Looks for** | `http.Get`/`Post`/`Head`/`PostForm` |
| **Stays quiet when** | Owned client with Timeout |
| **Remediation** | Prefer explicit clients |

### `go-http.response-writer-capabilities`

| | |
| --- | --- |
| **What** | A transparent `http.ResponseWriter` wrapper claims to preserve `Flusher` or `Hijacker`, but relies only on `Unwrap`/`ResponseController` and does not declare the corresponding methods |
| **Why** | Existing middleware often uses direct `w.(http.Flusher)` and `w.(http.Hijacker)` assertions, which do not follow `Unwrap` |
| **Looks for** | A changed, explicit capability-preservation claim beside a writer wrapper, named optional interfaces, and missing `Flush`/`Hijack` methods |
| **Stays quiet when** | Direct methods are declared; the wrapper intentionally reduces capabilities and makes no preservation claim; an ordinary recorder has no transparent-compatibility contract |
| **Remediation** | Implement the claimed methods with wrapper-appropriate semantics and test both direct assertions and `http.ResponseController` |
