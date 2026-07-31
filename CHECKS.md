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
