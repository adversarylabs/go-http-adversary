# go/http — issue catalog

This document is the **issue catalog** for this adversary: the classes of defects we aim to find, how we detect them (static vs LLM), public pattern references, and staff priority (P0 / P1 / LLM-only / Cut).

It is documentation and roadmap for contributors — not a runtime contract. Implemented detectors live in `src/` with fixtures under `fixtures/`; the **Review verdicts** section records what ships first.

Public examples cited below illustrate bad patterns only. Do not scrape secrets from them or copy copyrighted code into fixtures.

**Catalog id:** `go/http`  
**Status:** public OSS documentation of the issue classes this adversary targets  
**Goal:** trusted, high-precision detections. Prefer missing a weak signal over a false positive.

## Mission
Production-grade Go HTTP servers and clients: timeouts, bounds, middleware order, and safe defaults.

## LLM strategy (required for world-class)
**Enhance:** middleware order stories; production readiness judgment.
**Discover:** authz gaps on route groups, proxy SSRF.

### Division of labor
| Layer | Responsibility |
| --- | --- |
| **Static / structural** | Deterministic signals with line-level evidence. |
| **LLM enhancement** | Impact, multi-file stories, FP suppression. |
| **LLM discovery** | Novel issues only with concrete evidence. |

### Trust / anti-FP rules
Evidence required; LLM-only defaults medium/low; when unsure omit.

## Review verdicts (staff pass)

- **P0 implement:** `server.no-timeouts`, `body.unbounded-read`, `client.no-timeout`, `websocket.origin`, `redirect.open`, `cors.permissive`
- **P1:** `shutdown.missing`, `header.untrusted-log`, `method.override`, `tls.min-version`, `error.stack-leak`, `static.dotdot`, `compression.bomb`, `host.spoof`, `proxy.misconfig`, `cookie.session-fixation`, `metrics.unauth`, `hsts.missing`, `context.ignored`, `proxy-headers.trust`
- **LLM-only:** `middleware.order`, `header.smuggling`, `json.unknown-fields`
- **Cut:** `server.no-base-context` — near-universal "violation" with negligible payoff; FP machine. `trace.exposed` — duplicate of `go-security.pprof.exposed` (owned there).

## Issue catalog

---
### 1. `go-http.server.no-timeouts` — http.Server without Read/Write/Idle timeouts

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** ListenAndServe with zero timeouts enables slowloris.

**Static detection.** AST: http.Server lit missing timeout fields or http.ListenAndServe convenience.

**LLM role.** Suggest explicit Server with timeouts.

**False-positive guards.** httptest.Server in tests.

**Public examples of the bad pattern:**
  - https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
  - https://github.com/hashicorp/go-cleanhttp
  - https://pkg.go.dev/net/http#Server

---
### 2. `go-http.shutdown.missing` — No graceful Shutdown on signal

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** main ListenAndServe without signal.Notify + Shutdown.

**Static detection.** Detect main servers without Shutdown call.

**LLM role.** Recommend pattern.

**False-positive guards.** Libraries not cmd.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/net/http#Server.Shutdown
  - https://github.com/gin-gonic/gin — graceful stop examples
  - https://github.com/go-chi/chi

---
### 3. `go-http.body.unbounded-read` — io.ReadAll on request body without LimitReader

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** ReadAll(r.Body) allows memory exhaustion.

**Static detection.** AST: io.ReadAll/ioutil.ReadAll on http.Request.Body.

**LLM role.** Allow small fixed endpoints with MaxBytesReader.

**False-positive guards.** Already MaxBytesReader wrapped.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/net/http#MaxBytesReader
  - https://github.com/OWASP/Go-SCP
  - https://github.com/gin-gonic/gin — body size limits

---
### 4. `go-http.header.untrusted-log` — Logging entire request headers

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** log.Printf("%v", r.Header) may leak cookies/auth.

**Static detection.** Detect log of r.Header/r.Cookie.

**LLM role.** Redaction advice.

**False-positive guards.** Debug builds.

**Public examples of the bad pattern:**
  - https://github.com/OWASP/Go-SCP
  - https://go.dev/blog/slog
  - https://github.com/securego/gosec

---
### 5. `go-http.middleware.order` — Auth middleware after business handler mount

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Router mounts /admin before auth middleware.

**Static detection.** Framework-specific route AST hard; LLM discovery strong.

**LLM role.** Trace middleware chain.

**False-positive guards.** Public admin health intentionally open.

**Public examples of the bad pattern:**
  - https://github.com/go-chi/chi
  - https://github.com/gin-gonic/gin
  - https://github.com/labstack/echo

---
### 6. `go-http.cors.permissive` — Permissive CORS on credentialed API

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** AllowOrigins * with AllowCredentials.

**Static detection.** Detect cors middleware configs.

**LLM role.** Framework parsers.

**False-positive guards.** Public read-only APIs.

**Public examples of the bad pattern:**
  - https://github.com/rs/cors
  - https://github.com/gin-contrib/cors
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

---
### 7. `go-http.method.override` — Method override without restriction

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** X-HTTP-Method-Override accepted broadly.

**Static detection.** Detect override middleware.

**LLM role.** Limit methods.

**False-positive guards.** Legacy clients documented.

**Public examples of the bad pattern:**
  - https://github.com/gorilla/handlers
  - https://github.com/OWASP/Go-SCP
  - https://datatracker.ietf.org/doc/html/rfc7231

---
### 8. `go-http.websocket.origin` — WebSocket upgrader CheckOrigin always true

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** CheckOrigin: func(...) bool { return true }.

**Static detection.** AST detect always-true CheckOrigin.

**LLM role.** Recommend origin allowlist.

**False-positive guards.** Localhost dev.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/github.com/gorilla/websocket#Upgrader
  - https://github.com/gorilla/websocket
  - https://github.com/OWASP/Go-SCP

---
### 9. `go-http.tls.min-version` — TLSConfig MinVersion < TLS1.2

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** MinVersion: tls.VersionTLS10/11.

**Static detection.** Detect TLSConfig fields.

**LLM role.** Flag.

**False-positive guards.** Tests for old clients.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/crypto/tls#Config
  - https://github.com/OWASP/Go-SCP
  - https://ssl-config.mozilla.org/

---
### 10. `go-http.redirect.open` — Open redirect via user-controlled Location

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** http.Redirect(..., r.FormValue("next")).

**Static detection.** Taint Form/Query to Redirect url.

**LLM role.** Allow relative-only validation helpers.

**False-positive guards.** Validated allowlist redirects.

**Public examples of the bad pattern:**
  - https://github.com/OWASP/Go-SCP
  - https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
  - https://github.com/securego/gosec

---
### 11. `go-http.error.stack-leak` — Error responses include stack traces

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** debug.Stack or %+v errors to client.

**Static detection.** Detect write of fmt.Sprintf("%+v", err) to ResponseWriter.

**LLM role.** LLM: is env production?

**False-positive guards.** Dev mode flags.

**Public examples of the bad pattern:**
  - https://github.com/pkg/errors
  - https://github.com/OWASP/Go-SCP
  - https://github.com/gin-gonic/gin

---
### 12. `go-http.static.dotdot` — FileServer without clean path

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** http.ServeFile with user path.

**Static detection.** Detect ServeFile/ServeContent user input.

**LLM role.** Recommend embed/safejoin.

**False-positive guards.** Fixed paths.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/net/http#ServeFile
  - https://go.dev/blog/osroot
  - https://github.com/securego/gosec — G304

---
### 13. `go-http.client.no-timeout` — Outbound http.Client without Timeout

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Client{Transport: ...} zero Timeout.

**Static detection.** Detect Client lits.

**LLM role.** Allow context-only if all calls use ctx — still warn.

**False-positive guards.** Tests; clients whose custom Transport sets dial/TLS/response-header timeouts, or where every call site provably uses a per-request context deadline (downgrade to low rather than suppress).

**Public examples of the bad pattern:**
  - https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
  - https://github.com/hashicorp/go-cleanhttp
  - https://pkg.go.dev/net/http#Client

---
### 14. `go-http.compression.bomb` — Request body decompression without limits

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** gzip.NewReader(r.Body) without LimitReader.

**Static detection.** Detect compression readers on Body.

**LLM role.** Suggest limits.

**False-positive guards.** Trusted internal.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/compress/gzip
  - https://github.com/OWASP/Go-SCP
  - https://pkg.go.dev/net/http#MaxBytesReader

---
### 15. `go-http.host.spoof` — Trusting r.Host without validation

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Password reset links use r.Host from untrusted input.

**Static detection.** Detect r.Host in URL building for emails/redirects.

**LLM role.** LLM: is Host validated?

**False-positive guards.** Behind trusted proxy with careful config.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/net/http#Request.Host
  - https://github.com/OWASP/Go-SCP
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Host

---
### 16. `go-http.proxy.misconfig` — ReverseProxy without Rewrite/Director safety

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** httputil.NewSingleHostReverseProxy user URL.

**Static detection.** Detect ReverseProxy with user-controlled target.

**LLM role.** SSRF risk story.

**False-positive guards.** Fixed upstream.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/net/http/httputil#ReverseProxy
  - https://github.com/OWASP/Go-SCP
  - https://github.com/securego/gosec

---
### 17. `go-http.header.smuggling` — Hop-by-hop header forwarding

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** Copying all headers to upstream.

**Static detection.** Detect range r.Header copy without denylist.

**LLM role.** LLM discovery.

**False-positive guards.** Intentional proxies.

**Public examples of the bad pattern:**
  - https://www.rfc-editor.org/rfc/rfc7230
  - https://github.com/OWASP/Go-SCP
  - https://pkg.go.dev/net/http/httputil

---
### 18. `go-http.cookie.session-fixation` — Session ID accepted from user input

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** Session token from query string.

**Static detection.** Detect cookie/session set from query.

**LLM role.** Framework awareness.

**False-positive guards.** CSRF tokens in query for legacy.

**Public examples of the bad pattern:**
  - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  - https://github.com/gorilla/sessions
  - https://github.com/alexedwards/scs

---
### 19. `go-http.metrics.unauth` — Prometheus metrics public

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** /metrics unauthenticated exposing labels with secrets.

**Static detection.** Detect promhttp.Handler mounts.

**LLM role.** Suggest auth or network policy notes.

**False-positive guards.** Internal scrape only documented.

**Public examples of the bad pattern:**
  - https://github.com/prometheus/client_golang
  - https://prometheus.io/docs/guides/basic-auth/
  - https://github.com/OWASP/Go-SCP

---
### 20. `go-http.hsts.missing` — HTTPS server without HSTS header

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | medium |

**What it is.** TLS server not setting Strict-Transport-Security.

**Static detection.** Detect TLS Listen without HSTS middleware.

**LLM role.** Optional low severity.

**False-positive guards.** Localhost.

**Public examples of the bad pattern:**
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
  - https://github.com/unrolled/secure
  - https://github.com/OWASP/Go-SCP

---
### 21. `go-http.json.unknown-fields` — JSON decode without DisallowUnknownFields on auth payloads

| Field | Value |
| --- | --- |
| **Severity** | low |
| **Target confidence** | low |

**What it is.** Mass assignment risk for certain APIs.

**Static detection.** Detect Decoder without DisallowUnknownFields on sensitive structs.

**LLM role.** LLM: is mass assignment relevant?

**False-positive guards.** Open extensible APIs.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/encoding/json#Decoder.DisallowUnknownFields
  - https://github.com/OWASP/Go-SCP
  - https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html

---
### 22. `go-http.context.ignored` — Handler ignores r.Context() on outbound calls

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Client.Do without ctx from request.

**Static detection.** Detect http.NewRequest without context vs NewRequestWithContext.

**LLM role.** Cancellation correctness.

**False-positive guards.** Fire-and-forget intentional.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/net/http#NewRequestWithContext
  - https://go.dev/blog/context
  - https://github.com/hashicorp/go-cleanhttp

---
### 23. `go-http.proxy-headers.trust` — Trusting X-Forwarded-For / X-Real-IP without a trusted-proxy check

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Client-supplied forwarding headers used for auth allowlists, rate limiting, or audit identity are trivially spoofed unless a trusted proxy strips/sets them.

**Static detection.** r.Header.Get("X-Forwarded-For"/"X-Real-IP") flowing into IP comparisons, allowlists, or limiter keys.

**LLM role.** Is there a trusted-proxy configuration (gin SetTrustedProxies, RealIP middleware behind a known LB)?

**False-positive guards.** Logging-only use (downgrade to low); frameworks with trusted proxies configured.

**Public examples of the bad pattern:**
  - https://adam-p.ca/blog/2022/03/x-forwarded-for/
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
  - https://github.com/gin-gonic/gin — SetTrustedProxies

---
### 24. `go-http.cancelled-response-publication` — Cancellation abandons a published response

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** A background HTTP producer assigns a shared `*http.Response` and signals completion while the response owner waits on both completion and cancellation. If cancellation wins after both cases are ready, returning without re-observing completion can lose the only body-cleanup path.

**Static detection.** Require one struct's typed response and completion fields, asynchronous producer publication before signal, a waiter select on that signal and `ctx.Done()`, and a same-owner caller that consumes or closes the body.

**LLM role.** Explain the ownership handoff and confirm the proposed synchronization, drain, close, or transfer matches the surrounding API contract.

**False-positive guards.** Cancellation-arm or wrapper synchronization before cleanup, producer-owned close, a proven no-late-publish or ownership-transfer protocol, no actual body owner, non-HTTP payload, and unrelated/comment-only changes.

**Public example:**
  - https://github.com/connectrpc/connect-go/pull/938

---

## Implementation roadmap (after approval)
1. P0 static rules + vulnerable/clean fixtures. 2. LLM enhancement. 3. Evidence-gated discovery. 4. Public-repo precision bake-off.

**P0 priorities:** server timeouts, unbounded body reads, client timeouts, CheckOrigin true, open redirects, permissive CORS.
