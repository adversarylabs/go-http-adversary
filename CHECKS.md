# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `go-http.cancelled-response-publication` | Medium | A background producer publishes a `*http.Response` before signalling completion, while a response-body owner can return from a competing cancellation case without observing the ready response |
| `go-http.client-no-timeout` | High | HTTP client has no timeout budget |
| `go-http.client-response-body-close` | Medium | A consumed HTTP response body is not closed |
| `go-http.client-response-limit` | Medium | Client buffers response without size limit |
| `go-http.cors-permissive` | High | CORS allows overly broad origins/methods |
| `go-http.default-client` | Medium | Package-level DefaultClient helpers |
| `go-http.graceful-shutdown` | Medium | No graceful shutdown path |
| `go-http.handler-body-limit` | High | Handler buffers request body without limit |
| `go-http.provider-response-buffer-limit` | Medium | A production `http.ResponseWriter` substitute accumulates body data written by a provider, plugin, or downstream callback without a proven bound |
| `go-http.redirect-open` | High | Open redirect on untrusted next URL |
| `go-http.request-no-context` | Medium | Request built without context |
| `go-http.response-writer-capabilities` | Medium | A transparent `http.ResponseWriter` wrapper claims to preserve `Flusher` or `Hijacker`, but relies only on `Unwrap`/`ResponseController` and does not declare the corresponding methods |
| `go-http.server-timeouts` | High | HTTP server missing header-read timeout |
| `go-http.websocket-origin` | High | WebSocket CheckOrigin always allows |
