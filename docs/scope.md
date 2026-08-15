# go/http — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `go-http`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Go HTTP

## Mission

Review Go HTTP servers/clients for bounded requests, safe middleware, and production lifecycle.

## In scope (fair miss if humans raised it and we did not)

- Missing timeouts, unbounded request/client bodies, and unbounded buffering of provider or downstream HTTP response output
- HTTP response-body ownership lost when cancellation races a concurrent response publication
- Middleware ordering / panic recovery gaps
- Server shutdown / lifecycle mistakes
- Unsafe client reuse or per-request clients in hot paths when relevant to HTTP

## Out of scope (not a miss for this adversary)

- Non-HTTP concurrency
- CI
- Non-Go

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
