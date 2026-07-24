# Go HTTP adversary

Go HTTP reviews request boundaries and server lifecycle across `net/http`, Gin, Chi, Echo, Fiber, and framework-neutral middleware.

The initial review focuses on server timeouts, bounded request bodies, and graceful shutdown. Findings explain the production consequence and group repeated evidence into one remediation.

## Fixtures and calibration

Five graded fixtures own expected review snapshots. The 61-repository corpus calibrates request lifecycle and server operations without vendoring source.

## Automatic detection

`adversary auto` selects Go HTTP for changed Go source. Runtime-backed semantic detection will narrow this to HTTP-relevant changes when ReviewContext detector capabilities are available.

## Development

Run `npm test`, `adversary validate .`, and `adversary pack --check .`.
