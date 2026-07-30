import { contentSignal, lineSignals, positive } from "./signals.js";
import { type DomainDefinition, type Signal, type SourceRevision } from "./types.js";

export const domain: DomainDefinition = {
  name: "go-http",
  displayName: "Go HTTP",
  observationKey: "go-http.analysis",
  sourceDescription: "Go HTTP",
  includePath: (path) => path.endsWith(".go") && !path.endsWith("_test.go"),
  rules: [
    {
      id: "go-http.server-timeouts",
      title: "The HTTP server has no header-read timeout",
      concern: "missing HTTP server header-read timeouts",
      category: "reliability",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} HTTP server construction${count === 1 ? "" : "s"} omit a header-read timeout.`,
      whyItMatters: "An internet-facing server must bound how long a client can occupy a connection while sending headers.",
      impact: "Slow or malicious clients can retain file descriptors and goroutines indefinitely.",
      recommendation: "Construct http.Server explicitly and set ReadHeaderTimeout plus lifecycle-appropriate read, write, and idle bounds.",
    },
    {
      id: "go-http.handler-body-limit",
      title: "An HTTP handler buffers the request body without a size limit",
      concern: "unbounded HTTP handler request body buffering",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} handler body read${count === 1 ? "" : "s"} can consume an unbounded request body.`,
      whyItMatters: "Server request bodies are attacker-controlled and io.ReadAll allocates until EOF.",
      impact: "A single request can create memory pressure or terminate the process.",
      recommendation: "Wrap r.Body with http.MaxBytesReader (size class for JSON vs uploads) before decoding or buffering.",
    },
    {
      id: "go-http.client-response-limit",
      title: "An HTTP client buffers a response body without a size limit",
      concern: "unbounded HTTP client response buffering",
      category: "reliability",
      severity: "medium",
      confidence: "high",
      summary: (count) => `${count} client response read${count === 1 ? "" : "s"} buffer the body without a size class.`,
      whyItMatters: "Outbound peers can return unexpectedly large bodies that exhaust memory.",
      impact: "A misbehaving or compromised endpoint can OOM the client process.",
      recommendation: "Read with io.LimitReader using a size class (token JSON vs metadata vs small asset), not an unbounded io.ReadAll.",
    },
    {
      id: "go-http.graceful-shutdown",
      title: "The server lifecycle has no graceful shutdown path",
      concern: "HTTP servers without graceful shutdown",
      category: "reliability",
      severity: "medium",
      confidence: "high",
      summary: (count) => `${count} server startup path${count === 1 ? "" : "s"} use ListenAndServe without a matching Shutdown.`,
      whyItMatters: "Production and long-lived local callback servers must stop admission when the owning context ends.",
      impact: "Deploys, interrupts, and abandoned login callbacks can drop work or leak listeners.",
      recommendation: "Own an http.Server, select on caller cancel/timeout, and call Shutdown with a bounded context.",
    },
    {
      id: "go-http.client-no-timeout",
      title: "An HTTP client has no timeout budget",
      concern: "HTTP clients without timeout budgets",
      category: "reliability",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} HTTP client${count === 1 ? "" : "s"} are constructed without an explicit Timeout.`,
      whyItMatters: "Outbound calls without a deadline hang indefinitely against dead peers and can exhaust goroutines.",
      impact: "Workers and CLI commands wedge on network partitions with no user-visible deadline.",
      recommendation: "Set http.Client.Timeout or always pair requests with context deadlines.",
    },
    {
      id: "go-http.request-no-context",
      title: "An HTTP request is built without a context",
      concern: "HTTP requests without cancellation contexts",
      category: "reliability",
      severity: "medium",
      confidence: "high",
      summary: (count) => `${count} request construction${count === 1 ? "" : "s"} use NewRequest without a parent context.`,
      whyItMatters: "Caller cancellation and deadlines only propagate through RequestWithContext.",
      impact: "Cancelled work continues consuming connections after the caller has abandoned the operation.",
      recommendation: "Use http.NewRequestWithContext with the owning request, command, or worker context.",
    },
    {
      id: "go-http.default-client",
      title: "Package-level DefaultClient helpers perform outbound calls",
      concern: "unbounded DefaultClient HTTP helpers",
      category: "reliability",
      severity: "medium",
      confidence: "high",
      summary: (count) => `${count} call${count === 1 ? "" : "s"} use http.Get/Post/Head/PostForm without an owned client timeout.`,
      whyItMatters: "http.DefaultClient has no Timeout and is shared process-wide.",
      impact: "One hung call can leave sockets and goroutines open indefinitely.",
      recommendation: "Construct an http.Client with Timeout (or Transport limits) and call client.Do with a context.",
    },

    {
      id: "go-http.websocket-origin",
      title: "WebSocket CheckOrigin always allows",
      concern: "websocket origin bypass",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} WebSocket upgrader${count === 1 ? "" : "s"} set CheckOrigin to always true.`,
      whyItMatters: "Accepting any Origin enables cross-site WebSocket abuse.",
      impact: "Attackers can open privileged sockets from malicious sites.",
      recommendation: "Validate Origin against an allowlist.",
    },
    {
      id: "go-http.redirect-open",
      title: "Open redirect via user-controlled location",
      concern: "open redirect",
      category: "security",
      severity: "high",
      confidence: "medium",
      summary: (count) => `${count} redirect${count === 1 ? "" : "s"} use request-controlled destinations.`,
      whyItMatters: "Open redirects enable phishing and token theft.",
      impact: "Users can be sent to attacker-controlled sites after auth.",
      recommendation: "Allowlist redirect targets or force relative paths.",
    },
    {
      id: "go-http.cors-permissive",
      title: "Permissive CORS with credentials",
      concern: "cors wildcard credentials",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} CORS configuration${count === 1 ? "" : "s"} allow broad origins with credentials.`,
      whyItMatters: "Wildcard origins with credentials break browser security assumptions.",
      impact: "Malicious sites can invoke credentialed APIs.",
      recommendation: "Use explicit origin allowlists; never combine * with credentials.",
    },
  ],
  noRiskSummary: "The reviewed HTTP boundaries include bounded input, server timing, graceful lifecycle ownership, and outbound deadlines.",
  approvalSummary: "I would approve the reviewed HTTP request, client, and server lifecycle.",
  analyze(file) {
    const signals = [
      ...(file.current.includes("http.Server{") && !file.current.includes("ReadHeaderTimeout:")
        ? contentSignal(file, "go-http.server-timeouts", /http\.Server\s*\{/, "This server is constructed without ReadHeaderTimeout.")
        : []),
      ...readAllSignals(file),
      ...gracefulShutdownSignals(file),
      ...clientNoTimeoutSignals(file),
      ...lineSignals(
        file,
        "go-http.request-no-context",
        /\bhttp\.NewRequest\s*\(/,
        () => "This request is constructed without a parent context.",
      ),
      ...lineSignals(
        file,
        "go-http.default-client",
        /\bhttp\.(?:Get|Post|Head|PostForm)\s*\(/,
        () => "This call uses the process DefaultClient without an explicit timeout.",
      ),
      ...lineSignals(
        file,
        "go-http.websocket-origin",
        /CheckOrigin\s*:\s*func[\s\S]{0,80}?return\s+true/,
        () => "CheckOrigin always returns true.",
      ),
      ...lineSignals(
        file,
        "go-http.redirect-open",
        /http\.Redirect\([^)]*(?:FormValue|URL\.Query|Query\()/,
        () => "Redirect destination may be user-controlled.",
      ),
      ...lineSignals(
        file,
        "go-http.cors-permissive",
        /AllowOrigins?\s*[:=][^;\n]*\*|"Access-Control-Allow-Origin"\s*,\s*"\*"/,
        () => "CORS appears to allow all origins.",
      ),
    ];
    return {
      signals,
      positives: [
        ...positive(file, "go-http.request-bounded", /\bhttp\.MaxBytesReader\s*\(/, "Request body size is bounded before consumption."),
        ...positive(file, "go-http.response-bounded", /\bio\.LimitReader\s*\(/, "A body read is wrapped with LimitReader."),
        ...positive(file, "go-http.shutdown-owned", /\.Shutdown\s*\(/, "Server shutdown is explicitly owned and drainable."),
        ...positive(file, "go-http.client-timeout", /http\.Client\s*\{[^}]*Timeout\s*:/s, "An HTTP client declares an explicit Timeout."),
        ...positive(file, "go-http.request-context", /\bhttp\.NewRequestWithContext\s*\(/, "Outbound requests carry a parent context."),
      ],
    };
  },
};

/**
 * Partition io.ReadAll by trust boundary. Do not call CLI stdin, local files, or
 * full-artifact downloads "attacker-controlled request bodies".
 */
function readAllSignals(file: SourceRevision): Signal[] {
  if (!/\bio\.ReadAll\s*\(/.test(file.current)) return [];
  const signals: Signal[] = [];
  const lines = file.current.split("\n");
  lines.forEach((line, index) => {
    const match = line.match(/\bio\.ReadAll\s*\(\s*([^)]*)\s*\)/);
    if (match === null) return;
    // Local limit already applied on this line or nearby assignment.
    if (/\b(?:MaxBytesReader|LimitReader)\s*\(/.test(line)) return;
    const arg = (match[1] ?? "").trim();
    const surrounding = lines.slice(Math.max(0, index - 3), index + 3).join("\n");
    const path = file.path.replaceAll("\\", "/");

    // Class E-ish: skip under testdata / examples already excluded by includePath for _test.go.
    if (/(^|\/)(?:testdata|fixtures)\//.test(path)) return;

    // Class C: full product downloads / archives / checksums — do not recommend small limits.
    if (isLargeArtifactDownload(arg, surrounding, path)) return;

    // Class B / D: CLI stdin, local files, OCI/local store — not HTTP threat model.
    if (isLocalOrCliInput(arg, surrounding, path)) return;

    // Class A1: HTTP server handler request body.
    if (isHandlerRequestBody(arg, surrounding)) {
      signals.push({
        ruleId: "go-http.handler-body-limit",
        path: file.path,
        line: index + 1,
        message: "This handler fully buffers the HTTP request body without a size bound.",
        snippet: line.trim().slice(0, 300),
        data: { class: "handler-request-body", arg },
      });
      return;
    }

    // Class A2: HTTP client response body.
    if (isClientResponseBody(arg, surrounding)) {
      signals.push({
        ruleId: "go-http.client-response-limit",
        path: file.path,
        line: index + 1,
        message: "This client fully buffers an HTTP response body without a size class.",
        snippet: line.trim().slice(0, 300),
        data: { class: "client-response-body", arg },
      });
      return;
    }

    // Ambiguous ReadAll — prefer no medium/high finding.
  });
  return signals;
}

function isHandlerRequestBody(arg: string, surrounding: string): boolean {
  if (/\br\.Body\b|\breq\.Body\b|\brequest\.Body\b/.test(arg)) return true;
  if (/\b(?:r|req|request)\.Body\b/.test(arg)) return true;
  // io.ReadAll(body) where body was r.Body nearby
  if (/^\w+$/.test(arg) && new RegExp(`\\b${arg}\\s*:?=\\s*(?:r|req|request)\\.Body\\b`).test(surrounding)) {
    return true;
  }
  return false;
}

function isClientResponseBody(arg: string, surrounding: string): boolean {
  if (/\bresp(?:onse)?\.Body\b|\bres\.Body\b/.test(arg)) return true;
  if (/^\w+$/.test(arg) && new RegExp(`\\b${arg}\\s*:?=\\s*resp(?:onse)?\\.Body\\b`).test(surrounding)) {
    return true;
  }
  // Common: io.ReadAll(resp.Body) already covered; also http.Get result.
  if (/\.Body\b/.test(arg) && /\b(?:http\.(?:Get|Post|Head|PostForm)|client\.Do|Client\.Do)\b/.test(surrounding)) {
    return true;
  }
  return false;
}

function isLocalOrCliInput(arg: string, surrounding: string, path: string): boolean {
  if (/\bos\.Stdin\b|\bstdin\b/i.test(arg)) return true;
  if (/\bos\.Open\b|\bos\.ReadFile\b|\bos\.File\b|\bbytes\.NewReader\b|\bstrings\.NewReader\b|\bbytes\.Buffer\b/.test(arg + surrounding)) {
    // Only when ReadAll argument is clearly the file/reader, not an HTTP body alias.
    if (/\bBody\b/.test(arg)) return false;
    if (/\bos\.Stdin\b|\bOpen\s*\(|ReadFile\s*\(/.test(arg) || /\b(?:f|file|r|reader|rc)\b/.test(arg)) {
      // CLI / local path heuristics
      if (/(^|\/)cli\//.test(path) || /(^|\/)cmd\//.test(path)) return true;
      if (/\bos\.Stdin\b/.test(arg + surrounding)) return true;
      if (/\bOpen\s*\(|ReadFile\s*\(|ioutil\.ReadFile/.test(surrounding) && !/\bBody\b/.test(arg)) return true;
    }
  }
  // OCI / local store content (not HTTP).
  if (/\bmanifest\b|\boci\b|\bblob\b|\blayer\b/i.test(arg + surrounding) && !/\bBody\b/.test(arg)) {
    return true;
  }
  return false;
}

function isLargeArtifactDownload(arg: string, surrounding: string, path: string): boolean {
  const blob = `${path}\n${arg}\n${surrounding}`;
  if (/\b(?:download|downloader|checksum|archive|tarball|\.tar\.|gzip|binary|artifact|release asset)\b/i.test(blob)) {
    // Still flag if it is clearly resp.Body of a small JSON token exchange — those say "token"/"json".
    if (/\b(?:token|json|metadata|mmds)\b/i.test(blob) && /\bBody\b/.test(arg + surrounding) && !/\b(?:archive|tarball|binary|gzip)\b/i.test(blob)) {
      return false;
    }
    return true;
  }
  return false;
}

function gracefulShutdownSignals(file: SourceRevision): Signal[] {
  if (!/\bListenAndServe\s*\(/.test(file.current)) return [];
  if (/\.Shutdown\s*\(/.test(file.current)) return [];
  // Short-lived test helpers already excluded via _test.go includePath.
  return lineSignals(
    file,
    "go-http.graceful-shutdown",
    /\b(?:http\.)?ListenAndServe\s*\(/,
    () => "Server startup has no matching graceful shutdown path in this lifecycle.",
  );
}

function clientNoTimeoutSignals(file: SourceRevision) {
  if (!/http\.Client\s*\{/.test(file.current)) return [];
  // Flag Client literals that omit Timeout: in the same composite literal block (heuristic).
  const signals = [];
  const re = /http\.Client\s*\{/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(file.current)) !== null) {
    const start = match.index;
    const slice = file.current.slice(start, start + 400);
    if (!/\bTimeout\s*:/.test(slice)) {
      const line = file.current.slice(0, start).split("\n").length;
      signals.push({
        ruleId: "go-http.client-no-timeout",
        path: file.path,
        line,
        message: "This HTTP client is constructed without Timeout.",
        snippet: slice.split("\n")[0]?.trim().slice(0, 300) ?? "http.Client{",
        data: {},
      });
    }
  }
  return signals;
}
