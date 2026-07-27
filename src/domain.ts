import { contentSignal, lineSignals, positive } from "./signals.js";
import { type DomainDefinition, type SourceRevision } from "./types.js";

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
      id: "go-http.body-limit",
      title: "A request body is buffered without an explicit size limit",
      concern: "unbounded HTTP request body buffering",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} handler body read${count === 1 ? "" : "s"} can consume an unbounded request.`,
      whyItMatters: "Request bodies are attacker-controlled and io.ReadAll allocates until EOF.",
      impact: "A single request can create memory pressure or terminate the process.",
      recommendation: "Wrap the body with http.MaxBytesReader or io.LimitReader before decoding or buffering.",
    },
    {
      id: "go-http.graceful-shutdown",
      title: "The server lifecycle has no graceful shutdown path",
      concern: "HTTP servers without graceful shutdown",
      category: "reliability",
      severity: "medium",
      confidence: "high",
      summary: (count) => `${count} server startup path${count === 1 ? "" : "s"} use ListenAndServe without a matching Shutdown.`,
      whyItMatters: "Production termination must stop admission while allowing in-flight requests to drain.",
      impact: "Deploys and interrupts can drop active requests and abandon response work.",
      recommendation: "Own an http.Server, listen for cancellation, and call Shutdown with a bounded context.",
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
  ],
  noRiskSummary: "The reviewed HTTP boundaries include bounded input, server timing, graceful lifecycle ownership, and outbound deadlines.",
  approvalSummary: "I would approve the reviewed HTTP request, client, and server lifecycle.",
  analyze(file) {
    const signals = [
      ...(file.current.includes("http.Server{") && !file.current.includes("ReadHeaderTimeout:")
        ? contentSignal(file, "go-http.server-timeouts", /http\.Server\s*\{/, "This server is constructed without ReadHeaderTimeout.")
        : []),
      ...(file.current.includes("io.ReadAll(") && !/(MaxBytesReader|LimitReader)\s*\(/.test(file.current)
        ? lineSignals(file, "go-http.body-limit", /\bio\.ReadAll\s*\(/, () => "The request body is fully buffered without a visible size bound.")
        : []),
      ...(file.current.includes("ListenAndServe(") && !/\.Shutdown\s*\(/.test(file.current)
        ? lineSignals(file, "go-http.graceful-shutdown", /\b(?:http\.)?ListenAndServe\s*\(/, () => "Server startup has no matching graceful shutdown path in this lifecycle.")
        : []),
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
    ];
    return {
      signals,
      positives: [
        ...positive(file, "go-http.request-bounded", /\bhttp\.MaxBytesReader\s*\(/, "Request body size is bounded before consumption."),
        ...positive(file, "go-http.shutdown-owned", /\.Shutdown\s*\(/, "Server shutdown is explicitly owned and drainable."),
        ...positive(file, "go-http.client-timeout", /http\.Client\s*\{[^}]*Timeout\s*:/s, "An HTTP client declares an explicit Timeout."),
        ...positive(file, "go-http.request-context", /\bhttp\.NewRequestWithContext\s*\(/, "Outbound requests carry a parent context."),
      ],
    };
  },
};

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
