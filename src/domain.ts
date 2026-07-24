import { contentSignal, lineSignals, positive } from "./signals.js";
import { type DomainDefinition } from "./types.js";

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
      category: "reliability",
      severity: "medium",
      confidence: "high",
      summary: (count) => `${count} server startup path${count === 1 ? "" : "s"} use ListenAndServe without a matching Shutdown.`,
      whyItMatters: "Production termination must stop admission while allowing in-flight requests to drain.",
      impact: "Deploys and interrupts can drop active requests and abandon response work.",
      recommendation: "Own an http.Server, listen for cancellation, and call Shutdown with a bounded context.",
    },
  ],
  noRiskSummary: "The reviewed HTTP boundaries include bounded input, server timing, and graceful lifecycle ownership.",
  approvalSummary: "I would approve the reviewed HTTP request and server lifecycle.",
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
    ];
    return {
      signals,
      positives: [
        ...positive(file, "go-http.request-bounded", /\bhttp\.MaxBytesReader\s*\(/, "Request body size is bounded before consumption."),
        ...positive(file, "go-http.shutdown-owned", /\.Shutdown\s*\(/, "Server shutdown is explicitly owned and drainable."),
      ],
    };
  },
};
