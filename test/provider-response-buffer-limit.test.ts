import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";
import { createApp } from "../src/index.ts";
import { GO_HTTP_MODEL_PROMPT } from "../src/model-review.ts";

async function review(name: string, source: string) {
  const root = await mkdtemp(join(tmpdir(), `go-http-provider-buffer-${name}-`));
  await mkdir(root, { recursive: true });
  await writeFile(join(root, "middleware.go"), source);
  return createApp().run({ input: { source: { path: root } } });
}

const header = `package middleware
import (
  "bytes"
  "net/http"
)
type Provider interface { Authenticate(http.ResponseWriter, *http.Request) error }
`;

const unboundedSource = header + `
type bufferedWriter struct {
  header http.Header
  body bytes.Buffer
}
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{header: make(http.Header)}
  _ = p.Authenticate(writer, req)
}
func unrelated() {}
`;

test("reports callback-controlled ResponseWriter accumulation without a bound", async () => {
  const output = await review("unbounded", unboundedSource);
  const finding = output.findings.find((item) => item.ruleId === "go-http.provider-response-buffer-limit");
  assert.ok(finding);
  assert.equal(finding.confidence, "high");
  assert.equal(finding.evidence.length, 1);
  assert.equal(finding.evidence[0]?.data?.callbackMethod, "Authenticate");
});

test("diff mode requires a changed buffer or callback boundary", async () => {
  const unrelatedLine = unboundedSource.split("\n").findIndex((line) => line === "func unrelated() {}") + 1;
  const writeLine = unboundedSource.split("\n").findIndex((line) => line.includes("return w.body.Write(data)")) + 1;
  const base = {
    path: "middleware.go",
    current: unboundedSource,
    status: "modified" as const,
  };
  const unrelated = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ ...base, changedLines: new Set([unrelatedLine]) }],
  });
  assert.equal(unrelated.signals.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);

  const changedWrite = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ ...base, changedLines: new Set([writeLine]) }],
  });
  assert.equal(changedWrite.signals.filter((item) => item.ruleId === "go-http.provider-response-buffer-limit").length, 1);
});

test("diff mode only accepts semantic buffer, write, or callback lines and reanchors callback evidence", async () => {
  const source = unboundedSource.replace("body bytes.Buffer", "body bytes.Buffer\n  note string").replace(
    "func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }",
    `func (w *bufferedWriter) Write(data []byte) (int, error) {
  w.header.Set("X-Recorder", "1")
  return w.body.Write(data)
}`,
  );
  const lines = source.split("\n");
  const base = { path: "middleware.go", current: source, status: "modified" as const };
  const noteLine = lines.findIndex((line) => line.includes("note string")) + 1;
  const headerLine = lines.findIndex((line) => line.includes("X-Recorder")) + 1;
  const callbackLine = lines.findIndex((line) => line.includes("p.Authenticate")) + 1;

  for (const unrelatedLine of [noteLine, headerLine]) {
    const output = await analyzeDiscovery({
      mode: "diff",
      base: "main",
      files: [{ ...base, changedLines: new Set([unrelatedLine]) }],
    });
    assert.equal(output.signals.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);
  }

  const callbackOnly = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ ...base, changedLines: new Set([callbackLine]) }],
  });
  const finding = callbackOnly.signals.find((item) => item.ruleId === "go-http.provider-response-buffer-limit");
  assert.ok(finding);
  assert.equal(finding.line, callbackLine);
  assert.match(finding.snippet, /p\.Authenticate\(writer, req\)/);
});

test("tracks a writer constructor and alias chain and reanchors exact Caddy callback evidence", async () => {
  const source = `package caddyauth
import (
  "bytes"
  "net/http"
)
type Authenticator interface { Authenticate(http.ResponseWriter, *http.Request) (bool, error) }
type Authentication struct { Providers map[string]Authenticator }
func (a Authentication) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  for _, prov := range a.Providers {
    var bw *bufferedResponseWriter
    var pw http.ResponseWriter = w
    bw = newBufferedResponseWriter(w)
    pw = bw
    _, _ = prov.Authenticate(pw, r)
  }
}
func newBufferedResponseWriter(w http.ResponseWriter) *bufferedResponseWriter {
  return &bufferedResponseWriter{header: make(http.Header)}
}
type bufferedResponseWriter struct {
  header http.Header
  statusCode int
  buf bytes.Buffer
}
func (bw *bufferedResponseWriter) Header() http.Header { return bw.header }
func (bw *bufferedResponseWriter) WriteHeader(statusCode int) { bw.statusCode = statusCode }
func (bw *bufferedResponseWriter) Write(data []byte) (int, error) {
  bw.WriteHeader(http.StatusOK)
  return bw.buf.Write(data)
}
`;
  const callbackLine = source.split("\n").findIndex((line) => line.includes("prov.Authenticate")) + 1;
  const result = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ path: "caddyauth.go", current: source, status: "modified", changedLines: new Set([callbackLine]) }],
  });
  const finding = result.signals.find((item) => item.ruleId === "go-http.provider-response-buffer-limit");
  assert.ok(finding);
  assert.equal(finding.line, callbackLine);
  assert.equal(finding.data.callbackVariable, "pw");
  assert.match(finding.snippet, /prov\.Authenticate\(pw, r\)/);

  for (const relationshipText of [
    "return &bufferedResponseWriter{header: make(http.Header)}",
    "bw = newBufferedResponseWriter(w)",
    "pw = bw",
  ]) {
    const relationshipLine = source.split("\n").findIndex((line) => line.includes(relationshipText)) + 1;
    const relationshipOnly = await analyzeDiscovery({
      mode: "diff",
      base: "main",
      files: [{ path: "caddyauth.go", current: source, status: "modified", changedLines: new Set([relationshipLine]) }],
    });
    const relationshipFinding = relationshipOnly.signals.find(
      (item) => item.ruleId === "go-http.provider-response-buffer-limit",
    );
    assert.ok(relationshipFinding);
    assert.equal(relationshipFinding.line, relationshipLine);
    assert.match(relationshipFinding.snippet, new RegExp(relationshipText.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("stays quiet when the writer enforces a hard cap", async () => {
  const output = await review("bounded", header + `
const maxProviderBody = 1 << 20
type bufferedWriter struct {
  header http.Header
  body bytes.Buffer
}
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) {
  if w.body.Len()+len(data) > maxProviderBody { return len(data), nil }
  return w.body.Write(data)
}
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{header: make(http.Header)}
  _ = p.Authenticate(writer, req)
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);
});

test("does not infer a cap from mutation that falls through without terminating the overflow path", async () => {
  const output = await review("truncated", header + `
const maxProviderBody = 1 << 20
type bufferedWriter struct {
  header http.Header
  body bytes.Buffer
}
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) {
  remaining := maxProviderBody - w.body.Len()
  if len(data) > remaining { data = data[:remaining] }
  return w.body.Write(data)
}
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{header: make(http.Header)}
  _ = p.Authenticate(writer, req)
}
`);
  assert.ok(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"));
});

test("accepts the exact Caddy inline room cap and early return", async () => {
  const output = await review("caddy-cap", header + `
const maxProviderBody = 1 << 20
type bufferedWriter struct {
  header http.Header
  body bytes.Buffer
}
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) {
  if room := maxProviderBody - w.body.Len(); room < len(data) {
    if room > 0 { w.body.Write(data[:room]) }
    return len(data), nil
  }
  return w.body.Write(data)
}
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{header: make(http.Header)}
  _ = p.Authenticate(writer, req)
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);
});

test("requires the cap guard on an unconditional top-level path before accumulation", async () => {
  const wrappers = [
    `if enforceLimit {
    if w.body.Len()+len(data) > maxProviderBody { return len(data), nil }
  }`,
    `for enforceLimit {
    if w.body.Len()+len(data) > maxProviderBody { return len(data), nil }
    break
  }`,
    `switch enforceLimit {
  case true:
    if w.body.Len()+len(data) > maxProviderBody { return len(data), nil }
  }`,
  ];
  for (const [index, guard] of wrappers.entries()) {
    const output = await review(`conditional-cap-${index}`, header + `
const maxProviderBody = 1 << 20
var enforceLimit bool
type bufferedWriter struct { header http.Header; body bytes.Buffer }
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) {
  ${guard}
  return w.body.Write(data)
}
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{}
  _ = p.Authenticate(writer, req)
}
`);
    assert.ok(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"));
  }
});

test("does not treat an internal response recorder as callback-controlled", async () => {
  const output = await review("internal", header + `
type responseRecorder struct {
  header http.Header
  body bytes.Buffer
}
func (w *responseRecorder) Header() http.Header { return w.header }
func (w *responseRecorder) WriteHeader(code int) {}
func (w *responseRecorder) Write(data []byte) (int, error) { return w.body.Write(data) }
func renderLocal() []byte {
  writer := &responseRecorder{header: make(http.Header)}
  _, _ = writer.Write([]byte("fixed"))
  return writer.body.Bytes()
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);
});

test("requires provider provenance instead of a generic callback-shaped method name", async () => {
  const output = await review("local-renderer", header + `
type bufferedWriter struct {
  header http.Header
  body bytes.Buffer
}
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
type renderer struct{}
func (renderer) Render(w http.ResponseWriter) { _, _ = w.Write([]byte("fixed")) }
func renderLocal() {
  writer := &bufferedWriter{header: make(http.Header)}
  renderer{}.Render(writer)
}
func renderThroughMisleadingName() {
  writer := &bufferedWriter{header: make(http.Header)}
  provider := renderer{}
  provider.Render(writer)
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);
});

test("does not associate allocation and callback across function scopes", async () => {
  const output = await review("cross-function", header + `
type bufferedWriter struct {
  header http.Header
  body bytes.Buffer
}
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
func construct() {
  writer := &bufferedWriter{header: make(http.Header)}
  _ = writer
}
func unrelated(p Provider, writer http.ResponseWriter, req *http.Request) {
  _ = p.Authenticate(writer, req)
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);
});

test("does not accept unrelated limiter calls or size branches as a buffer cap", async () => {
  const decoyHeader = `package middleware
import (
  "bytes"
  "io"
  "net/http"
  "strings"
)
type Provider interface { Authenticate(http.ResponseWriter, *http.Request) error }
`;
  const output = await review("decoy-bounds", decoyHeader + `
const maxHeaders = 10
type bufferedWriter struct {
  header http.Header
  body bytes.Buffer
  metadata []string
}
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) {
  _ = io.LimitReader(strings.NewReader("fixed"), 4)
  if len(w.metadata) > maxHeaders { return 0, nil }
  return w.body.Write(data)
}
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{header: make(http.Header)}
  _ = p.Authenticate(writer, req)
}
`);
  assert.ok(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"));
});

test("does not accept an inline room calculation that writes the full input", async () => {
  const output = await review("decoy-inline-cap", header + `
const maxProviderBody = 1 << 20
type bufferedWriter struct {
  header http.Header
  body bytes.Buffer
}
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) {
  if room := maxProviderBody - w.body.Len(); room < len(data) {
    w.body.Write(data)
    return len(data), nil
  }
  return w.body.Write(data)
}
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{header: make(http.Header)}
  _ = p.Authenticate(writer, req)
}
`);
  assert.ok(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"));
});

test("does not accept a nominal overflow rejection that writes the full payload", async () => {
  const output = await review("decoy-rejection", header + `
const maxProviderBody = 1 << 20
type bufferedWriter struct { header http.Header; body bytes.Buffer }
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) {
  if w.body.Len()+len(data) > maxProviderBody { return w.body.Write(data) }
  return w.body.Write(data)
}
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{header: make(http.Header)}
  _ = p.Authenticate(writer, req)
}
`);
  assert.ok(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"));
});

test("requires a sufficient overflow predicate and unconditional top-level return", async () => {
  const variants = [
    `if w.body.Len()+len(data) > maxProviderBody && allowTruncate {
  return len(data), nil
}`,
    `if w.body.Len()+len(data) > maxProviderBody {
  if allowTruncate { return len(data), nil }
}`,
    `if w.body.Len()+len(data) > maxProviderBody {
  func() { return }()
}`,
  ];
  for (const [index, branch] of variants.entries()) {
    const output = await review(`incomplete-cap-${index}`, header + `
const maxProviderBody = 1 << 20
var allowTruncate bool
type bufferedWriter struct { header http.Header; body bytes.Buffer }
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) {
  ${branch}
  return w.body.Write(data)
}
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{header: make(http.Header)}
  _ = p.Authenticate(writer, req)
}
`);
    assert.ok(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"));
  }
});

test("requires the real ResponseWriter method signatures and bytes.Buffer provenance", async () => {
  const fakeBuffer = await review("custom-buffer", `package middleware
import "net/http"
type Buffer struct{}
func (*Buffer) Write(data []byte) (int, error) { return len(data), nil }
type Provider interface { Authenticate(http.ResponseWriter) }
type bufferedWriter struct { header http.Header; body Buffer }
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
func run(p Provider) { writer := &bufferedWriter{}; p.Authenticate(writer) }
`);
  assert.equal(fakeBuffer.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);

  const fakeHTTP = await review("custom-http", `package middleware
import (
  "bytes"
  http "example.com/not-net-http"
)
type Provider interface { Authenticate(http.ResponseWriter) }
type bufferedWriter struct { header http.Header; body bytes.Buffer }
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
func run(p Provider) { writer := &bufferedWriter{}; p.Authenticate(writer) }
`);
  assert.equal(fakeHTTP.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);

  for (const malformed of [
    "func (w *bufferedWriter) Header() map[string][]string { return nil }",
    "func (w *bufferedWriter) WriteHeader(code string) {}",
    "func (w *bufferedWriter) Write(data string) (int, error) { return 0, nil }",
  ]) {
    const method = malformed.match(/bufferedWriter\) ([A-Za-z]+)/)?.[1];
    assert.ok(method);
    const source = unboundedSource.replace(
      new RegExp(`^func \\(w \\*bufferedWriter\\) ${method}.*$`, "m"),
      malformed,
    );
    const output = await review("bad-signature", source);
    assert.equal(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);
  }
});

test("binds accumulation to the actual bytes.Buffer field instead of the first declaration", async () => {
  const output = await review("multiple-buffers", header + `
type bufferedWriter struct {
  header http.Header
  scratch bytes.Buffer
  body bytes.Buffer
}
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{}
  _ = p.Authenticate(writer, req)
}
`);
  const finding = output.findings.find((item) => item.ruleId === "go-http.provider-response-buffer-limit");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.data?.bufferField, "body");
});

test("does not infer callback provenance from a Provider-looking type name", async () => {
  const output = await review("provider-name-only", `package middleware
import (
  "bytes"
  "net/http"
)
type Provider struct{}
func (Provider) Authenticate(any) {}
type bufferedWriter struct { header http.Header; body bytes.Buffer }
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
func run(p Provider) { writer := &bufferedWriter{}; p.Authenticate(writer) }
`);
  assert.equal(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);
});

test("maps the passed writer to the exact ResponseWriter parameter position", async () => {
  const wrapper = `
type bufferedWriter struct { header http.Header; body bytes.Buffer }
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
`;
  const cases = [
    `type Provider interface { Authenticate(any) http.ResponseWriter }
func run(p Provider) { writer := &bufferedWriter{}; _ = p.Authenticate(writer) }`,
    `type Provider interface { Writer(http.ResponseWriter); Authenticate(any) }
func run(p Provider) { writer := &bufferedWriter{}; p.Authenticate(writer) }`,
    `type Provider interface { Authenticate(http.ResponseWriter, any) }
func run(p Provider) { writer := &bufferedWriter{}; p.Authenticate(nil, writer) }`,
  ];
  for (const [index, callback] of cases.entries()) {
    const output = await review(`wrong-callback-slot-${index}`, `package middleware
import ("bytes"; "net/http")
${wrapper}
${callback}
`);
    assert.equal(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"), false);
  }

  const positive = await review("callback-second-slot", `package middleware
import ("bytes"; "net/http")
${wrapper}
type Provider interface { Authenticate(*http.Request, http.ResponseWriter) }
func run(p Provider, req *http.Request) { writer := &bufferedWriter{}; p.Authenticate(req, writer) }
`);
  assert.ok(positive.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"));
});

test("nearby bound-looking identifiers do not suppress concrete unbounded dataflow", async () => {
  const output = await review("lexical-bound-noise", header + `
var bounded = response.bytes
type bufferedWriter struct { header http.Header; body bytes.Buffer }
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
func run(p Provider, req *http.Request) {
  writer := &bufferedWriter{}
  _ = p.Authenticate(writer, req)
}
`);
  assert.ok(output.findings.some((item) => item.ruleId === "go-http.provider-response-buffer-limit"));
});

test("evaluates every valid callback use independently for changed-line locality", async () => {
  const source = header + `
type bufferedWriter struct { header http.Header; body bytes.Buffer }
func (w *bufferedWriter) Header() http.Header { return w.header }
func (w *bufferedWriter) WriteHeader(code int) {}
func (w *bufferedWriter) Write(data []byte) (int, error) { return w.body.Write(data) }
func run(first Provider, second Provider, req *http.Request) {
  firstWriter := &bufferedWriter{}
  _ = first.Authenticate(firstWriter, req)
  secondWriter := &bufferedWriter{}
  _ = second.Authenticate(secondWriter, req)
}
`;
  const secondLine = source.split("\n").findIndex((line) => line.includes("second.Authenticate")) + 1;
  const result = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ path: "middleware.go", current: source, status: "modified", changedLines: new Set([secondLine]) }],
  });
  const findings = result.signals.filter((item) => item.ruleId === "go-http.provider-response-buffer-limit");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.line, secondLine);
  assert.equal(findings[0]?.data?.callbackVariable, "secondWriter");
  assert.match(findings[0]?.snippet ?? "", /second\.Authenticate/);
});

test("detects the exact Caddy pre-fix provider buffering source shape", async () => {
  const output = await review("caddy-source", `package caddyauth
import (
  "bytes"
  "net/http"
)
type Authenticator interface { Authenticate(http.ResponseWriter, *http.Request) (bool, error) }
type Authentication struct { Providers map[string]Authenticator }
func (a Authentication) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  for _, prov := range a.Providers {
    var bw *bufferedResponseWriter
    var pw http.ResponseWriter = w
    bw = newBufferedResponseWriter(w)
    pw = bw
    _, _ = prov.Authenticate(pw, r)
  }
}
func newBufferedResponseWriter(w http.ResponseWriter) *bufferedResponseWriter {
  return &bufferedResponseWriter{header: make(http.Header)}
}
type bufferedResponseWriter struct {
  header http.Header
  statusCode int
  buf bytes.Buffer
}
func (bw *bufferedResponseWriter) Header() http.Header { return bw.header }
func (bw *bufferedResponseWriter) WriteHeader(statusCode int) { bw.statusCode = statusCode }
func (bw *bufferedResponseWriter) Write(data []byte) (int, error) {
  bw.WriteHeader(http.StatusOK)
  return bw.buf.Write(data)
}
`);
  const finding = output.findings.find((item) => item.ruleId === "go-http.provider-response-buffer-limit");
  assert.ok(finding);
  assert.equal(finding.evidence[0]?.data?.callbackMethod, "Authenticate");
  assert.equal(finding.evidence[0]?.data?.callbackVariable, "pw");
});

test("prompt requires both callback and accumulation evidence and preserves quiet cases", () => {
  assert.match(GO_HTTP_MODEL_PROMPT, /cite both the callback boundary and accumulation/);
  assert.match(GO_HTTP_MODEL_PROMPT, /hard output cap is established in prepared source/);
  assert.match(GO_HTTP_MODEL_PROMPT, /ordinary streaming to the real ResponseWriter/);
});
