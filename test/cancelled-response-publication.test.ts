import assert from "node:assert/strict";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";
import { GO_HTTP_MODEL_PROMPT } from "../src/model-review.ts";

const ruleId = "go-http.cancelled-response-publication";

const connectPrefix = `package connect
import (
  "context"
  "net/http"
)
type duplexHTTPCall struct {
  ctx context.Context
  httpClient *http.Client
  responseReady chan struct{}
  response *http.Response
  responseErr error
}
func (d *duplexHTTPCall) start() { go d.makeRequest() }
func (d *duplexHTTPCall) makeRequest() {
  defer close(d.responseReady)
  response, err := d.httpClient.Do(nil)
  if err != nil { d.responseErr = err; return }
  d.response = response
}
`;

const vulnerable = connectPrefix + `
func (d *duplexHTTPCall) BlockUntilResponseReady() error {
  select {
  case <-d.responseReady:
    return d.responseErr
  case <-d.ctx.Done():
    return d.ctx.Err()
  }
}
func (d *duplexHTTPCall) CloseRead() error {
  _ = d.BlockUntilResponseReady()
  if d.response == nil { return nil }
  return d.response.Body.Close()
}
`;

function repository(source: string) {
  return analyzeDiscovery({
    mode: "repository",
    files: [{ path: "duplex_http_call.go", current: source, status: "repository", changedLines: new Set() }],
  });
}

function lineOf(source: string, text: string): number {
  return source.split("\n").findIndex((line) => line.includes(text)) + 1;
}

test("reports the exact Connect pre-fix publication/cancellation ownership chain", async () => {
  const result = await repository(vulnerable);
  const signal = result.signals.find((item) => item.ruleId === ruleId);
  assert.ok(signal, JSON.stringify(result.signals, null, 2));
  assert.equal(signal.data.ownerType, "duplexHTTPCall");
  assert.equal(signal.data.responseField, "response");
  assert.equal(signal.data.completionField, "responseReady");
  assert.equal(signal.data.producer, "makeRequest");
  assert.equal(signal.data.waiter, "BlockUntilResponseReady");
  assert.equal(signal.data.responseOwner, "CloseRead");
});

test("accepts the reviewed Connect wrapper that re-observes completion before response ownership", async () => {
  const fixed = connectPrefix + `
func (d *duplexHTTPCall) BlockUntilResponseReady() error {
  select {
  case <-d.responseReady:
    return d.responseErr
  case <-d.ctx.Done():
    return d.ctx.Err()
  }
}
func (d *duplexHTTPCall) responseAfterReady() *http.Response {
  _ = d.BlockUntilResponseReady()
  <-d.responseReady
  return d.response
}
func (d *duplexHTTPCall) Read(data []byte) (int, error) {
  if err := d.BlockUntilResponseReady(); err != nil { return 0, err }
  return d.response.Body.Read(data)
}
func (d *duplexHTTPCall) CloseRead() error {
  response := d.responseAfterReady()
  if response == nil { return nil }
  return response.Body.Close()
}
`;
  const result = await repository(fixed);
  assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
});

test("accepts a cancellation arm that synchronizes with completion before ownership", async () => {
  const fixed = connectPrefix + `
func (d *duplexHTTPCall) BlockUntilResponseReady() (*http.Response, error) {
  select {
  case <-d.responseReady:
    return d.response, d.responseErr
  case <-d.ctx.Done():
    <-d.responseReady
    return d.response, d.responseErr
  }
}
func (d *duplexHTTPCall) CloseRead() error {
  response, _ := d.BlockUntilResponseReady()
  if response == nil { return nil }
  return response.Body.Close()
}
`;
  const result = await repository(fixed);
  assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
});

test("requires typed HTTP ownership, ordered asynchronous publication, and a real body owner", async () => {
  const variants = [
    vulnerable.replace("response *http.Response", "response *result").replace("type duplexHTTPCall struct {", "type result struct { Body interface{ Close() error } }\ntype duplexHTTPCall struct {"),
    vulnerable.replace("func (d *duplexHTTPCall) start() { go d.makeRequest() }", "func (d *duplexHTTPCall) start() { d.makeRequest() }"),
    vulnerable.replace("d.response = response", "close(d.responseReady)\n  d.response = response").replace("defer close(d.responseReady)\n", ""),
    vulnerable.replace("return d.response.Body.Close()", "return nil"),
    vulnerable.replace("case <-d.responseReady:", "case <-d.otherReady:").replace("responseReady chan struct{}", "responseReady chan struct{}\n  otherReady chan struct{}"),
  ];
  for (const [index, source] of variants.entries()) {
    const result = await repository(source);
    assert.equal(
      result.signals.some((item) => item.ruleId === ruleId),
      false,
      `variant ${index}: ${JSON.stringify(result.signals, null, 2)}`,
    );
  }
});

test("accepts producer-owned cleanup and synchronized cancellation cleanup", async () => {
  const producerClose = vulnerable.replace("d.response = response", "d.response = response\n  d.response.Body.Close() // producer retains ownership");
  const synchronizedClose = vulnerable.replace(
    "case <-d.ctx.Done():\n    return d.ctx.Err()",
    "case <-d.ctx.Done():\n    <-d.responseReady\n    d.response.Body.Close()\n    return d.ctx.Err()",
  );
  for (const source of [producerClose, synchronizedClose]) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }
});

test("does not mistake unsynchronized cleanup or a competing nested select for ownership", async () => {
  const variants = [
    vulnerable.replace(
      "case <-d.ctx.Done():\n    return d.ctx.Err()",
      "case <-d.ctx.Done():\n    d.response.Body.Close()\n    return d.ctx.Err()",
    ),
    vulnerable.replace(
      "case <-d.ctx.Done():\n    return d.ctx.Err()",
      "case <-d.ctx.Done():\n    select { case <-d.responseReady: case <-otherReady(): }\n    return d.ctx.Err()",
    ),
    vulnerable.replace(
      "case <-d.ctx.Done():\n    return d.ctx.Err()",
      "case <-d.ctx.Done():\n    if shouldAbort() { return d.ctx.Err() }\n    <-d.responseReady\n    return nil",
    ),
    vulnerable
      .replace("func (d *duplexHTTPCall) BlockUntilResponseReady() error", "func (d *duplexHTTPCall) BlockUntilResponseReady() (*http.Response, error)")
      .replace("return d.responseErr", "return d.response, d.responseErr")
      .replace("return d.ctx.Err()", "return d.response, d.ctx.Err()")
      .replace("_ = d.BlockUntilResponseReady()", "_, _ = d.BlockUntilResponseReady()"),
  ];
  for (const source of variants) {
    const result = await repository(source);
    assert.ok(result.signals.some((item) => item.ruleId === ruleId), JSON.stringify(result.signals, null, 2));
  }
});

test("requires imported context.Context provenance for Done", async () => {
  const fake = vulnerable
    .replace('  "context"\n', "")
    .replace("type duplexHTTPCall struct {", "type stopper struct { ch chan struct{} }\nfunc (s *stopper) Done() <-chan struct{} { return s.ch }\ntype duplexHTTPCall struct {")
    .replace("ctx context.Context", "ctx *stopper")
    .replace("return d.ctx.Err()", "return nil");
  const result = await repository(fake);
  assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
});

test("follows a simple waiter wrapper to the response body owner", async () => {
  const wrapped = vulnerable.replace(
    `func (d *duplexHTTPCall) CloseRead() error {
  _ = d.BlockUntilResponseReady()
  if d.response == nil { return nil }
  return d.response.Body.Close()
}`,
    `func (d *duplexHTTPCall) responseAfterWait() *http.Response { _ = d.BlockUntilResponseReady(); return d.response }
func (d *duplexHTTPCall) CloseRead() error {
  response := d.responseAfterWait()
  if response == nil { return nil }
  return response.Body.Close()
}`,
  );
  const result = await repository(wrapped);
  assert.ok(result.signals.some((item) => item.ruleId === ruleId), JSON.stringify(result.signals, null, 2));
});

test("requires reachable producer signalling and body ownership", async () => {
  const variants = [
    vulnerable.replace("func (d *duplexHTTPCall) start() { go d.makeRequest() }", "func (d *duplexHTTPCall) start() { if false { go d.makeRequest() } }"),
    vulnerable.replace("defer close(d.responseReady)", "if false { defer close(d.responseReady) }"),
    vulnerable.replace("_ = d.BlockUntilResponseReady()", "_ = d.BlockUntilResponseReady()\n  return nil"),
  ];
  for (const source of variants) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }
});

test("recognizes reachable nested producer starts without reviving statically dead blocks", async () => {
  const reachable = [
    vulnerable.replace(
      "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
      "func (d *duplexHTTPCall) start() { if true { go d.makeRequest() } }",
    ),
    vulnerable.replace(
      "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
      "func (d *duplexHTTPCall) start() { if panic := func(any) {}; true { _ = panic; go d.makeRequest() } }",
    ),
    vulnerable.replace(
      "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
      "func (d *duplexHTTPCall) start() { if panic := func(any) {}; true { panic(\"continue\"); go d.makeRequest() } }",
    ),
    vulnerable.replace(
      "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
      "func (d *duplexHTTPCall) start() { switch true { case true: go d.makeRequest() } }",
    ),
  ];
  for (const source of reachable) {
    const result = await repository(source);
    assert.ok(result.signals.some((item) => item.ruleId === ruleId), JSON.stringify(result.signals, null, 2));
  }

  const deadElse = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { if (true) { return } else { go d.makeRequest() } }",
  );
  const deadConsequence = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { if (false) { go d.makeRequest() } }",
  );
  const deadSwitchCase = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { switch false { case true: go d.makeRequest() } }",
  );
  for (const source of [deadElse, deadConsequence, deadSwitchCase]) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }
});

test("requires executable producer calls and accepts bounded cancellation synchronization", async () => {
  const inertNestedClosure = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { go func() { _ = func() { d.makeRequest() } }() }",
  );
  assert.equal((await repository(inertNestedClosure)).signals.some((item) => item.ruleId === ruleId), false);
  const deadInvokedProducer = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { go func() { if false { d.makeRequest() } }() }",
  );
  assert.equal((await repository(deadInvokedProducer)).signals.some((item) => item.ruleId === ruleId), false);

  const invokedProducerClosures = [
    vulnerable.replace(
      "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
      "func (d *duplexHTTPCall) start() { go func() { d.makeRequest() }() }",
    ),
    vulnerable.replace(
      "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
      "func (d *duplexHTTPCall) start() { go func() { func() { d.makeRequest() }() }() }",
    ),
  ];
  for (const source of invokedProducerClosures) {
    assert.ok((await repository(source)).signals.some((item) => item.ruleId === ruleId));
  }

  const cancellationIIFE = vulnerable.replace(
    "case <-d.ctx.Done():\n    return d.ctx.Err()",
    "case <-d.ctx.Done():\n    func() { <-d.responseReady }()\n    return d.ctx.Err()",
  );
  const cancellationHelper = vulnerable
    .replace(
      "func (d *duplexHTTPCall) BlockUntilResponseReady() error {",
      "func (d *duplexHTTPCall) awaitLate() { <-d.responseReady }\nfunc (d *duplexHTTPCall) BlockUntilResponseReady() error {",
    )
    .replace(
      "case <-d.ctx.Done():\n    return d.ctx.Err()",
      "case <-d.ctx.Done():\n    d.awaitLate()\n    return d.ctx.Err()",
    );
  for (const source of [cancellationIIFE, cancellationHelper]) {
    assert.equal((await repository(source)).signals.some((item) => item.ruleId === ruleId), false);
  }

  const conditionalHelper = cancellationHelper.replace(
    "func (d *duplexHTTPCall) awaitLate() { <-d.responseReady }",
    "func (d *duplexHTTPCall) awaitLate() { if shouldWait() { <-d.responseReady } }",
  );
  const competingIIFE = vulnerable.replace(
    "case <-d.ctx.Done():\n    return d.ctx.Err()",
    "case <-d.ctx.Done():\n    func() { select { case <-d.responseReady: case <-otherReady(): } }()\n    return d.ctx.Err()",
  );
  const asyncIIFE = vulnerable.replace(
    "case <-d.ctx.Done():\n    return d.ctx.Err()",
    "case <-d.ctx.Done():\n    func() { go func() { <-d.responseReady }() }()\n    return d.ctx.Err()",
  );
  const deferredIIFE = vulnerable.replace(
    "case <-d.ctx.Done():\n    return d.ctx.Err()",
    "case <-d.ctx.Done():\n    func() { defer func() { <-d.responseReady }() }()\n    return d.ctx.Err()",
  );
  for (const [index, source] of [conditionalHelper, competingIIFE, asyncIIFE, deferredIIFE].entries()) {
    assert.ok((await repository(source)).signals.some((item) => item.ruleId === ruleId), `unsafe synchronization ${index}`);
  }

  const conditionalOwner = vulnerable.replace(
    "if d.response == nil { return nil }\n  return d.response.Body.Close()",
    "if d.response != nil && shouldClose() { return d.response.Body.Close() }\n  return nil",
  );
  assert.ok((await repository(conditionalOwner)).signals.some((item) => item.ruleId === ruleId));
});

test("binds synchronization and ownership to all-path receiver and import provenance", async () => {
  const parenthesizedIIFE = vulnerable.replace(
    "case <-d.ctx.Done():\n    return d.ctx.Err()",
    "case <-d.ctx.Done():\n    (func() { <-d.responseReady })()\n    return d.ctx.Err()",
  );
  const iifeHelper = vulnerable
    .replace(
      "func (d *duplexHTTPCall) BlockUntilResponseReady() error {",
      "func (d *duplexHTTPCall) awaitLate() { <-d.responseReady }\nfunc (d *duplexHTTPCall) BlockUntilResponseReady() error {",
    )
    .replace(
      "case <-d.ctx.Done():\n    return d.ctx.Err()",
      "case <-d.ctx.Done():\n    func() { d.awaitLate() }()\n    return d.ctx.Err()",
    );
  for (const source of [parenthesizedIIFE, iifeHelper]) {
    assert.equal((await repository(source)).signals.some((item) => item.ruleId === ruleId), false);
  }

  const conditionalReturn = iifeHelper
    .replace("func (d *duplexHTTPCall) awaitLate() { <-d.responseReady }", "func (d *duplexHTTPCall) awaitLate() { if skip() { return }; <-d.responseReady }")
    .replace("func() { d.awaitLate() }()", "d.awaitLate()");
  const bypassingGoto = conditionalReturn.replace(
    "if skip() { return }; <-d.responseReady",
    "goto done; <-d.responseReady; done:",
  );
  const reassignedHelper = conditionalReturn.replace(
    "if skip() { return }; <-d.responseReady",
    "d = otherCall; <-d.responseReady",
  ).replace("type duplexHTTPCall struct {", "var otherCall *duplexHTTPCall\n\ntype duplexHTTPCall struct {");
  const reassignedStart = vulnerable
    .replace("type duplexHTTPCall struct {", "var otherCall *duplexHTTPCall\n\ntype duplexHTTPCall struct {")
    .replace("func (d *duplexHTTPCall) start() { go d.makeRequest() }", "func (d *duplexHTTPCall) start() { d = otherCall; go d.makeRequest() }");
  const conditionalReassignedStart = reassignedStart.replace("d = otherCall;", "if replace() { d = otherCall };");
  const rangedStart = reassignedStart.replace(
    "d = otherCall; go d.makeRequest()",
    "for _, d := range []*duplexHTTPCall{otherCall} { go d.makeRequest() }",
  );
  for (const source of [conditionalReturn, bypassingGoto, reassignedHelper]) {
    assert.ok((await repository(source)).signals.some((item) => item.ruleId === ruleId));
  }
  for (const source of [reassignedStart, conditionalReassignedStart, rangedStart]) {
    assert.equal((await repository(source)).signals.some((item) => item.ruleId === ruleId), false);
  }
  const siblingShadowStart = reassignedStart.replace(
    "d = otherCall; go d.makeRequest()",
    "{ d := otherCall; _ = d }; go d.makeRequest()",
  );
  assert.ok((await repository(siblingShadowStart)).signals.some((item) => item.ruleId === ruleId));

  const competingCallerSelect = vulnerable.replace(
    "_ = d.BlockUntilResponseReady()\n  if d.response == nil",
    "_ = d.BlockUntilResponseReady()\n  select { case <-d.responseReady: case <-otherReady(): }\n  if d.response == nil",
  );
  assert.ok((await repository(competingCallerSelect)).signals.some((item) => item.ruleId === ruleId));

  const shadowedOwner = vulnerable
    .replace("type duplexHTTPCall struct {", "var otherCall *duplexHTTPCall\n\ntype duplexHTTPCall struct {")
    .replace(
      "if d.response == nil { return nil }\n  return d.response.Body.Close()",
      "if closeNow() { d := otherCall; return d.response.Body.Close() }\n  return nil",
    );
  const reassignedOwner = shadowedOwner.replace("d := otherCall", "d = otherCall");
  const rangedOwner = shadowedOwner.replace(
    "if closeNow() { d := otherCall; return d.response.Body.Close() }",
    "for _, d := range []*duplexHTTPCall{otherCall} { return d.response.Body.Close() }",
  );
  for (const source of [shadowedOwner, reassignedOwner, rangedOwner]) {
    assert.equal((await repository(source)).signals.some((item) => item.ruleId === ruleId), false);
  }

  const shadowedIO = vulnerable
    .replace('  "net/http"', '  "net/http"\n  "io"')
    .replace("type duplexHTTPCall struct {", "type fakeIO struct{}\nfunc (fakeIO) ReadAll(any) ([]byte, error) { return nil, nil }\nvar _ io.Reader\n\ntype duplexHTTPCall struct {")
    .replace(
      "if d.response == nil { return nil }\n  return d.response.Body.Close()",
      "io := fakeIO{}\n  _, err := io.ReadAll(d.response.Body)\n  return err",
    );
  assert.equal((await repository(shadowedIO)).signals.some((item) => item.ruleId === ruleId), false);
});

test("a changed nested owner guard is eligible semantic evidence", async () => {
  const previous = vulnerable.replace(
    "if d.response == nil { return nil }\n  return d.response.Body.Close()",
    "if false { return d.response.Body.Close() }\n  return nil",
  );
  const current = previous.replace("if false {", "if shouldClose() {");
  const guardLine = lineOf(current, "if shouldClose()");
  const result = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "duplex_http_call.go",
      current,
      previous,
      status: "modified",
      changedLines: new Set([guardLine]),
    }],
  });
  const signal = result.signals.find((item) => item.ruleId === ruleId);
  assert.ok(signal, JSON.stringify(result.signals, null, 2));
  assert.equal(signal.line, guardLine);
});

test("strings cannot fake producer cleanup or a response owner", async () => {
  const fakeCleanup = vulnerable.replace("d.response = response", 'd.response = response\n  log.Print("d.response.Body.Close()")');
  const fakeOwner = vulnerable.replace("if d.response == nil { return nil }\n  return d.response.Body.Close()", 'log.Print("d.response.Body.Close()")\n  return nil');
  assert.ok((await repository(fakeCleanup)).signals.some((item) => item.ruleId === ruleId));
  assert.equal((await repository(fakeOwner)).signals.some((item) => item.ruleId === ruleId), false);
});

test("does not let comments, closures, branches, or conditional producer cleanup fake the proof", async () => {
  const commentDoesNotDrain = vulnerable.replace(
    "return d.ctx.Err()",
    "// later: <-d.responseReady; d.response.Body.Close()\n    return d.ctx.Err()",
  );
  const closureDoesNotDrain = vulnerable.replace(
    "return d.ctx.Err()",
    "_ = func() { <-d.responseReady }\n    return d.ctx.Err()",
  );
  const conditionalProducerClose = vulnerable.replace(
    "d.response = response",
    "d.response = response\n  if d.ctx.Err() != nil { d.response.Body.Close() }",
  );
  const conditionalCancellationClose = vulnerable.replace(
    "return d.ctx.Err()",
    "if false { d.response.Body.Close() }\n    return d.ctx.Err()",
  );
  for (const source of [commentDoesNotDrain, closureDoesNotDrain, conditionalProducerClose, conditionalCancellationClose]) {
    const result = await repository(source);
    assert.ok(result.signals.some((item) => item.ruleId === ruleId), JSON.stringify(result.signals, null, 2));
  }

  const mutuallyExclusiveOwner = vulnerable.replace(
    `_ = d.BlockUntilResponseReady()
  if d.response == nil { return nil }
  return d.response.Body.Close()`,
    `if shouldWait() {
    _ = d.BlockUntilResponseReady()
  } else {
    return d.response.Body.Close()
  }
  return nil`,
  );
  const result = await repository(mutuallyExclusiveOwner);
  assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
});

test("rejects nil publication and mutually exclusive publication/signal branches", async () => {
  const nilPublication = vulnerable.replace("d.response = response", "d.response = nil");
  const splitBranches = vulnerable
    .replace("defer close(d.responseReady)\n", "")
    .replace("d.response = response", "if response != nil {\n    d.response = response\n  } else {\n    close(d.responseReady)\n  }");
  for (const source of [nilPublication, splitBranches]) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }
});

test("accepts a direct caller synchronization before closing the published body", async () => {
  const fixed = vulnerable.replace(
    `_ = d.BlockUntilResponseReady()
  if d.response == nil { return nil }`,
    `_ = d.BlockUntilResponseReady()
  <-d.responseReady
  if d.response == nil { return nil }`,
  );
  const result = await repository(fixed);
  assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
});

test("diff locality accepts only the ownership relationship and ignores unrelated or comment-only edits", async () => {
  const semanticLines = [
    lineOf(vulnerable, "responseReady chan struct{}"),
    lineOf(vulnerable, "response *http.Response"),
    lineOf(vulnerable, "go d.makeRequest()"),
    lineOf(vulnerable, "d.response = response"),
    lineOf(vulnerable, "defer close(d.responseReady)"),
    lineOf(vulnerable, "case <-d.ctx.Done()"),
    lineOf(vulnerable, "return d.ctx.Err()"),
    lineOf(vulnerable, "d.BlockUntilResponseReady()"),
    lineOf(vulnerable, "d.response.Body.Close()"),
  ];
  for (const changedLine of semanticLines) {
    const result = await analyzeDiscovery({
      mode: "diff",
      base: "main",
      files: [{ path: "duplex_http_call.go", current: vulnerable, status: "modified", changedLines: new Set([changedLine]) }],
    });
    const signal = result.signals.find((item) => item.ruleId === ruleId);
    assert.ok(signal, `semantic line ${changedLine}: ${JSON.stringify(result.signals, null, 2)}`);
    assert.equal(signal.line, changedLine);
  }

  const withNoise = vulnerable.replace(
    "return d.ctx.Err()",
    "// d.responseReady d.response.Body.Close()\n    return d.ctx.Err()",
  ) + "\nfunc unrelated() {}\n";
  for (const changedLine of [lineOf(withNoise, "// d.responseReady"), lineOf(withNoise, "func unrelated")]) {
    const result = await analyzeDiscovery({
      mode: "diff",
      base: "main",
      files: [{ path: "duplex_http_call.go", current: withNoise, status: "modified", changedLines: new Set([changedLine]) }],
    });
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }

  const commentOnly = vulnerable.replace("response *http.Response", "response *http.Response // documentation");
  const result = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "duplex_http_call.go",
      current: commentOnly,
      previous: vulnerable,
      status: "modified",
      changedLines: new Set([lineOf(commentOnly, "// documentation")]),
    }],
  });
  assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));

  const multilineComment = vulnerable.replace(
    "return d.response.Body.Close()",
    "return d.response.Body.Close(/* documentation\n    only */)",
  );
  const commentLines = new Set([
    lineOf(multilineComment, "/* documentation"),
    lineOf(multilineComment, "only */"),
  ]);
  const multilineResult = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "duplex_http_call.go",
      current: multilineComment,
      previous: vulnerable,
      status: "modified",
      changedLines: commentLines,
    }],
  });
  assert.equal(
    multilineResult.signals.some((item) => item.ruleId === ruleId),
    false,
    JSON.stringify(multilineResult.signals, null, 2),
  );

  const mixedCommentReflow = multilineComment.replace("type duplexHTTPCall struct {", "var unrelated = 1\n\ntype duplexHTTPCall struct {");
  const mixedResult = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "duplex_http_call.go",
      current: mixedCommentReflow,
      previous: vulnerable,
      status: "modified",
      changedLines: new Set([
        lineOf(mixedCommentReflow, "var unrelated"),
        lineOf(mixedCommentReflow, "/* documentation"),
        lineOf(mixedCommentReflow, "only */"),
      ]),
    }],
  });
  assert.equal(
    mixedResult.signals.some((item) => item.ruleId === ruleId),
    false,
    JSON.stringify(mixedResult.signals, null, 2),
  );

  const changedConsumer = vulnerable.replace("d.response.Body.Close()", "d.response.Body.Read(nil)");
  const changedConsumerResult = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "duplex_http_call.go",
      current: changedConsumer,
      previous: vulnerable,
      status: "modified",
      changedLines: new Set([lineOf(changedConsumer, "d.response.Body.Read(nil)")]),
    }],
  });
  const changedConsumerSignal = changedConsumerResult.signals.find((item) => item.ruleId === ruleId);
  assert.ok(changedConsumerSignal, JSON.stringify(changedConsumerResult.signals, null, 2));
  assert.equal(changedConsumerSignal.line, lineOf(changedConsumer, "d.response.Body.Read(nil)"));
});

test("normalizes parenthesized expressions and requires every ownership-chain step to be reachable", async () => {
  const variants = [
    vulnerable.replace("d.response = response", "d.response = (nil)"),
    vulnerable.replace("func (d *duplexHTTPCall) start() { go d.makeRequest() }", "func (d *duplexHTTPCall) start() { return; go d.makeRequest() }"),
    vulnerable.replace("func (d *duplexHTTPCall) BlockUntilResponseReady() error {\n  select {", "func (d *duplexHTTPCall) BlockUntilResponseReady() error {\n  return nil\n  select {"),
    vulnerable.replace("func (d *duplexHTTPCall) CloseRead() error {\n  _ = d.BlockUntilResponseReady()", "func (d *duplexHTTPCall) CloseRead() error {\n  return nil\n  _ = d.BlockUntilResponseReady()"),
    vulnerable.replace("d.response = response", "d.response = response\n  d.response = nil"),
  ];
  for (const source of variants) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }

  const unreachableCleanup = vulnerable.replace(
    "d.response = response",
    "d.response = response\n  return\n  d.response.Body.Close()",
  );
  assert.ok((await repository(unreachableCleanup)).signals.some((item) => item.ruleId === ruleId));
});

test("unconditional builtin panic and goto make chain nodes unreachable", async () => {
  const absentChains = [
    vulnerable.replace(
      "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
      "func (d *duplexHTTPCall) start() { panic(\"stop\"); go d.makeRequest() }",
    ),
    vulnerable.replace(
      "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
      "func (d *duplexHTTPCall) start() { goto done; go d.makeRequest(); done: }",
    ),
    vulnerable.replace(
      "func (d *duplexHTTPCall) BlockUntilResponseReady() error {\n  select {",
      "func (d *duplexHTTPCall) BlockUntilResponseReady() error {\n  panic(\"stop\")\n  select {",
    ),
    vulnerable.replace(
      "func (d *duplexHTTPCall) BlockUntilResponseReady() error {\n  select {",
      "func (d *duplexHTTPCall) BlockUntilResponseReady() error {\n  goto done\n  select {",
    ).replace("\n}\nfunc (d *duplexHTTPCall) CloseRead()", "\ndone:\n  return nil\n}\nfunc (d *duplexHTTPCall) CloseRead()"),
    vulnerable.replace(
      "func (d *duplexHTTPCall) CloseRead() error {\n  _ = d.BlockUntilResponseReady()",
      "func (d *duplexHTTPCall) CloseRead() error {\n  panic(\"stop\")\n  _ = d.BlockUntilResponseReady()",
    ),
    vulnerable.replace(
      "func (d *duplexHTTPCall) CloseRead() error {\n  _ = d.BlockUntilResponseReady()",
      "func (d *duplexHTTPCall) CloseRead() error {\n  goto done\n  _ = d.BlockUntilResponseReady()",
    ).replace("  return d.response.Body.Close()\n}", "  return d.response.Body.Close()\ndone:\n  return nil\n}"),
  ];
  for (const source of absentChains) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result, null, 2));
  }

  const localShadow = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { panic := func(any) {}; panic(\"continue\"); go d.makeRequest() }",
  );
  const packageShadow = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { panic(\"continue\"); go d.makeRequest() }",
  ) + "\nvar panic = func(any) {}\n";
  for (const source of [localShadow, packageShadow]) {
    assert.ok((await repository(source)).signals.some((item) => item.ruleId === ruleId));
  }

  const gotoTargetIsChain = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { goto launch; launch: go d.makeRequest() }",
  );
  const conditionalPanic = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { if shouldStop() { panic(\"stop\") }; go d.makeRequest() }",
  );
  for (const source of [gotoTargetIsChain, conditionalPanic]) {
    assert.ok((await repository(source)).signals.some((item) => item.ruleId === ruleId));
  }
});

test("unreachable cleanup inside a synchronous cancellation helper does not prove ownership", async () => {
  const helpers = [
    "func (d *duplexHTTPCall) drainLate() { <-d.responseReady; panic(\"stop\"); d.response.Body.Close() }",
    "func (d *duplexHTTPCall) drainLate() { <-d.responseReady; goto done; d.response.Body.Close(); done: }",
  ];
  for (const helper of helpers) {
    const source = vulnerable
      .replace(
        "func (d *duplexHTTPCall) BlockUntilResponseReady() error {",
        `${helper}\nfunc (d *duplexHTTPCall) BlockUntilResponseReady() error {`,
      )
      .replace(
        "case <-d.ctx.Done():\n    return d.ctx.Err()",
        "case <-d.ctx.Done():\n    d.drainLate()\n    return d.ctx.Err()",
      );
    assert.ok((await repository(source)).signals.some((item) => item.ruleId === ruleId));
  }
});

test("requires builtin and standard-library provenance for signal and body-consumer calls", async () => {
  const shadowedClose = vulnerable.replace(
    "type duplexHTTPCall struct {",
    "func close(chan struct{}) {}\n\ntype duplexHTTPCall struct {",
  );
  const fakeReadAll = vulnerable
    .replace("type duplexHTTPCall struct {", "type reader struct{}\nfunc (reader) ReadAll(any) error { return nil }\nvar fake reader\n\ntype duplexHTTPCall struct {")
    .replace("return d.response.Body.Close()", "return fake.ReadAll(d.response.Body)");
  for (const source of [shadowedClose, fakeReadAll]) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }

  const standardReadAll = vulnerable
    .replace('  "net/http"', '  "net/http"\n  "io"')
    .replace("return d.response.Body.Close()", "_, err := io.ReadAll(d.response.Body); return err");
  assert.ok((await repository(standardReadAll)).signals.some((item) => item.ruleId === ruleId));
});

test("accepts synchronous producer and cancellation cleanup through bounded direct calls", async () => {
  const producerIIFE = vulnerable.replace(
    "d.response = response",
    "d.response = response\n  func() { d.response.Body.Close() }()",
  );
  const cancellationHelper = vulnerable
    .replace(
      "func (d *duplexHTTPCall) BlockUntilResponseReady() error {",
      "func (d *duplexHTTPCall) drainLate() { <-d.responseReady; if d.response != nil { d.response.Body.Close() } }\nfunc (d *duplexHTTPCall) BlockUntilResponseReady() error {",
    )
    .replace("case <-d.ctx.Done():\n    return d.ctx.Err()", "case <-d.ctx.Done():\n    d.drainLate()\n    return d.ctx.Err()");
  const parenthesizedDrain = vulnerable.replace(
    "case <-d.ctx.Done():\n    return d.ctx.Err()",
    "case <-d.ctx.Done():\n    <-(d.responseReady)\n    return d.ctx.Err()",
  );
  for (const source of [producerIIFE, cancellationHelper, parenthesizedDrain]) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }

  const parenthesizedCases = vulnerable
    .replace("case <-d.responseReady:", "case <-(d.responseReady):")
    .replace("case <-d.ctx.Done():", "case <-(d.ctx.Done()):");
  assert.ok((await repository(parenthesizedCases)).signals.some((item) => item.ruleId === ruleId));

  const asyncProducerCleanup = vulnerable.replace(
    "d.response = response",
    "d.response = response\n  go func() { d.response.Body.Close() }()",
  );
  const asyncCancellationHelper = cancellationHelper.replace("d.drainLate()", "go d.drainLate()");
  for (const source of [asyncProducerCleanup, asyncCancellationHelper]) {
    assert.ok((await repository(source)).signals.some((item) => item.ruleId === ruleId));
  }
});

test("tracks all-path waits and receiver identity through executed control flow", async () => {
  const bypassingWaits = [
    vulnerable.replace(
      "case <-d.ctx.Done():\n    return d.ctx.Err()",
      "case <-d.ctx.Done():\n    func() { if shouldSkip() { return }; <-d.responseReady }()\n    return d.ctx.Err()",
    ),
    vulnerable.replace(
      `case <-d.ctx.Done():
    return d.ctx.Err()
  }
}`,
      `case <-d.ctx.Done():
    if shouldSkip() { goto done }
    <-d.responseReady
    return d.ctx.Err()
  }
done:
  return d.ctx.Err()
}`,
    ),
  ];
  for (const source of bypassingWaits) {
    assert.ok((await repository(source)).signals.some((item) => item.ruleId === ruleId));
  }

  const receiverChanges = [
    vulnerable
      .replace("type duplexHTTPCall struct {", "var other *duplexHTTPCall\n\ntype duplexHTTPCall struct {")
      .replace(
        "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
        "func (d *duplexHTTPCall) start() { func() { d = other }(); go d.makeRequest() }",
      ),
    vulnerable
      .replace("type duplexHTTPCall struct {", "var other *duplexHTTPCall\n\ntype duplexHTTPCall struct {")
      .replace(
        "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
        "func (d *duplexHTTPCall) start() { for _, d = range []*duplexHTTPCall{other} { go d.makeRequest() } }",
      ),
    vulnerable
      .replace("type duplexHTTPCall struct {", "var other *duplexHTTPCall\n\ntype duplexHTTPCall struct {")
      .replace(
        "_ = d.BlockUntilResponseReady()\n  if d.response == nil { return nil }\n  return d.response.Body.Close()",
        "_ = d.BlockUntilResponseReady()\n  func() { d = other }()\n  if d.response == nil { return nil }\n  return d.response.Body.Close()",
      ),
  ];
  for (const source of receiverChanges) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }

  const unreachableChange = vulnerable
    .replace("type duplexHTTPCall struct {", "var other *duplexHTTPCall\n\ntype duplexHTTPCall struct {")
    .replace(
      "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
      "func (d *duplexHTTPCall) start() { if false { d = other }; go d.makeRequest() }",
    );
  assert.ok((await repository(unreachableChange)).signals.some((item) => item.ruleId === ruleId));
});

test("recognizes caller-side bounded re-observation and producer activation locality", async () => {
  const boundedCaller = vulnerable
    .replace(
      "func (d *duplexHTTPCall) BlockUntilResponseReady() error {",
      "func (d *duplexHTTPCall) awaitLate() { <-d.responseReady }\nfunc (d *duplexHTTPCall) BlockUntilResponseReady() error {",
    )
    .replace(
      "_ = d.BlockUntilResponseReady()\n  if d.response == nil { return nil }\n  return d.response.Body.Close()",
      "_ = d.BlockUntilResponseReady()\n  d.awaitLate()\n  if d.response == nil { return nil }\n  return d.response.Body.Close()",
    );
  assert.equal(
    (await repository(boundedCaller)).signals.some((item) => item.ruleId === ruleId),
    false,
  );

  const previous = vulnerable.replace(
    "func (d *duplexHTTPCall) start() { go d.makeRequest() }",
    "func (d *duplexHTTPCall) start() { if false { go d.makeRequest() } }",
  );
  const current = previous.replace("if false { go", "if shouldStart() { go");
  const changedLine = lineOf(current, "if shouldStart()");
  const result = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "duplex_http_call.go",
      current,
      previous,
      status: "modified",
      changedLines: new Set([changedLine]),
    }],
  });
  const signal = result.signals.find((item) => item.ruleId === ruleId);
  assert.ok(signal, JSON.stringify(result.signals, null, 2));
  assert.equal(signal.line, changedLine);
});

test("a reset after direct completion signalling does not erase the publication race", async () => {
  const source = vulnerable
    .replace("defer close(d.responseReady)\n", "")
    .replace("d.response = response", "d.response = response\n  close(d.responseReady)\n  d.response = nil");
  assert.ok((await repository(source)).signals.some((item) => item.ruleId === ruleId));
});

test("the model contract preserves the same ownership proof and quiet boundaries", () => {
  assert.match(GO_HTTP_MODEL_PROMPT, /typed \*http\.Response publication, its completion signal, and a real body owner/);
  assert.match(GO_HTTP_MODEL_PROMPT, /cancellation paths that synchronize with completion before cleanup/);
  assert.match(GO_HTTP_MODEL_PROMPT, /proven no-late-publication or ownership-transfer protocol/);
});
