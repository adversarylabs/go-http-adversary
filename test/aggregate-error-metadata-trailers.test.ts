import assert from "node:assert/strict";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";

const ruleId = "go-http.aggregate-error-metadata-as-trailers";

const prefix = `package connect
import (
  "net/http"
  "strings"
)
type responseSource interface {
  ResponseHeader() http.Header
  ResponseTrailer() http.Header
}
type Error struct{}
func (e *Error) Meta() http.Header { return make(http.Header) }
type errorResponseWrapper struct {
  base responseSource
  err *Error
}
`;

function repository(source: string) {
  return analyzeDiscovery({
    mode: "repository",
    files: [{ path: "context.go", current: source, status: "repository", changedLines: new Set() }],
  });
}

function repositoryAt(path: string, source: string) {
  return analyzeDiscovery({
    mode: "repository",
    files: [{ path, current: source, status: "repository", changedLines: new Set() }],
  });
}

function lineOf(source: string, text: string): number {
  return source.split("\n").findIndex((line) => line.includes(text)) + 1;
}

const vulnerable = prefix + `
func (w *errorResponseWrapper) ResponseHeader() http.Header {
  if w.base != nil { return w.base.ResponseHeader() }
  return make(http.Header)
}
func (w *errorResponseWrapper) ResponseTrailer() http.Header {
  combined := make(http.Header)
  if w.base != nil {
    for k, v := range w.base.ResponseTrailer() {
      combined[k] = v
    }
  }
  if w.err != nil {
    for k, v := range w.err.Meta() {
      combined[k] = v
    }
  }
  return combined
}
`;

test("reports the exact Connect review-head aggregate-to-trailer merge", async () => {
  const result = await repository(vulnerable);
  const signal = result.signals.find((item) => item.ruleId === ruleId);
  assert.ok(signal, JSON.stringify(result.signals, null, 2));
  assert.equal(signal.data.wrapper, "errorResponseWrapper");
  assert.equal(signal.data.baseField, "base");
  assert.equal(signal.data.errorField, "err");
  assert.equal(signal.data.aggregateMethod, "Meta");
  assert.equal(signal.line, lineOf(vulnerable, "for k, v := range w.err.Meta()"));
});

test("reports append-style merging into the retained trailer map", async () => {
  const source = vulnerable.replaceAll("combined[k] = v", "combined[k] = append(combined[k], v...)");
  const result = await repository(source);
  assert.equal(result.signals.filter((item) => item.ruleId === ruleId).length, 1, JSON.stringify(result.signals, null, 2));
});

test("reports regardless of which source is copied into the result first", async () => {
  const reversed = vulnerable.replace(
    `if w.base != nil {
    for k, v := range w.base.ResponseTrailer() {
      combined[k] = v
    }
  }
  if w.err != nil {
    for k, v := range w.err.Meta() {
      combined[k] = v
    }
  }`,
    `if w.err != nil {
    for k, v := range w.err.Meta() {
      combined[k] = v
    }
  }
  if w.base != nil {
    for k, v := range w.base.ResponseTrailer() {
      combined[k] = v
    }
  }`,
  );
  const result = await repository(reversed);
  assert.equal(result.signals.filter((item) => item.ruleId === ruleId).length, 1, JSON.stringify(result.signals, null, 2));
});

test("accepts the final code that preserves the base classified channels", async () => {
  const fixed = prefix + `
func (w *errorResponseWrapper) ResponseHeader() http.Header {
  if w.base != nil { return w.base.ResponseHeader() }
  return make(http.Header)
}
func (w *errorResponseWrapper) ResponseTrailer() http.Header {
  if w.base != nil { return w.base.ResponseTrailer() }
  return make(http.Header)
}
`;
  const result = await repository(fixed);
  assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
});

test("stays quiet without both a retained classified base and an unclassified aggregate", async () => {
  const cases = [
    vulnerable.replace("for k, v := range w.base.ResponseTrailer()", "for k, v := range make(http.Header)"),
    vulnerable.replace("w.err.Meta()", "w.err.Trailer()"),
    vulnerable.replace("combined[k] = v\n    }\n  }\n  if w.err", "other[k] = v\n    }\n  }\n  if w.err").replace("combined := make(http.Header)", "combined := make(http.Header)\n  other := make(http.Header)"),
    vulnerable.replace(
      "  if w.err != nil {",
      "  combined = make(http.Header)\n  if w.err != nil {",
    ),
  ];
  for (const source of cases) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }
});

test("accepts aggregate metadata partitioned by a trailer marker", async () => {
  const partitioned = vulnerable.replace(
    "combined[k] = v\n    }\n  }\n  return combined",
    `if strings.HasPrefix(k, "Trailer-") {
        combined[strings.TrimPrefix(k, "Trailer-")] = v
      }
    }
  }
  return combined`,
  );
  const result = await repository(partitioned);
  assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));

  const inverted = partitioned.replace("if strings.HasPrefix", "if !strings.HasPrefix");
  const unsafe = await repository(inverted);
  assert.equal(unsafe.signals.filter((item) => item.ruleId === ruleId).length, 1, JSON.stringify(unsafe.signals, null, 2));
});

test("does not mistake disjunctions or shadowed string helpers for a trailer partition", async () => {
  const partitioned = vulnerable.replace(
    "combined[k] = v\n    }\n  }\n  return combined",
    `if strings.HasPrefix(k, "Trailer-") || allowMetadata(k) {
        combined[strings.TrimPrefix(k, "Trailer-")] = v
      }
    }
  }
  return combined`,
  ).replace(
    "type Error struct{}",
    "func allowMetadata(string) bool { return true }\ntype Error struct{}",
  );
  const disjunction = await repository(partitioned);
  assert.equal(
    disjunction.signals.filter((item) => item.ruleId === ruleId).length,
    1,
    JSON.stringify(disjunction.signals, null, 2),
  );

  const shadowed = partitioned
    .replace(" || allowMetadata(k)", "")
    .replace(
      "combined := make(http.Header)",
      "strings := fakeStrings{}\n  combined := make(http.Header)",
    )
    .replace(
      "type Error struct{}",
      "type fakeStrings struct{}\nfunc (fakeStrings) HasPrefix(string, string) bool { return true }\ntype Error struct{}",
    );
  const fake = await repository(shadowed);
  assert.equal(fake.signals.filter((item) => item.ruleId === ruleId).length, 1, JSON.stringify(fake.signals, null, 2));

  const contains = partitioned
    .replace(" || allowMetadata(k)", "")
    .replace("strings.HasPrefix", "strings.Contains");
  const weakPartition = await repository(contains);
  assert.equal(
    weakPartition.signals.filter((item) => item.ruleId === ruleId).length,
    1,
    JSON.stringify(weakPartition.signals, null, 2),
  );
});

test("requires real standard-library types and reachable copy paths", async () => {
  const aliased = vulnerable
    .replace('"net/http"', 'h "net/http"')
    .replaceAll("http.Header", "h.Header");
  const aliasResult = await repository(aliased);
  assert.equal(aliasResult.signals.filter((item) => item.ruleId === ruleId).length, 1, JSON.stringify(aliasResult.signals, null, 2));

  const impostor = vulnerable.replace('"net/http"', '"example.invalid/net/http"');
  const fakeImport = await repository(impostor);
  assert.equal(fakeImport.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(fakeImport.signals, null, 2));

  const dead = vulnerable.replace(
    "if w.err != nil {\n    for k, v := range w.err.Meta()",
    "if false {\n    for k, v := range w.err.Meta()",
  );
  const unreachable = await repository(dead);
  assert.equal(unreachable.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(unreachable.signals, null, 2));

  const testOnly = await repositoryAt("context_test.go", vulnerable);
  assert.equal(testOnly.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(testOnly.signals, null, 2));
});

test("rejects receiver rebinding, field replacement, and uninvoked nested copies", async () => {
  const receiverRebound = vulnerable.replace(
    "combined := make(http.Header)",
    "w = &errorResponseWrapper{}\n  combined := make(http.Header)",
  );
  const baseReplaced = vulnerable.replace(
    "combined := make(http.Header)",
    "w.base = nil\n  combined := make(http.Header)",
  );
  const nested = vulnerable.replace(
    "for k, v := range w.err.Meta() {\n      combined[k] = v\n    }",
    "copyMeta := func() { for k, v := range w.err.Meta() { combined[k] = v } }\n    _ = copyMeta",
  );
  for (const source of [receiverRebound, baseReplaced, nested]) {
    const result = await repository(source);
    assert.equal(result.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(result.signals, null, 2));
  }
});

test("diff mode reports the changed aggregate merge and ignores comment-only edits", async () => {
  const addedLine = lineOf(vulnerable, "for k, v := range w.err.Meta()");
  const changed = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "context.go",
      previous: vulnerable.replace("w.err.Meta()", "w.err.Trailer()"),
      current: vulnerable,
      status: "modified",
      changedLines: new Set([addedLine]),
    }],
  });
  assert.equal(changed.signals.filter((item) => item.ruleId === ruleId).length, 1, JSON.stringify(changed.signals, null, 2));
  assert.equal(changed.signals.find((item) => item.ruleId === ruleId)?.line, addedLine);

  const commentOnly = vulnerable.replace("for k, v := range w.err.Meta() {", "for k, v := range w.err.Meta() { // aggregate docs");
  const commentLine = lineOf(commentOnly, "aggregate docs");
  const quiet = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "context.go",
      previous: vulnerable,
      current: commentOnly,
      status: "modified",
      changedLines: new Set([commentLine]),
    }],
  });
  assert.equal(quiet.signals.some((item) => item.ruleId === ruleId), false, JSON.stringify(quiet.signals, null, 2));
});
