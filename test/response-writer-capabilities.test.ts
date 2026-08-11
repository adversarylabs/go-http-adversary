import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";
import { createApp } from "../src/index.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const ruleId = "go-http.response-writer-capabilities";

test("flags the evaluated wrapper that preserves capabilities only through ResponseController", async () => {
  const result = await reviewFixture("vulnerable");
  const finding = result.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding);
  assert.match(finding.evidence[0]!.message ?? "", /Flush or Hijack/);
});

test("accepts the final direct methods and an intentionally narrow recorder", async () => {
  const result = await reviewFixture("clean");
  assert.equal(
    result.findings.some((item) => item.ruleId === ruleId),
    false,
    JSON.stringify(result.findings, null, 2),
  );
});

test("diff mode anchors the explicit preservation contract", async () => {
  const current = `package middleware
import "net/http"
// bufferedWriter preserves Flusher and Hijacker capabilities through ResponseController.
type bufferedWriter struct { http.ResponseWriter }
func (w *bufferedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *bufferedWriter) FlushError() error { return nil }
`;
  const typeLine = current.split("\n").findIndex((line) => line.startsWith("type bufferedWriter")) + 1;
  const claimLine = typeLine - 1;
  const analysis = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "middleware/writer.go",
      current,
      changedLines: new Set([claimLine, typeLine]),
      status: "modified",
    }],
  });
  const signals = analysis.signals.filter((item) => item.ruleId === ruleId);
  assert.equal(signals.length, 1);
  assert.equal(signals[0]!.line, typeLine);
});

async function reviewFixture(name: string) {
  return createApp().run({
    input: { source: { path: join(projectRoot, "fixtures", "response-writer-capabilities", name) } },
    includeRawObservations: true,
  });
}
