import assert from "node:assert/strict";
import { mkdtemp, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp } from "../src/index.ts";

async function reviewTree(files: Record<string, string>) {
  const root = await mkdtemp(join(tmpdir(), "go-http-read-"));
  for (const [relative, content] of Object.entries(files)) {
    const absolute = join(root, relative);
    await mkdir(join(absolute, ".."), { recursive: true });
    await writeFile(absolute, content);
  }
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
}

test("handler r.Body ReadAll is handler-body-limit", async () => {
  const output = await reviewTree({
    "handler.go": `package main
import ("io"; "net/http")
func h(w http.ResponseWriter, r *http.Request) { io.ReadAll(r.Body) }
`,
  });
  assert.ok(output.findings.some((f) => f.ruleId === "go-http.handler-body-limit"));
  assert.equal(output.findings.some((f) => f.ruleId === "go-http.body-limit"), false);
});

test("client resp.Body ReadAll is client-response-limit", async () => {
  const output = await reviewTree({
    "client.go": `package main
import ("io"; "net/http")
func get(c *http.Client) {
	resp, _ := c.Get("https://example.com")
	io.ReadAll(resp.Body)
}
`,
  });
  assert.ok(output.findings.some((f) => f.ruleId === "go-http.client-response-limit"));
});

test("CLI stdin ReadAll is not an HTTP body finding", async () => {
  const output = await reviewTree({
    "cli/cmd/prepare.go": `package cmd
import ("io"; "os")
func prepare() { io.ReadAll(os.Stdin) }
`,
  });
  assert.equal(output.findings.some((f) => f.ruleId === "go-http.handler-body-limit"), false);
  assert.equal(output.findings.some((f) => f.ruleId === "go-http.client-response-limit"), false);
});

test("archive downloader ReadAll is not flagged", async () => {
  const output = await reviewTree({
    "pkg/tools/downloader.go": `package tools
import ("io"; "net/http")
func download(resp *http.Response) { io.ReadAll(resp.Body) } // full archive download
`,
  });
  assert.equal(
    output.findings.some((f) => f.ruleId === "go-http.client-response-limit" || f.ruleId === "go-http.handler-body-limit"),
    false,
  );
});
