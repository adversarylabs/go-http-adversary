import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";
import { createApp } from "../src/index.ts";

const ruleId = "go-http.client-response-body-close";

async function review(source: string) {
  const root = await mkdtemp(join(tmpdir(), "go-http-close-"));
  await mkdir(root, { recursive: true });
  await writeFile(join(root, "client.go"), source);
  return createApp().run({ input: { source: { path: root } }, includeRawObservations: true });
}

test("flags a response body decoded without a close", async () => {
  const output = await review(`package client
import ("encoding/json"; "net/http")
func fetch(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil { return err }
	var result map[string]any
	return json.NewDecoder(resp.Body).Decode(&result)
}
`);
  const finding = output.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding, JSON.stringify(output.findings, null, 2));
  assert.match(finding.evidence[0]!.message ?? "", /without being closed/);
});

test("accepts deferred and direct body closes", async () => {
  const output = await review(`package client
import ("encoding/json"; "net/http")
func deferred(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(&struct{}{})
}
func direct(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil { return err }
	err = json.NewDecoder(resp.Body).Decode(&struct{}{})
	resp.Body.Close()
	return err
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false, JSON.stringify(output.findings, null, 2));
});

test("accepts an explicit response ownership transfer", async () => {
  const output = await review(`package client
import "net/http"
func fetch(client *http.Client, req *http.Request) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil { return nil, err }
	return resp, nil
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false, JSON.stringify(output.findings, null, 2));
});

test("accepts body ownership passed to an explicit close helper", async () => {
  const output = await review(`package client
import ("encoding/json"; "net/http")
func closeBody(body any) {}
func fetch(client *http.Client) error {
	resp, err := client.Get("https://example.com")
	if err != nil { return err }
	defer closeBody(resp.Body)
	return json.NewDecoder(resp.Body).Decode(&struct{}{})
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false, JSON.stringify(output.findings, null, 2));
});

test("does not mistake an unrelated Do method for an HTTP response", async () => {
  const output = await review(`package worker
import "io"
type result struct { Body io.Reader }
type worker struct{}
func (worker) Do() (*result, error) { return nil, nil }
func run(w worker) error {
	resp, err := w.Do()
	if err != nil { return err }
	_, err = io.ReadAll(resp.Body)
	return err
}
`);
  assert.equal(output.findings.some((item) => item.ruleId === ruleId), false, JSON.stringify(output.findings, null, 2));
});

test("diff mode requires the acquisition-to-consumption span to change", async () => {
  const current = `package client
import ("encoding/json"; "net/http")
func fetch(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil { return err }
	return json.NewDecoder(resp.Body).Decode(&struct{}{})
}
`;
  const analysis = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ path: "client.go", current, changedLines: new Set([1]), status: "modified" }],
  });
  assert.equal(analysis.signals.some((item) => item.ruleId === ruleId), false);
});
