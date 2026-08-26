import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execute = promisify(execFile);
const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

test("the published runtime executes without node_modules", async () => {
  const artifact = await mkdtemp(join(tmpdir(), "go-http-artifact-"));
  const repository = await mkdtemp(join(tmpdir(), "go-http-target-"));
  const entrypoint = join(artifact, "dist", "index.js");
  const input = join(artifact, "input.json");
  const output = join(artifact, "output.json");

  const ignored = (await readFile(join(projectRoot, ".adversaryignore"), "utf8"))
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  assert.ok(ignored.includes(".git"));
  assert.ok(ignored.includes("node_modules/"));

  await mkdir(dirname(entrypoint), { recursive: true });
  await mkdir(join(artifact, "schemas"), { recursive: true });
  await copyFile(join(projectRoot, "dist", "index.js"), entrypoint);
  await copyFile(join(projectRoot, "dist", "web-tree-sitter.wasm"), join(artifact, "dist", "web-tree-sitter.wasm"));
  await copyFile(join(projectRoot, "dist", "tree-sitter-go.wasm"), join(artifact, "dist", "tree-sitter-go.wasm"));
  await copyFile(
    join(projectRoot, "schemas", "adversary.review.v1.schema.json"),
    join(artifact, "schemas", "adversary.review.v1.schema.json"),
  );
  await copyFile(join(projectRoot, "THIRD_PARTY_NOTICES.md"), join(artifact, "THIRD_PARTY_NOTICES.md"));
  await writeFile(join(artifact, "package.json"), '{"type":"module"}\n');
  await writeFile(join(repository, "main.go"), `package sample
import ("context"; "net/http")
type call struct {
  ctx context.Context
  client *http.Client
  ready chan struct{}
  response *http.Response
}
func (c *call) start() { go c.produce() }
func (c *call) produce() {
  defer close(c.ready)
  response, err := c.client.Do(nil)
  if err != nil { return }
  c.response = response
}
func (c *call) wait() error {
  select {
  case <-c.ready: return nil
  case <-c.ctx.Done(): return c.ctx.Err()
  }
}
func (c *call) closeResponse() error {
  _ = c.wait()
  if c.response == nil { return nil }
  return c.response.Body.Close()
}

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
func (w *errorResponseWrapper) ResponseTrailer() http.Header {
  combined := make(http.Header)
  for k, v := range w.base.ResponseTrailer() { combined[k] = v }
  for k, v := range w.err.Meta() { combined[k] = v }
  return combined
}
`);
  await writeFile(input, `${JSON.stringify({ source: { path: repository } })}\n`);

  const bundle = await readFile(entrypoint, "utf8");
  assert.doesNotMatch(bundle, /from\s+["'](?:@adversarylabs\/sdk|web-tree-sitter)["']/);
  const notices = await readFile(join(artifact, "THIRD_PARTY_NOTICES.md"), "utf8");
  assert.deepEqual([...notices.matchAll(/^## (.+?) \(/gm)].map((match) => match[1]), [
    "@adversarylabs/sdk",
    "ajv",
    "fast-deep-equal",
    "fast-uri",
    "json-schema-traverse",
    "tree-sitter-go",
    "web-tree-sitter",
    "yaml",
  ]);
  assert.match(notices, /Permission is hereby granted/);
  assert.match(notices, /Redistribution and use in source and binary forms/);
  assert.match(notices, /Copyright \(c\) 2014 Max Brunsfeld/);

  await execute(process.execPath, [entrypoint], {
    cwd: artifact,
    env: {
      ...process.env,
      ADVERSARY_INPUT: input,
      ADVERSARY_OUTPUT: output,
      ADVERSARY_REPO: repository,
    },
  });

  const envelope = JSON.parse(await readFile(output, "utf8"));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "go-http");
  assert.equal(envelope.result.adversary.version, "0.0.21");
  assert.equal(
    envelope.result.findings.some((finding: { ruleId?: string }) =>
      finding.ruleId === "go-http.cancelled-response-publication"
    ),
    true,
    JSON.stringify(envelope.result.findings, null, 2),
  );
  assert.equal(
    envelope.result.findings.some((finding: { ruleId?: string }) =>
      finding.ruleId === "go-http.aggregate-error-metadata-as-trailers"
    ),
    true,
    JSON.stringify(envelope.result.findings, null, 2),
  );
});
