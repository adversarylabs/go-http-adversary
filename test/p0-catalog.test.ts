import assert from "node:assert/strict";
import { cp, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createApp } from "../src/index.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
async function isolated(rel: string) {
  const root = await mkdtemp(join(tmpdir(), "go-http-p0-"));
  await cp(join(projectRoot, "fixtures", rel), root, { recursive: true });
  return root;
}
const review = async (rel: string) =>
  createApp().run({ input: { source: { path: await isolated(rel) } }, includeRawObservations: true });

test("P0 go-http catalog rules", async () => {
  const cases = [
    { dir: "p0-timeouts", id: "go-http.server-timeouts" },
    { dir: "p0-body", id: "go-http.handler-body-limit" },
    { dir: "p0-client", id: "go-http.client-no-timeout" },
    { dir: "p0-ws", id: "go-http.websocket-origin" },
    { dir: "p0-redirect", id: "go-http.redirect-open" },
    { dir: "p0-cors", id: "go-http.cors-permissive" },
  ] as const;
  for (const c of cases) {
    const bad = await review(`${c.dir}/vulnerable`);
    assert.equal(bad.findings.some((f) => f.ruleId === c.id), true, `${c.id} missed; ${bad.findings.map((f) => f.ruleId)}`);
    const good = await review(`${c.dir}/clean`);
    assert.equal(good.findings.some((f) => f.ruleId === c.id), false, `${c.id} FP`);
  }
});
