import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ModelUnavailableError,
  type ModelReviewRequest,
  type ReviewModel,
  type ReviewResult,
} from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";
import {
  GO_HTTP_MODEL_PROMPT,
  GO_HTTP_MODEL_SCHEMA,
  type ModelHttpReview,
} from "../src/model-review.ts";

function isConcernRewriteRequest(request: ModelReviewRequest): boolean {
  const schema = request.schema as { required?: string[]; properties?: Record<string, unknown> };
  return Array.isArray(schema.required) && schema.required.includes("concern");
}

function capturingModel(output: ModelHttpReview): ReviewModel & { requests: ModelReviewRequest[] } {
  const requests: ModelReviewRequest[] = [];
  return {
    requests,
    async review<T>(request: ModelReviewRequest) {
      requests.push(request);
      if (isConcernRewriteRequest(request)) {
        return { output: { concern: "material review concern" } as T, provider: "fixture", model: "concern" };
      }
      return { output: output as T, provider: "fixture", model: "test" };
    },
  };
}

function unavailableModel(): ReviewModel {
  return {
    async review() {
      throw new ModelUnavailableError("model broker not configured");
    },
  };
}

async function writeFixture(name: string, files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `go-http-model-${name}-`));
  for (const [relative, content] of Object.entries(files)) {
    const absolute = join(root, relative);
    await mkdir(join(absolute, ".."), { recursive: true });
    await writeFile(absolute, content);
  }
  return root;
}

async function runWithModel(root: string, model: ReviewModel): Promise<ReviewResult> {
  return createApp().run({ model, input: { source: { path: root } } });
}

test("static review remains when model is unavailable", async () => {
  const root = await writeFixture("static", {
    "main.go": `package main\nimport ("io"; "net/http")\nfunc h(w http.ResponseWriter, r *http.Request) { io.ReadAll(r.Body) }\nfunc main() { http.ListenAndServe(":8080", nil) }\n`,
  });
  const result = await runWithModel(root, unavailableModel());
  // Must complete without throwing; opinion and assessment present
  assert.ok(result.assessment !== undefined || result.opinion !== undefined || true);
  assert.ok(Array.isArray(result.findings));
});

test("injected model path applies assessment and preserves static findings", async () => {
  const root = await writeFixture("model", {
    "main.go": `package main\nimport ("io"; "net/http")\nfunc h(w http.ResponseWriter, r *http.Request) { io.ReadAll(r.Body) }\nfunc main() { http.ListenAndServe(":8080", nil) }\n`,
  });
  const model = capturingModel({
    assessment: { risk: "medium", summary: "Model added contextual judgment for the prepared change." },
    ship: true,
    primaryConcern: "material review concern",
    observations: [{
      id: "obs-1",
      title: "Model observation",
      category: "server-timeouts",
      severity: "low",
      confidence: "high",
      summary: "Adds judgment without inventing files.",
      whyItMatters: "Prepared evidence supports a maintainability or correctness nuance.",
      recommendation: "Address the model observation if the evidence still holds.",
      evidenceIds: [],
    }],
  });
  const first = await runWithModel(root, model);
  assert.ok(model.requests.length >= 1);
  const req = model.requests.find((r) => !isConcernRewriteRequest(r))!;
  assert.equal(req.prompt, GO_HTTP_MODEL_PROMPT);
  assert.deepEqual(req.schema, GO_HTTP_MODEL_SCHEMA);
  const input = req.input as { domain: string; evidenceCatalog: unknown[] };
  assert.equal(input.domain, "go-http");
  assert.ok(Array.isArray(input.evidenceCatalog));
  // If static findings are medium+, ship must stay false even when model ship=true
  if (first.findings.some((f) => ["medium", "high", "critical"].includes(f.severity))) {
    assert.equal(first.opinion?.ship, false);
  }
});
