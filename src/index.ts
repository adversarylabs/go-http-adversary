#!/usr/bin/env node

import { realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { Adversary } from "@adversarylabs/sdk";
import { analyzeDiscovery } from "./analyze.js";
import { discoverSources } from "./discover.js";
import { domain } from "./domain.js";
import { reviewDomain } from "./review.js";

export function createApp(): Adversary {
  const app = new Adversary({
    name: domain.name,
    version: "0.0.16",
    review: { maximumFindings: 5, minimumConfidence: "medium" },
  });

  app.rule(`${domain.name}.review`, async (ctx) => {
    const discovery = await discoverSources(ctx);
    const analysis = await analyzeDiscovery(discovery);
    ctx.summary.files_scanned = analysis.filesScanned;
    if (analysis.parseErrors.length > 0) {
      ctx.review.observe({
        key: domain.observationKey,
        summary: `Parsed ${analysis.filesScanned} ${domain.sourceDescription} files with ${analysis.parseErrors.length} parse error${analysis.parseErrors.length === 1 ? "" : "s"}.`,
        metadata: {
          role: "context",
          parser: "tree-sitter-go",
          mode: analysis.mode,
          parseErrors: analysis.parseErrors.length,
        },
      });
    }
    await reviewDomain(
      ctx,
      analysis,
      discovery.files.map((file) => ({
        path: file.path,
        current: file.current,
        status: file.status,
      })),
    );
  });
  return app;
}

async function runIfDirect(): Promise<void> {
  if (
    process.argv[1] !== undefined &&
    (await realpath(process.argv[1])) === (await realpath(fileURLToPath(import.meta.url)))
  ) {
    await createApp().runFromEnvironment();
  }
}

void runIfDirect();
