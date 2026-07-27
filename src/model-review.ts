import {
  formatOpinion,
  isOpinionConcernPhrase,
  ModelUnavailableError,
  ModelReviewError,
  requireOpinionConcern,
  type ChangeContext,
  type ModelReviewRequest,
  type RuleContext,
} from "@adversarylabs/sdk";
import { type Analysis, type Signal } from "./types.js";

const MAX_MODEL_FILES = 16;
const MAX_FILE_CHARS = 6_000;
const MAX_DETERMINISTIC_SIGNALS = 40;
const MAX_MODEL_OBSERVATIONS = 6;

export const GO_HTTP_MODEL_PROMPT = `You are reviewing Go HTTP code for request boundaries, server lifecycle, and outbound client correctness.

Authority:
- server timeouts and graceful Shutdown (including long-lived local callback servers)
- handler request bodies (r.Body) needing MaxBytesReader with a size class
- client response bodies (resp.Body) needing LimitReader with a size class (token JSON vs metadata)
- outbound http.Client timeouts and request contexts
- DefaultClient / http.Get/Post without deadlines

Hard exclusions — do NOT file unbounded-body findings for:
- CLI stdin / multi-MB YAML or manifest inputs (product must accept large legitimate input)
- Full product downloads of archives/binaries/checksum streams
- Local OCI store / file reads that are not HTTP
- *_test.go noise

Never label CLI stdin as an "attacker-controlled request body" unless it is an HTTP server handler.
Severity by exposure: public handler > client to untrusted host > local trusted input (usually silence).
When recommending limits, state a size class; do not invent a single tiny generic limit for release YAML or downloads.

Do NOT review generic Go style, CLI UX, databases, or Kubernetes.
Prefer silence over speculation. Zero to six observations. Cite only evidenceIds from the catalog.
Do not restate deterministic signals without added judgment.
primaryConcern is a short noun phrase after "I would address", empty when ship is true.
Return JSON matching the schema only.`;

export const GO_HTTP_MODEL_SCHEMA: Record<string, unknown> = {
  type: "object",
  additionalProperties: false,
  required: ["assessment", "ship", "observations"],
  properties: {
    assessment: {
      type: "object",
      additionalProperties: false,
      required: ["risk", "summary"],
      properties: {
        risk: {
          type: "string",
          enum: ["none", "low", "medium", "high", "critical"],
        },
        summary: { type: "string", minLength: 1, maxLength: 800 },
      },
    },
    ship: { type: "boolean" },
    primaryConcern: { type: "string", minLength: 1, maxLength: 120 },
    observations: {
      type: "array",
      maxItems: MAX_MODEL_OBSERVATIONS,
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "id",
          "title",
          "category",
          "severity",
          "confidence",
          "summary",
          "whyItMatters",
          "recommendation",
          "evidenceIds",
        ],
        properties: {
          id: { type: "string", minLength: 1, maxLength: 64 },
          title: { type: "string", minLength: 1, maxLength: 160 },
          category: {
            type: "string",
            enum: [
              "server-timeouts",
              "handler-body-limit",
              "client-response-limit",
              "body-limit",
              "graceful-shutdown",
              "client-timeout",
              "request-context",
              "default-client",
              "auth-headers",
              "completeness",
            ],
          },
          severity: {
            type: "string",
            enum: ["low", "medium", "high", "critical"],
          },
          confidence: {
            type: "string",
            enum: ["medium", "high"],
          },
          summary: { type: "string", minLength: 1, maxLength: 500 },
          whyItMatters: { type: "string", minLength: 1, maxLength: 500 },
          recommendation: { type: "string", minLength: 1, maxLength: 500 },
          evidenceIds: {
            type: "array",
            minItems: 1,
            maxItems: 8,
            items: { type: "string", minLength: 1, maxLength: 96 },
          },
        },
      },
    },
  },
};

export interface PreparedEvidenceItem {
  id: string;
  kind: "deterministic" | "source";
  path: string;
  line?: number;
  message: string;
  snippet: string;
}

export interface PreparedModelInput {
  domain: "go-http";
  change: {
    scanMode: "changed" | "all" | "repository";
    baseRef?: string;
    headRef?: string;
    worktree?: boolean;
    changedFiles: string[];
  };
  deterministicSignals: Array<{
    id: string;
    ruleId: string;
    path: string;
    line: number;
    message: string;
    snippet: string;
  }>;
  sources: Array<{
    id: string;
    path: string;
    status: string;
    content: string;
    truncated: boolean;
  }>;
  evidenceCatalog: PreparedEvidenceItem[];
}

export interface ModelHttpObservation {
  id: string;
  title: string;
  category: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: "medium" | "high";
  summary: string;
  whyItMatters: string;
  recommendation: string;
  evidenceIds: string[];
}

export interface ModelHttpReview {
  assessment: {
    risk: "none" | "low" | "medium" | "high" | "critical";
    summary: string;
  };
  ship: boolean;
  primaryConcern?: string;
  observations: ModelHttpObservation[];
}

export type DiscoveryFile = { path: string; current: string; status: string };

export function prepareModelInputFromDiscovery(
  change: ChangeContext | null,
  analysis: Analysis,
  files: DiscoveryFile[],
): PreparedModelInput {
  const evidenceCatalog: PreparedEvidenceItem[] = [];
  const deterministicSignals = analysis.signals
    .slice()
    .sort(
      (left, right) =>
        left.path.localeCompare(right.path) ||
        left.line - right.line ||
        left.ruleId.localeCompare(right.ruleId),
    )
    .slice(0, MAX_DETERMINISTIC_SIGNALS)
    .map((signal) => {
      const id = evidenceIdForSignal(signal);
      evidenceCatalog.push({
        id,
        kind: "deterministic",
        path: signal.path,
        line: signal.line,
        message: signal.message,
        snippet: signal.snippet.slice(0, 300),
      });
      return {
        id,
        ruleId: signal.ruleId,
        path: signal.path,
        line: signal.line,
        message: signal.message,
        snippet: signal.snippet.slice(0, 300),
      };
    });

  const byPath = new Map(files.map((file) => [file.path, file]));
  const pathOrder = [
    ...new Set([
      ...analysis.signals.map((signal) => signal.path),
      ...(change?.changedFiles ?? []),
      ...files.map((file) => file.path),
    ]),
  ].sort((left, right) => {
    const changed = new Set(change?.changedFiles ?? []);
    const leftChanged = changed.has(left) ? 0 : 1;
    const rightChanged = changed.has(right) ? 0 : 1;
    if (leftChanged !== rightChanged) return leftChanged - rightChanged;
    return left.localeCompare(right);
  });

  const sources: PreparedModelInput["sources"] = [];
  for (const path of pathOrder) {
    if (sources.length >= MAX_MODEL_FILES) break;
    const file = byPath.get(path);
    if (file === undefined) continue;
    const truncated = file.current.length > MAX_FILE_CHARS;
    const content = truncated
      ? `${file.current.slice(0, MAX_FILE_CHARS)}\n/* truncated */\n`
      : file.current;
    const id = `file:${path}`;
    sources.push({
      id,
      path,
      status: file.status,
      content,
      truncated,
    });
    evidenceCatalog.push({
      id,
      kind: "source",
      path,
      message: `Prepared source excerpt for ${path}`,
      snippet: content.split("\n").slice(0, 3).join("\n").slice(0, 300),
    });
  }

  return {
    domain: "go-http",
    change: {
      scanMode: change === null ? "repository" : change.scanMode,
      ...(change?.baseRef === undefined ? {} : { baseRef: change.baseRef }),
      ...(change?.headRef === undefined ? {} : { headRef: change.headRef }),
      ...(change === null ? {} : { worktree: change.worktree }),
      changedFiles: [...(change?.changedFiles ?? [])].slice(0, 100),
    },
    deterministicSignals,
    sources,
    evidenceCatalog,
  };
}

export function buildModelReviewRequestFromDiscovery(
  change: ChangeContext | null,
  analysis: Analysis,
  files: DiscoveryFile[],
): {
  request: ModelReviewRequest;
  evidenceById: Map<string, PreparedEvidenceItem>;
  input: PreparedModelInput;
} {
  const input = prepareModelInputFromDiscovery(change, analysis, files);
  const evidenceById = new Map(input.evidenceCatalog.map((item) => [item.id, item]));
  return {
    input,
    evidenceById,
    request: {
      prompt: GO_HTTP_MODEL_PROMPT,
      input,
      schema: GO_HTTP_MODEL_SCHEMA,
      budget: {
        maximumOutputTokens: 4_096,
        timeoutMs: 120_000,
      },
    },
  };
}

export type StaticSeverity = "none" | "low" | "medium" | "high" | "critical";

export async function applyModelHttpReview(
  ctx: RuleContext,
  output: ModelHttpReview,
  evidenceById: Map<string, PreparedEvidenceItem>,
  staticSeverities: StaticSeverity[] = [],
  staticPrimaryConcern?: string,
): Promise<void> {
  const modelObservationSeverities = output.observations.map((item) => item.severity);
  const risk = maxSeverity([
    output.assessment.risk,
    ...staticSeverities,
    ...modelObservationSeverities,
  ]);

  ctx.review.assessment({
    risk,
    summary: output.assessment.summary,
  });

  const rankedObservations = output.observations.slice().sort(
    (left, right) =>
      severityRank(right.severity) - severityRank(left.severity) || left.id.localeCompare(right.id),
  );
  const blocking =
    staticSeverities.some((severity) => severityRank(severity) >= severityRank("medium")) ||
    modelObservationSeverities.some((severity) => severityRank(severity) >= severityRank("medium"));
  const ship = output.ship && !blocking;

  const topModel = rankedObservations[0];
  const staticMax = maxSeverity(staticSeverities);
  const modelMax = maxSeverity(modelObservationSeverities);
  const modelCandidates = [topModel?.title, output.primaryConcern];
  const staticCandidates = [staticPrimaryConcern];
  const ordered =
    severityRank(staticMax) > severityRank(modelMax)
      ? [...staticCandidates, ...modelCandidates]
      : [...modelCandidates, ...staticCandidates];
  const concern = await resolveOpinionConcern(ctx, ordered);

  ctx.review.opinion(
    formatOpinion({
      ship,
      ...(concern === undefined ? {} : { concern }),
      change: ctx.change,
    }),
  );

  for (const observation of output.observations.slice(0, MAX_MODEL_OBSERVATIONS)) {
    const evidence = observation.evidenceIds
      .map((id) => evidenceById.get(id))
      .filter((item): item is PreparedEvidenceItem => item !== undefined)
      .slice(0, 8)
      .map((item) => ({
        location: {
          file: item.path,
          ...(item.line === undefined ? {} : { line: item.line }),
        },
        message: item.message,
        snippet: item.snippet,
      }));

    ctx.review.observe({
      key: `go-http.model.${observation.id}`,
      summary: `[${observation.severity}/${observation.confidence}] ${observation.title}: ${observation.summary}`,
      ...(evidence.length === 0 ? {} : { evidence }),
      metadata: {
        source: "model",
        category: observation.category,
        severity: observation.severity,
        confidence: observation.confidence,
        whyItMatters: observation.whyItMatters,
        recommendation: observation.recommendation,
        evidenceIds: observation.evidenceIds,
      },
    });
  }
}

export async function runModelHttpReview(
  ctx: RuleContext,
  analysis: Analysis,
  files: DiscoveryFile[],
  staticSeverities: StaticSeverity[] = [],
  staticPrimaryConcern?: string,
): Promise<"applied" | "unavailable"> {
  const { request, evidenceById } = buildModelReviewRequestFromDiscovery(
    ctx.change,
    analysis,
    files,
  );
  try {
    const result = await ctx.model.review<ModelHttpReview>(request);
    await applyModelHttpReview(
      ctx,
      result.output,
      evidenceById,
      staticSeverities,
      staticPrimaryConcern,
    );
    return "applied";
  } catch (error) {
    if (error instanceof ModelUnavailableError) {
      return "unavailable";
    }
    // Non-fatal model/provider failures must not hide static findings already emitted.
    if (error instanceof ModelReviewError || (error instanceof Error && /model|broker|fireworks|openai|anthropic/i.test(error.message))) {
      return "unavailable";
    }
    throw error;
  }
}

function evidenceIdForSignal(signal: Signal): string {
  return `det:${signal.ruleId}:${signal.path}:${signal.line}`;
}

function severityRank(severity: StaticSeverity | ModelHttpObservation["severity"]): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    case "none":
      return 0;
  }
}

async function resolveOpinionConcern(
  ctx: RuleContext,
  candidates: Array<string | undefined>,
): Promise<string | undefined> {
  for (const candidate of candidates) {
    if (candidate === undefined || candidate.trim() === "") continue;
    if (isOpinionConcernPhrase(candidate)) {
      return requireOpinionConcern(candidate);
    }
    try {
      const result = await ctx.model.concern({ text: candidate });
      return result.concern;
    } catch {
      // try next
    }
  }
  return undefined;
}

function maxSeverity(values: Array<StaticSeverity | ModelHttpObservation["severity"]>): StaticSeverity {
  let best: StaticSeverity = "none";
  for (const value of values) {
    if (severityRank(value) > severityRank(best)) {
      best = value;
    }
  }
  return best;
}
