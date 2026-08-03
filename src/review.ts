import { formatOpinion, requireOpinionConcern, type RuleContext } from "@adversarylabs/sdk";
import { domain } from "./domain.js";
import { runModelHttpReview, type DiscoveryFile } from "./model-review.js";
import { attachImportNavigation } from "./navigation.js";
import { type Analysis, type RuleDefinition, type Signal } from "./types.js";

const RISK_ORDER = { none: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;
const MAX_FINDINGS = 4;

export async function reviewDomain(
  ctx: RuleContext,
  analysis: Analysis,
  discoveryFiles: DiscoveryFile[] = [],
): Promise<void> {
  const candidates: Array<{ rule: RuleDefinition; signals: Signal[] }> = [];
  for (const rule of domain.rules) {
    const signals = analysis.signals.filter((signal) => signal.ruleId === rule.id);
    if (signals.length === 0) continue;
    candidates.push({ rule, signals });
  }

  const active = [...candidates]
    .sort(
      (left, right) =>
        RISK_ORDER[right.rule.severity] - RISK_ORDER[left.rule.severity] ||
        right.signals.length - left.signals.length ||
        left.rule.id.localeCompare(right.rule.id),
    )
    .slice(0, MAX_FINDINGS);

  for (const item of active) {
    ctx.finding({
      ruleId: item.rule.id,
      title: item.rule.title,
      category: item.rule.category,
      severity: item.rule.severity,
      confidence: item.rule.confidence,
      summary: item.rule.summary(item.signals.length),
      whyItMatters: item.rule.whyItMatters,
      impact: item.rule.impact,
      evidence: item.signals.slice(0, 12).map((signal) => ({
        location: {
          file: signal.path,
          line: signal.line,
          ...(signal.endLine === undefined ? {} : { endLine: signal.endLine }),
        },
        message: signal.message,
        snippet: signal.snippet,
        data: signal.data,
      })),
      recommendation: item.rule.recommendation,
      remediation: { complexity: "small" },
    });
  }

  addPositives(ctx, analysis);

  const staticSeverities = active.map((item) => item.rule.severity);
  const staticPrimaryConcern = active[0]?.rule.concern ?? active[0]?.rule.title.toLowerCase();
  await attachImportNavigation(ctx, analysis);

  const modelStatus = await runModelHttpReview(
    ctx,
    analysis,
    discoveryFiles,
    staticSeverities,
    staticPrimaryConcern,
  );
  if (modelStatus === "applied") {
    return;
  }

  if (active.length === 0) {
    ctx.review.assessment({ risk: "none", summary: domain.noRiskSummary });
    ctx.review.opinion({ ship: true, summary: domain.approvalSummary });
    return;
  }

  const primary = active[0]!;
  const concern = primary.rule.concern ?? primary.rule.title.toLowerCase();
  ctx.review.assessment({
    risk: primary.rule.severity,
    summary: `${primary.rule.title}. ${primary.rule.impact}`,
  });
  ctx.review.opinion(
    formatOpinion({
      ship: primary.rule.severity === "low",
      concern: requireOpinionConcern(concern),
      change: ctx.change,
    }),
  );
}

function addPositives(ctx: RuleContext, analysis: Analysis): void {
  const byKey = new Map<string, typeof analysis.positives>();
  for (const item of analysis.positives) {
    const existing = byKey.get(item.key) ?? [];
    existing.push(item);
    byKey.set(item.key, existing);
  }
  for (const [key, items] of [...byKey].sort(([left], [right]) => left.localeCompare(right))) {
    ctx.review.positive({
      key,
      summary: items.length === 1 ? items[0]!.summary : `${items.length} reviewed locations: ${items[0]!.summary}`,
      evidence: items.slice(0, 8).map((item) => ({
        location: { file: item.path, line: item.line },
        message: item.summary,
      })),
    });
  }
}
