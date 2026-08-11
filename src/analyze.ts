import { domain } from "./domain.js";
import { descendants, parseGo, sourceText } from "./parser.js";
import { type Analysis, type Discovery, type PositiveSignal, type Signal, type SourceRevision } from "./types.js";
import { type Node } from "web-tree-sitter";

export async function analyzeDiscovery(discovery: Discovery): Promise<Analysis> {
  const signals: Signal[] = [];
  const positives: PositiveSignal[] = [];
  const parseErrors: Analysis["parseErrors"] = [];

  for (const file of discovery.files) {
    try {
      if (file.path.endsWith(".go")) {
        const tree = await parseGo(file.current);
        try {
          if (tree.rootNode.hasError) throw new Error("Go source contains syntax errors");
          signals.push(...responseWriterCapabilitySignals(file, tree.rootNode));
        } finally {
          tree.delete();
        }
      }
      const result = domain.analyze(file);
      signals.push(...result.signals.filter((item) => changed(file, item.line, item.endLine)));
      positives.push(...result.positives.filter((item) => changed(file, item.line)));
    } catch (error) {
      parseErrors.push({ path: file.path, message: error instanceof Error ? error.message : String(error) });
    }
  }

  return {
    mode: discovery.mode,
    ...(discovery.base === undefined ? {} : { base: discovery.base }),
    filesScanned: discovery.files.length,
    signals: signals.sort(byLocation),
    positives: positives.sort(byLocation),
    parseErrors: parseErrors.sort((left, right) => left.path.localeCompare(right.path)),
  };
}

interface CapabilityClaim {
  line: number;
  endLine: number;
  text: string;
  capabilities: Array<"Flusher" | "Hijacker">;
}

function responseWriterCapabilitySignals(file: SourceRevision, root: Node): Signal[] {
  const claims = responseWriterCapabilityClaims(file, root);
  if (claims.length === 0) return [];

  const methods = descendants(root, "method_declaration");
  const signals: Signal[] = [];
  for (const typeSpec of descendants(root, "type_spec")) {
    const nameNode = typeSpec.childForFieldName("name");
    const typeNode = typeSpec.childForFieldName("type");
    if (nameNode === null || typeNode?.type !== "struct_type") continue;

    const structText = sourceText(typeNode, file.current);
    if (!/(?:http\.)?ResponseWriter\b|ResponseWriterWrapper\b/.test(structText)) continue;

    const typeName = sourceText(nameNode, file.current);
    const line = typeSpec.startPosition.row + 1;
    const claim = claims.find((item) => item.endLine < line && line - item.endLine <= 2);
    if (claim === undefined) continue;

    const declaredMethods = new Set<string>();
    for (const method of methods) {
      const receiver = method.childForFieldName("receiver");
      const methodName = method.childForFieldName("name");
      if (receiver === null || methodName === null) continue;
      if (!new RegExp(`\\b${escapeRegExp(typeName)}\\b`).test(sourceText(receiver, file.current))) continue;
      declaredMethods.add(sourceText(methodName, file.current));
    }

    const missing = claim.capabilities.filter((capability) =>
      capability === "Flusher" ? !declaredMethods.has("Flush") : !declaredMethods.has("Hijack")
    );
    if (missing.length === 0) continue;

    signals.push({
      ruleId: "go-http.response-writer-capabilities",
      path: file.path,
      line,
      message:
        `${typeName} claims to preserve direct ${claim.capabilities.join("/")} assertions but does not declare ` +
        `${missing.map((item) => item === "Flusher" ? "Flush" : "Hijack").join(" or ")}; ` +
        "ResponseController unwrapping does not satisfy ordinary interface assertions.",
      snippet: sourceText(typeSpec, file.current).trim().slice(0, 300),
      data: { wrapper: typeName, claimed: claim.capabilities, missing, claimLine: claim.line },
    });
  }
  return signals;
}

function responseWriterCapabilityClaims(file: SourceRevision, root: Node): CapabilityClaim[] {
  const comments = descendants(root, "comment").sort(
    (left, right) => left.startPosition.row - right.startPosition.row,
  );
  const groups: Node[][] = [];
  for (const comment of comments) {
    const group = groups[groups.length - 1];
    const previous = group?.[group.length - 1];
    if (group !== undefined && previous !== undefined &&
      comment.startPosition.row <= previous.endPosition.row + 1) {
      group.push(comment);
    } else {
      groups.push([comment]);
    }
  }

  const claims: CapabilityClaim[] = [];
  for (const group of groups) {
    const startLine = group[0]!.startPosition.row + 1;
    const endLine = group[group.length - 1]!.endPosition.row + 1;
    if (!changed(file, startLine, endLine)) continue;
    const text = group.map((node) => sourceText(node, file.current)).join(" ");
    if (!/(?:preserv|remain|type-assert|capabilit)/i.test(text)) continue;

    const capabilities: CapabilityClaim["capabilities"] = [];
    if (/\bFlusher\b/.test(text)) capabilities.push("Flusher");
    if (/\bHijacker\b/.test(text)) capabilities.push("Hijacker");
    if (capabilities.length > 0) claims.push({ line: startLine, endLine, text, capabilities });
  }
  return claims;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function changed(file: SourceRevision, line: number, endLine = line): boolean {
  if (file.status === "repository" || file.status === "added") return true;
  for (let candidate = line; candidate <= endLine; candidate += 1) {
    if (file.changedLines.has(candidate)) return true;
  }
  return false;
}

function byLocation(left: { path: string; line: number }, right: { path: string; line: number }): number {
  return left.path.localeCompare(right.path) || left.line - right.line;
}
