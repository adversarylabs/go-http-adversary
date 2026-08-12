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
          signals.push(...clientResponseBodyCloseSignals(file, tree.rootNode));
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

interface ClientResponseAcquisition {
  name: string;
  line: number;
}

function clientResponseBodyCloseSignals(file: SourceRevision, root: Node): Signal[] {
  const signals: Signal[] = [];
  const functions = [
    ...descendants(root, "function_declaration"),
    ...descendants(root, "method_declaration"),
    ...descendants(root, "func_literal"),
  ];

  for (const fn of functions) {
    const body = fn.childForFieldName("body");
    if (body === null) continue;
    const bodyText = sourceText(body, file.current);
    const acquisitions = clientResponseAcquisitions(bodyText, body.startPosition.row + 1);

    for (const acquisition of acquisitions) {
      const name = escapeRegExp(acquisition.name);
      if (new RegExp(`\\b${name}\\s*\\.\\s*Body\\s*\\.\\s*Close\\s*\\(`).test(bodyText)) continue;
      if (bodyTransfersOwnership(bodyText, name)) continue;
      if (bodyUsesCloseHelper(bodyText, name)) continue;

      const consumption = firstResponseBodyConsumption(bodyText, name);
      if (consumption === undefined) continue;
      const line = body.startPosition.row + 1 + bodyText.slice(0, consumption.index).split("\n").length - 1;
      if (!changed(file, acquisition.line, line)) continue;

      signals.push({
        ruleId: "go-http.client-response-body-close",
        path: file.path,
        line,
        message: `${acquisition.name}.Body is consumed in this function without being closed or returned to an owner.`,
        snippet: consumption.text.trim().slice(0, 300),
        data: { response: acquisition.name, acquisitionLine: acquisition.line, consumer: consumption.consumer },
      });
    }
  }
  return signals;
}

function clientResponseAcquisitions(body: string, bodyStartLine: number): ClientResponseAcquisition[] {
  const acquisitions: ClientResponseAcquisition[] = [];
  const assignment = /\b([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*)?\s*:?=\s*(?:http\.(?:Get|Post|Head|PostForm)|(?:[A-Za-z_]\w*\.)*(?:client|httpClient|httpclient|DefaultClient|hc|c)\.(?:Do|Get|Post|Head|PostForm)|(?:[A-Za-z_]\w*\.)*(?:transport|roundTripper|roundtripper|rt)\.RoundTrip)\s*\(/g;
  let match: RegExpExecArray | null;
  while ((match = assignment.exec(body)) !== null) {
    const name = match[1];
    if (name === undefined || name === "_") continue;
    acquisitions.push({
      name,
      line: bodyStartLine + body.slice(0, match.index).split("\n").length - 1,
    });
  }
  return acquisitions;
}

function firstResponseBodyConsumption(
  body: string,
  responseName: string,
): { index: number; text: string; consumer: string } | undefined {
  const responseBody = `${responseName}\\s*\\.\\s*Body`;
  const consumers: Array<{ name: string; pattern: RegExp }> = [
    { name: "ReadAll", pattern: new RegExp(`\\b(?:io|ioutil)\\.ReadAll\\s*\\(\\s*${responseBody}\\b`) },
    { name: "Decode", pattern: new RegExp(`\\b(?:json|xml)\\.NewDecoder\\s*\\(\\s*${responseBody}\\s*\\)\\s*\\.\\s*Decode\\s*\\(`) },
    { name: "Copy", pattern: new RegExp(`\\bio\\.(?:Copy|CopyBuffer)\\s*\\([^\\n,]+,\\s*${responseBody}\\b`) },
  ];
  let first: { index: number; text: string; consumer: string } | undefined;
  for (const consumer of consumers) {
    const match = consumer.pattern.exec(body);
    if (match === null || (first !== undefined && first.index <= match.index)) continue;
    first = { index: match.index, text: match[0], consumer: consumer.name };
  }
  return first;
}

function bodyTransfersOwnership(body: string, responseName: string): boolean {
  return body.split("\n").some((line) => {
    const returned = line.match(/\breturn\s+(.+)$/)?.[1];
    if (returned === undefined) return false;
    return returned.split(",").some((expression) =>
      new RegExp(`^\\s*${responseName}\\s*$`).test(expression.replace(/\/\/.*$/, "")),
    );
  });
}

function bodyUsesCloseHelper(body: string, responseName: string): boolean {
  const calls = body.matchAll(/\b([A-Za-z_]\w*)\s*\(([^)\n]*)\)/g);
  for (const call of calls) {
    const name = call[1] ?? "";
    const args = call[2] ?? "";
    if (!/(?:close|cleanup|release|discard)/i.test(name)) continue;
    if (new RegExp(`\\b${responseName}\\b`).test(args)) return true;
  }
  return false;
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
