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
          signals.push(...providerResponseBufferSignals(file, tree.rootNode));
          signals.push(...clientResponseBodyCloseSignals(file, tree.rootNode));
          signals.push(...cancelledResponsePublicationSignals(file, tree.rootNode));
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

interface OwnedResponseState {
  typeName: string;
  responseField: string;
  responseDeclaration: Node;
  completionField: string;
  completionDeclaration: Node;
  contextFields: Set<string>;
}

interface PublishedResponse {
  method: Node;
  methodName: string;
  receiver: string;
  assignment: Node;
  signal: Node;
  asyncStart: Node;
}

interface CancellationWaiter {
  method: Node;
  methodName: string;
  receiver: string;
  select: Node;
  completionCase: Node;
  cancellationCase: Node;
  cancellationReturn: Node;
}

interface ResponseOwner {
  method: Node;
  methodName: string;
  waitCall: Node;
  bodyUse: Node;
}

/**
 * Detect the narrow response-ownership race demonstrated by connect-go #938.
 *
 * This is intentionally a whole-chain proof, not a search for selects that
 * mention ctx.Done. A single receiver type must own the typed HTTP response
 * and completion channel, publish the response before signalling from an
 * asynchronously-started producer, race that signal against cancellation,
 * and have a caller that actually consumes or closes the published body.
 */
function cancelledResponsePublicationSignals(file: SourceRevision, root: Node): Signal[] {
  const httpAliases = standardImportAliases(root, file.current, "net/http", "http");
  const contextAliases = standardImportAliases(root, file.current, "context", "context");
  if (httpAliases.size === 0 || contextAliases.size === 0) return [];
  const lexicalFile = maskGoLexicalNoise(root, file.current);
  const methods = descendants(root, "method_declaration");
  const bodyConsumerPaths = standardBodyConsumerPaths(root, file.current);
  const signals: Signal[] = [];

  for (const state of ownedResponseStates(root, file.current, httpAliases, contextAliases)) {
    const typeMethods = methods.filter((method) => methodReceiverType(method, file.current) === state.typeName);
    const publishers = publishedResponses(state, typeMethods, lexicalFile, file.current);
    const waiters = cancellationWaiters(state, typeMethods, lexicalFile, file.current);

    for (const publisher of publishers) {
      if (producerOwnsPublishedResponse(publisher, state, lexicalFile, file.current)) continue;
      for (const waiter of waiters) {
        if (cancellationCaseHandlesResponse(waiter, state, typeMethods, lexicalFile, file.current)) continue;
        const owners = responseOwners(state, waiter, typeMethods, lexicalFile, file.current, bodyConsumerPaths);
        for (const owner of owners) {
          const evidence = firstChangedNode(file, [
            state.responseDeclaration,
            state.completionDeclaration,
            publisher.asyncStart,
            publisher.assignment,
            publisher.signal,
            waitReceiveNode(waiter.completionCase),
            waitReceiveNode(waiter.cancellationCase),
            waiter.cancellationReturn,
            owner.waitCall,
            owner.bodyUse,
          ]);
          if (evidence === undefined) continue;

          signals.push({
            ruleId: "go-http.cancelled-response-publication",
            path: file.path,
            line: evidence.startPosition.row + 1,
            endLine: evidence.endPosition.row + 1,
            message:
              `${state.typeName}.${publisher.methodName} publishes ${state.responseField} before signalling ` +
              `${state.completionField}, but ${state.typeName}.${waiter.methodName} can return cancellation ` +
              `without re-observing completion before ${state.typeName}.${owner.methodName} owns the response body.`,
            snippet: sourceText(evidence, file.current).trim().slice(0, 300),
            data: {
              ownerType: state.typeName,
              responseField: state.responseField,
              completionField: state.completionField,
              producer: publisher.methodName,
              waiter: waiter.methodName,
              responseOwner: owner.methodName,
              publicationLine: publisher.assignment.startPosition.row + 1,
              signalLine: publisher.signal.startPosition.row + 1,
              cancellationLine: waiter.cancellationCase.startPosition.row + 1,
              bodyOwnerLine: owner.bodyUse.startPosition.row + 1,
            },
          });
        }
      }
    }
  }
  return signals;
}

function ownedResponseStates(
  root: Node,
  source: string,
  httpAliases: Set<string>,
  contextAliases: Set<string>,
): OwnedResponseState[] {
  const states: OwnedResponseState[] = [];
  for (const typeSpec of descendants(root, "type_spec")) {
    const name = typeSpec.childForFieldName("name");
    const type = typeSpec.childForFieldName("type");
    if (name === null || type?.type !== "struct_type") continue;
    const responseFields: Array<{ name: string; node: Node }> = [];
    const completionFields: Array<{ name: string; node: Node }> = [];
    const contextFields = new Set<string>();
    for (const field of descendants(type, "field_declaration").filter((candidate) =>
      sameSyntaxNode(candidate.parent?.parent ?? null, type)
    )) {
      const text = sourceText(field, source).replace(/\s+/g, " ").trim();
      for (const alias of httpAliases) {
        const response = new RegExp(
          `^([A-Za-z_]\\w*(?:\\s*,\\s*[A-Za-z_]\\w*)*)\\s+\\*\\s*${escapeRegExp(alias)}\\s*\\.\\s*Response$`,
        ).exec(text);
        for (const fieldName of response?.[1]?.split(",").map((item) => item.trim()) ?? []) {
          responseFields.push({ name: fieldName, node: field });
        }
      }
      const completion = /^([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s+chan\s+struct\s*\{\s*\}$/.exec(text);
      for (const fieldName of completion?.[1]?.split(",").map((item) => item.trim()) ?? []) {
        completionFields.push({ name: fieldName, node: field });
      }
      for (const alias of contextAliases) {
        const context = new RegExp(
          `^([A-Za-z_]\\w*(?:\\s*,\\s*[A-Za-z_]\\w*)*)\\s+${escapeRegExp(alias)}\\s*\\.\\s*Context$`,
        ).exec(text);
        for (const fieldName of context?.[1]?.split(",").map((item) => item.trim()) ?? []) {
          contextFields.add(fieldName);
        }
      }
    }
    for (const response of responseFields) {
      for (const completion of completionFields) {
        states.push({
          typeName: sourceText(name, source),
          responseField: response.name,
          responseDeclaration: response.node,
          completionField: completion.name,
          completionDeclaration: completion.node,
          contextFields,
        });
      }
    }
  }
  return states;
}

function methodReceiverType(method: Node, source: string): string | undefined {
  const receiver = method.childForFieldName("receiver");
  if (receiver === null) return undefined;
  return sourceText(receiver, source).match(/\(\s*[A-Za-z_]\w*\s+\*?\s*([A-Za-z_]\w*)\s*\)/)?.[1];
}

function methodName(method: Node, source: string): string | undefined {
  const name = method.childForFieldName("name");
  return name === null ? undefined : sourceText(name, source);
}

function publishedResponses(
  state: OwnedResponseState,
  methods: Node[],
  lexicalFile: string,
  source: string,
): PublishedResponse[] {
  const publishers: PublishedResponse[] = [];
  for (const method of methods) {
    const body = method.childForFieldName("body");
    const receiver = methodReceiverName(method, source);
    const name = methodName(method, source);
    if (body === null || receiver === undefined || name === undefined) continue;
    const assignments = descendants(body, "assignment_statement").filter((node) => {
      if (!sameSyntaxNode(owningFunction(node), method) || !directlyReachableInBlock(body, node)) return false;
      const sides = assignmentSides(node);
      return sides !== undefined && pathEquals(selectorPath(sides.left, source), [receiver, state.responseField]);
    }).sort((left, right) => left.startIndex - right.startIndex);
    let assignment: Node | undefined;
    let signal: Node | undefined;
    for (const candidate of [...assignments].reverse()) {
      if (expressionIsNil(assignmentSides(candidate)?.right)) continue;
      const candidateSignal = producerSignalAfterPublication(method, candidate, receiver, state.completionField, lexicalFile);
      if (candidateSignal === undefined) continue;
      if (candidateSignal.type === "defer_statement") {
        if (!sameSyntaxNode(assignments.at(-1) ?? null, candidate)) break;
      } else if (assignments.some((later) =>
        later.startIndex > candidate.endIndex && later.endIndex < candidateSignal.startIndex
      )) continue;
      assignment = candidate;
      signal = candidateSignal;
      break;
    }
    if (assignment === undefined || signal === undefined) continue;
    const asyncStart = asyncProducerStart(methods, method, name, source);
    if (asyncStart === undefined) continue;
    publishers.push({ method, methodName: name, receiver, assignment, signal, asyncStart });
  }
  return publishers;
}

function producerSignalAfterPublication(
  method: Node,
  assignment: Node,
  receiver: string,
  completionField: string,
  lexicalFile: string,
): Node | undefined {
  const body = method.childForFieldName("body");
  if (body === null) return undefined;
  const deferred = descendants(body, "defer_statement").find((node) =>
    sameSyntaxNode(owningFunction(node), method) && directlyReachableInBlock(body, node) &&
    descendants(node, "call_expression").some((call) =>
      pathEquals(callPath(call, lexicalFile), ["close"]) &&
      unshadowedBuiltin(call, "close", lexicalFile) &&
      pathEquals(selectorPath(callArguments(call)[0], lexicalFile), [receiver, completionField])
    )
  );
  if (deferred !== undefined) return deferred;
  const candidates = [
    ...descendants(body, "expression_statement"),
    ...descendants(body, "send_statement"),
  ].filter((node) => sameSyntaxNode(owningFunction(node), method) && node.startIndex > assignment.endIndex);
  return candidates.find((node) => {
    if (!sameSyntaxNode(enclosingBlock(node), enclosingBlock(assignment)!)) return false;
    if (!directlyReachableInBlock(body, node)) return false;
    if (node.type === "send_statement") {
      return pathEquals(selectorPath(node.namedChildren[0], lexicalFile), [receiver, completionField]);
    }
    return descendants(node, "call_expression").some((call) =>
      pathEquals(callPath(call, lexicalFile), ["close"]) &&
      unshadowedBuiltin(call, "close", lexicalFile) &&
      pathEquals(selectorPath(callArguments(call)[0], lexicalFile), [receiver, completionField])
    );
  });
}

function asyncProducerStart(methods: Node[], producer: Node, producerName: string, source: string): Node | undefined {
  for (const method of methods) {
    if (sameSyntaxNode(method, producer)) continue;
    const body = method.childForFieldName("body");
    const receiver = methodReceiverName(method, source);
    if (body === null || receiver === undefined) continue;
    const start = descendants(body, "go_statement").find((node) =>
      sameSyntaxNode(owningFunction(node), method) && directlyReachableInBlock(body, node) &&
      descendants(node, "call_expression").some((call) =>
        pathEquals(callPath(call, source), [receiver, producerName])
      )
    );
    if (start !== undefined) return start;
  }
  return undefined;
}

function cancellationWaiters(
  state: OwnedResponseState,
  methods: Node[],
  lexicalSource: string,
  source: string,
): CancellationWaiter[] {
  const waiters: CancellationWaiter[] = [];
  for (const method of methods) {
    const body = method.childForFieldName("body");
    const receiver = methodReceiverName(method, source);
    const name = methodName(method, source);
    if (body === null || receiver === undefined || name === undefined) continue;
    for (const select of descendants(body, "select_statement")) {
      if (!sameSyntaxNode(owningFunction(select), method) || !directlyReachableInBlock(body, select)) continue;
      const cases = select.namedChildren.filter((child) => child.type === "communication_case");
      const completionCase = cases.find((item) =>
        communicationReceiveMatches(item, lexicalSource, receiver, state.completionField)
      );
      const cancellationCase = cases.find((item) =>
        communicationReceivesContextDone(item, lexicalSource, receiver, state.contextFields)
      );
      if (completionCase === undefined || cancellationCase === undefined) continue;
      const cancellationReturn = descendants(cancellationCase, "return_statement")
        .filter((item) => sameSyntaxNode(owningFunction(item), method))
        .sort((left, right) => left.startIndex - right.startIndex)[0];
      if (cancellationReturn === undefined) continue;
      waiters.push({
        method,
        methodName: name,
        receiver,
        select,
        completionCase,
        cancellationCase,
        cancellationReturn,
      });
    }
  }
  return waiters;
}

function waitReceiveNode(caseNode: Node): Node {
  return caseNode.namedChildren.find((child) => child.type === "receive_statement") ?? caseNode;
}

function directCaseStatements(caseNode: Node): Node[] {
  return caseNode.namedChildren.find((child) => child.type === "statement_list")?.namedChildren ?? [];
}

function communicationReceiveMatches(caseNode: Node, source: string, receiver: string, field: string): boolean {
  return pathEquals(receiveTargetPath(waitReceiveNode(caseNode), source), [receiver, field]);
}

function communicationReceivesContextDone(
  caseNode: Node,
  source: string,
  receiver: string,
  contextFields: Set<string>,
): boolean {
  return [...contextFields].some((field) =>
    pathEquals(receiveTargetPath(waitReceiveNode(caseNode), source), [receiver, field, "Done"])
  );
}

function cancellationCaseHandlesResponse(
  waiter: CancellationWaiter,
  state: OwnedResponseState,
  methods: Node[],
  lexicalSource: string,
  source: string,
): boolean {
  const statements = waiter.cancellationCase.namedChildren.find((child) => child.type === "statement_list");
  if (statements === undefined) return false;
  const topLevel = directCaseStatements(waiter.cancellationCase);
  const returnIndex = topLevel.findIndex((statement) => sameSyntaxNode(statement, waiter.cancellationReturn));
  if (returnIndex < 0) return false;
  return topLevel.slice(0, returnIndex).some((statement) => {
    if (["expression_statement", "assignment_statement", "short_var_declaration"].includes(statement.type) &&
      communicationReceiveTextMatches(statement, lexicalSource, waiter.receiver, state.completionField)) return true;
    if (statement.type !== "expression_statement") return false;
    return descendants(statement, "call_expression").some((call) => {
      if (!sameSyntaxNode(owningFunction(call), waiter.method)) return false;
      const path = callPath(call, lexicalSource);
      if (path?.length !== 2 || path[0] !== waiter.receiver) return false;
      const helper = methods.find((method) => methodName(method, source) === path[1]);
      return helper !== undefined && helperSynchronizesAndCloses(helper, state, lexicalSource, source);
    });
  });
}

function communicationReceiveTextMatches(node: Node, source: string, receiver: string, field: string): boolean {
  return pathEquals(receiveTargetPath(node, source), [receiver, field]);
}

function producerOwnsPublishedResponse(
  publisher: PublishedResponse,
  state: OwnedResponseState,
  lexicalSource: string,
  source: string,
): boolean {
  const body = publisher.method.childForFieldName("body");
  if (body === null) return false;
  const assigned = unwrapExpression(assignmentSides(publisher.assignment)?.right);
  const assignedName = assigned?.type === "identifier" ? sourceText(assigned, source) : undefined;
  const directlyClosed = descendants(body, "call_expression").some((call) => {
    if (!sameSyntaxNode(owningFunction(call), publisher.method) || call.startIndex <= publisher.assignment.endIndex ||
      !directlyReachableInBlock(body, call)) return false;
    if (!sameSyntaxNode(enclosingBlock(call), enclosingBlock(publisher.assignment)!)) return false;
    const path = callPath(call, lexicalSource);
    return pathEquals(path, [publisher.receiver, state.responseField, "Body", "Close"]) ||
      (assignedName !== undefined && pathEquals(path, [assignedName, "Body", "Close"]));
  });
  if (directlyClosed) return true;

  return descendants(body, "call_expression").some((invocation) => {
    if (!sameSyntaxNode(owningFunction(invocation), publisher.method) ||
      invocation.startIndex <= publisher.assignment.endIndex || !directlyReachableInBlock(body, invocation)) return false;
    if (directStatementContaining(body, invocation)?.type !== "expression_statement") return false;
    const literal = invocation.childForFieldName("function");
    if (literal?.type !== "func_literal" || callArguments(invocation).length !== 0) return false;
    const literalBody = literal.childForFieldName("body");
    if (literalBody === null) return false;
    return descendants(literalBody, "call_expression").some((call) => {
      if (!sameSyntaxNode(owningFunction(call), literal) || !directlyReachableInBlock(literalBody, call)) return false;
      const path = callPath(call, lexicalSource);
      return pathEquals(path, [publisher.receiver, state.responseField, "Body", "Close"]) ||
        (assignedName !== undefined && pathEquals(path, [assignedName, "Body", "Close"]));
    });
  });
}

function responseOwners(
  state: OwnedResponseState,
  waiter: CancellationWaiter,
  methods: Node[],
  lexicalSource: string,
  source: string,
  bodyConsumerPaths: Set<string>,
): ResponseOwner[] {
  const owners: ResponseOwner[] = [];
  const wrappers = responseWaitWrappers(state, waiter, methods, lexicalSource, source);
  for (const method of methods) {
    if (sameSyntaxNode(method, waiter.method)) continue;
    const body = method.childForFieldName("body");
    const receiver = methodReceiverName(method, source);
    const name = methodName(method, source);
    if (body === null || receiver === undefined || name === undefined) continue;
    const waitCalls = descendants(body, "call_expression").filter((call) =>
      sameSyntaxNode(owningFunction(call), method) && isDirectStatement(body, call) &&
      directlyReachableInBlock(body, call) && pathEquals(callPath(call, lexicalSource), [receiver, waiter.methodName])
    );
    for (const waitCall of waitCalls) {
      if (waitCallHasTerminatingErrorGuard(waitCall, lexicalSource)) continue;
      const bodyUse = responseBodyUseAfter(body, waitCall, [receiver, state.responseField], lexicalSource, bodyConsumerPaths);
      if (bodyUse === undefined) continue;
      if (!sameSyntaxNode(enclosingBlock(waitCall), enclosingBlock(bodyUse)!)) continue;
      if (hasUnconditionalReturnBetween(body, waitCall, bodyUse)) continue;
      if (callerReobservesCompletion(body, waitCall, bodyUse, receiver, state.completionField, lexicalSource)) continue;
      owners.push({ method, methodName: name, waitCall, bodyUse });
    }

    for (const wrapper of wrappers) {
      for (const wrapperCall of descendants(body, "call_expression").filter((call) =>
        sameSyntaxNode(owningFunction(call), method) && isDirectStatement(body, call) &&
        directlyReachableInBlock(body, call) && pathEquals(callPath(call, lexicalSource), [receiver, wrapper.name])
      )) {
        const responseName = assignedIdentifier(wrapperCall, source);
        if (responseName === undefined) continue;
        const bodyUse = responseBodyUseAfter(body, wrapperCall, [responseName], lexicalSource, bodyConsumerPaths);
        if (bodyUse === undefined || !sameSyntaxNode(enclosingBlock(wrapperCall), enclosingBlock(bodyUse)!)) continue;
        if (hasUnconditionalReturnBetween(body, wrapperCall, bodyUse)) continue;
        owners.push({ method, methodName: name, waitCall: wrapperCall, bodyUse });
      }
    }
  }
  return owners;
}

function responseBodyUseAfter(
  body: Node,
  waitCall: Node,
  responsePath: string[],
  source: string,
  bodyConsumerPaths: Set<string>,
): Node | undefined {
  return descendants(body, "call_expression").find((call) => {
    if (call.startIndex <= waitCall.endIndex || !sameSyntaxNode(owningFunction(call), owningFunction(waitCall)!) ||
      !directlyReachableInBlock(body, call)) return false;
    const path = callPath(call, source);
    const bodyPath = [...responsePath, "Body"];
    if (pathEquals(path, [...bodyPath, "Close"]) || pathEquals(path, [...bodyPath, "Read"])) return true;
    if (path === undefined || !bodyConsumerPaths.has(path.join("."))) return false;
    return callArguments(call).some((argument) => pathEquals(selectorPath(argument, source), bodyPath));
  });
}

function callerReobservesCompletion(
  body: Node,
  waitCall: Node,
  bodyUse: Node,
  receiver: string,
  completionField: string,
  source: string,
): boolean {
  return [...descendants(body, "receive_statement"), ...descendants(body, "expression_statement")].some((receive) =>
    sameSyntaxNode(owningFunction(receive), owningFunction(waitCall)!) &&
    sameSyntaxNode(enclosingBlock(receive), enclosingBlock(waitCall)!) &&
    receive.startIndex > waitCall.endIndex && receive.endIndex < bodyUse.startIndex &&
    communicationReceiveTextMatches(receive, source, receiver, completionField)
  );
}

function waitCallHasTerminatingErrorGuard(waitCall: Node, source: string): boolean {
  let current: Node | null = waitCall.parent;
  while (current !== null && current.type !== "if_statement") {
    if (current.type === "statement_list" || current.type === "block") return false;
    current = current.parent;
  }
  if (current === null) return false;
  const initializer = current.namedChildren.find((child) => child.type === "short_var_declaration");
  const consequence = current.namedChildren.find((child) => child.type === "block");
  if (initializer === undefined || consequence === undefined || !containsNode(initializer, waitCall)) return false;
  const sides = assignmentSides(initializer);
  if (sides?.left.type !== "identifier") return false;
  const errorName = sourceText(sides.left, source).trim();
  const condition = current.namedChildren.find((child) => child.type === "binary_expression");
  if (condition === undefined || sourceText(condition, source).replace(/\s/g, "") !== `${errorName}!=nil`) return false;
  return topLevelStatements(consequence).some((statement) => statement.type === "return_statement");
}

interface ResponseWaitWrapper {
  name: string;
}

function responseWaitWrappers(
  state: OwnedResponseState,
  waiter: CancellationWaiter,
  methods: Node[],
  lexicalSource: string,
  source: string,
): ResponseWaitWrapper[] {
  const wrappers: ResponseWaitWrapper[] = [];
  for (const method of methods) {
    if (sameSyntaxNode(method, waiter.method)) continue;
    const body = method.childForFieldName("body");
    const receiver = methodReceiverName(method, source);
    const name = methodName(method, source);
    if (body === null || receiver === undefined || name === undefined) continue;
    const waitCall = descendants(body, "call_expression").find((call) =>
      sameSyntaxNode(owningFunction(call), method) && directlyReachableInBlock(body, call) &&
      pathEquals(callPath(call, lexicalSource), [receiver, waiter.methodName])
    );
    if (waitCall === undefined) continue;
    const responseReturn = descendants(body, "return_statement").find((statement) =>
      sameSyntaxNode(owningFunction(statement), method) && directlyReachableInBlock(body, statement) &&
      statement.startIndex > waitCall.endIndex &&
      statement.namedChildren.some((child) => pathEquals(selectorPath(child, lexicalSource), [receiver, state.responseField]))
    );
    if (responseReturn === undefined || hasUnconditionalReturnBetween(body, waitCall, responseReturn)) continue;
    if (callerReobservesCompletion(body, waitCall, responseReturn, receiver, state.completionField, lexicalSource)) continue;
    wrappers.push({ name });
  }
  return wrappers;
}

function helperSynchronizesAndCloses(
  method: Node,
  state: OwnedResponseState,
  lexicalSource: string,
  source: string,
): boolean {
  const body = method.childForFieldName("body");
  const receiver = methodReceiverName(method, source);
  if (body === null || receiver === undefined) return false;
  const statements = topLevelStatements(body);
  const receive = statements.find((statement) =>
    communicationReceiveTextMatches(statement, lexicalSource, receiver, state.completionField)
  );
  if (receive === undefined || !directlyReachableInBlock(body, receive)) return false;
  const directClose = descendants(body, "call_expression").some((call) =>
    sameSyntaxNode(owningFunction(call), method) && call.startIndex > receive.endIndex &&
    directlyReachableInBlock(body, call) &&
    pathEquals(callPath(call, lexicalSource), [receiver, state.responseField, "Body", "Close"])
  );
  if (directClose) return true;
  return statements.some((statement) => {
    if (statement.type !== "if_statement" || statement.startIndex <= receive.endIndex ||
      !directlyReachableInBlock(body, statement)) return false;
    const condition = statement.childForFieldName("condition") ??
      statement.namedChildren.find((child) => child.type === "binary_expression");
    const consequence = statement.childForFieldName("consequence") ??
      statement.namedChildren.find((child) => child.type === "block");
    if (condition === null || condition === undefined || consequence === null || consequence === undefined) return false;
    const expected = `${receiver}.${state.responseField}!=nil`;
    if (sourceText(condition, lexicalSource).replace(/\s/g, "") !== expected) return false;
    return descendants(consequence, "call_expression").some((call) =>
      sameSyntaxNode(owningFunction(call), method) && directlyReachableInBlock(consequence, call) &&
      pathEquals(callPath(call, lexicalSource), [receiver, state.responseField, "Body", "Close"])
    );
  });
}

function receiveTargetPath(node: Node, source: string): string[] | undefined {
  const owner = owningFunction(node);
  if (owner === null) return undefined;
  const receive = [node, ...descendants(node, "unary_expression")].find((candidate) =>
    candidate.type === "unary_expression" && sameSyntaxNode(owningFunction(candidate), owner) &&
    sourceText(candidate, source).trimStart().startsWith("<-")
  );
  const operand = receive?.namedChildren[0];
  if (operand === undefined) return undefined;
  const unwrapped = unwrapExpression(operand);
  return unwrapped?.type === "call_expression" ? callPath(unwrapped, source) : selectorPath(unwrapped, source);
}

function standardBodyConsumerPaths(root: Node, source: string): Set<string> {
  const paths = new Set<string>();
  for (const alias of standardImportAliases(root, source, "io", "io")) {
    for (const name of ["ReadAll", "Copy", "CopyBuffer"]) paths.add(`${alias}.${name}`);
  }
  for (const module of ["encoding/json", "encoding/xml"] as const) {
    const fallback = module.split("/").at(-1)!;
    for (const alias of standardImportAliases(root, source, module, fallback)) paths.add(`${alias}.NewDecoder`);
  }
  return paths;
}

function selectorPath(node: Node | undefined | null, source: string): string[] | undefined {
  if (node === undefined || node === null) return undefined;
  if (node.type === "identifier") return [sourceText(node, source).trim()];
  if (node.type === "selector_expression") {
    const operand = selectorPath(node.childForFieldName("operand"), source);
    const field = node.childForFieldName("field");
    return operand === undefined || field === null ? undefined : [...operand, sourceText(field, source).trim()];
  }
  if (node.type === "parenthesized_expression" && node.namedChildren.length === 1) {
    return selectorPath(node.namedChildren[0], source);
  }
  if (node.type === "expression_list" && node.namedChildren.length === 1) {
    return selectorPath(node.namedChildren[0], source);
  }
  return undefined;
}

function callPath(call: Node, source: string): string[] | undefined {
  if (call.type !== "call_expression") return undefined;
  return selectorPath(call.childForFieldName("function"), source);
}

function callArguments(call: Node): Node[] {
  return call.childForFieldName("arguments")?.namedChildren ?? [];
}

function pathEquals(actual: string[] | undefined, expected: string[]): boolean {
  return actual !== undefined && actual.length === expected.length &&
    actual.every((part, index) => part === expected[index]);
}

function assignmentSides(statement: Node): { left: Node; right: Node } | undefined {
  const rawLeft = statement.childForFieldName("left") ?? statement.namedChildren[0];
  const rawRight = statement.childForFieldName("right") ?? statement.namedChildren.at(-1);
  const left = rawLeft?.type === "expression_list" && rawLeft.namedChildren.length === 1
    ? rawLeft.namedChildren[0]
    : rawLeft;
  const right = rawRight?.type === "expression_list" && rawRight.namedChildren.length === 1
    ? rawRight.namedChildren[0]
    : rawRight;
  return left === undefined || right === undefined ? undefined : { left, right };
}

function unwrapExpression(node: Node | undefined | null): Node | undefined {
  let current = node ?? undefined;
  while (current !== undefined &&
    (current.type === "parenthesized_expression" || current.type === "expression_list") &&
    current.namedChildren.length === 1) {
    current = current.namedChildren[0];
  }
  return current;
}

function expressionIsNil(node: Node | undefined): boolean {
  return unwrapExpression(node)?.type === "nil";
}

function assignedIdentifier(call: Node, source: string): string | undefined {
  let current = call.parent;
  while (current !== null && current.type !== "assignment_statement" && current.type !== "short_var_declaration") {
    if (current.type === "statement_list" || current.type === "block") return undefined;
    current = current.parent;
  }
  if (current === null) return undefined;
  const sides = assignmentSides(current);
  return sides?.left.type === "identifier" ? sourceText(sides.left, source).trim() : undefined;
}

function isDirectStatement(block: Node, node: Node): boolean {
  let current: Node | null = node;
  while (current !== null && current.parent !== null) {
    if (current.parent.type === "statement_list") return sameSyntaxNode(current.parent.parent, block);
    current = current.parent;
  }
  return false;
}

function directlyReachableInBlock(block: Node, node: Node): boolean {
  const statement = directStatementContaining(block, node);
  if (statement === undefined) return false;
  return !topLevelStatements(block).some((candidate) =>
    candidate.endIndex < statement.startIndex && candidate.type === "return_statement"
  );
}

function unshadowedBuiltin(use: Node, name: string, source: string): boolean {
  let root: Node = use;
  while (root.parent !== null) root = root.parent;
  for (const declaration of descendants(root, "function_declaration")) {
    const declared = declaration.childForFieldName("name");
    if (declared !== null && sourceText(declared, source) === name) return false;
  }
  for (const declaration of [...descendants(root, "type_spec"), ...descendants(root, "var_spec"), ...descendants(root, "const_spec")]) {
    if (owningFunction(declaration) !== null) continue;
    if (declarationNames(declaration, source).has(name)) return false;
  }
  for (const spec of descendants(root, "import_spec")) {
    if (new RegExp(`^${escapeRegExp(name)}\\s+[\"\u0060]`).test(sourceText(spec, source).trim())) return false;
  }

  const owner = owningFunction(use);
  if (owner === null) return true;
  const body = owner.childForFieldName("body");
  const signature = source.slice(owner.startIndex, body?.startIndex ?? owner.endIndex);
  if (new RegExp(`(?:\\(|,)\\s*${escapeRegExp(name)}(?:\\s|,)`).test(signature)) return false;
  for (const declaration of [
    ...descendants(owner, "short_var_declaration"),
    ...descendants(owner, "var_spec"),
    ...descendants(owner, "const_spec"),
  ]) {
    if (declaration.startIndex >= use.startIndex || !sameSyntaxNode(owningFunction(declaration), owner)) continue;
    if (!declarationNames(declaration, source).has(name)) continue;
    const scope = enclosingBlock(declaration);
    if (scope !== null && containsNode(scope, use)) return false;
  }
  return true;
}

function declarationNames(node: Node, source: string): Set<string> {
  let candidate = node;
  if (node.type === "short_var_declaration") candidate = node.childForFieldName("left") ?? node.namedChildren[0] ?? node;
  const text = sourceText(candidate, source).split(/:=|=|\s+(?=[A-Za-z_*\[])/, 1)[0] ?? "";
  return new Set(text.split(",").map((part) => part.trim()).filter((part) => /^[A-Za-z_]\w*$/.test(part)));
}

function directStatementContaining(block: Node, node: Node): Node | undefined {
  let current: Node | null = node;
  while (current !== null && current.parent !== null) {
    if (current.parent.type === "statement_list") {
      return sameSyntaxNode(current.parent.parent, block) ? current : undefined;
    }
    current = current.parent;
  }
  return undefined;
}

function hasUnconditionalReturnBetween(block: Node, before: Node, after: Node): boolean {
  const beforeStatement = directStatementContaining(block, before);
  const afterStatement = directStatementContaining(block, after);
  if (beforeStatement === undefined || afterStatement === undefined) return true;
  return topLevelStatements(block).some((statement) =>
    statement.type === "return_statement" &&
    statement.startIndex > beforeStatement.endIndex && statement.endIndex < afterStatement.startIndex
  );
}

function containsNode(container: Node, candidate: Node): boolean {
  return candidate.startIndex >= container.startIndex && candidate.endIndex <= container.endIndex;
}

function enclosingBlock(node: Node): Node | null {
  let current = node.parent;
  while (current !== null) {
    if (current.type === "block") return current;
    current = current.parent;
  }
  return null;
}

function firstChangedNode(file: SourceRevision, nodes: Node[]): Node | undefined {
  return nodes.find((node) => semanticallyChanged(file, node.startPosition.row + 1, node.endPosition.row + 1));
}

function semanticallyChanged(file: SourceRevision, line: number, endLine = line): boolean {
  if (!changed(file, line, endLine)) return false;
  if (file.status !== "modified") return true;
  const currentLines = file.current.split("\n");
  if (file.previous === undefined) {
    return [...file.changedLines].some((candidate) =>
      candidate >= line && candidate <= endLine && !hasInlineGoComment(currentLines[candidate - 1] ?? "")
    );
  }
  const previousLines = file.previous.split("\n");
  for (let candidate = line; candidate <= endLine; candidate += 1) {
    if (!file.changedLines.has(candidate)) continue;
    const current = goLineSemantics(currentLines[candidate - 1] ?? "");
    const previous = goLineSemantics(previousLines[candidate - 1] ?? "");
    if (current !== previous) return true;
  }
  return false;
}

function hasInlineGoComment(line: string): boolean {
  return goLineSemantics(line) !== line.replace(/\s+/g, "").trim();
}

function goLineSemantics(line: string): string {
  let quote: '"' | "'" | "`" | undefined;
  let escaped = false;
  let semantic = "";
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index]!;
    const next = line[index + 1];
    if (quote === undefined && character === "/" && next === "/") break;
    if (quote === undefined && character === "/" && next === "*") {
      const end = line.indexOf("*/", index + 2);
      if (end < 0) break;
      index = end + 1;
      continue;
    }
    semantic += character;
    if (quote === "`") {
      if (character === "`") quote = undefined;
      continue;
    }
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") quote = character;
  }
  return semantic.replace(/\s+/g, "").trim();
}

interface BufferedWriterUse {
  variable: string;
  line: number;
  method: string;
  node: Node;
  relationships: Node[];
}

/**
 * Find production ResponseWriter substitutes that accumulate body bytes from a
 * downstream/provider callback without a size contract. This is deliberately
 * narrower than "a struct contains bytes.Buffer": the type must implement the
 * ResponseWriter surface and an instance must cross a callback boundary.
 */
function providerResponseBufferSignals(file: SourceRevision, root: Node): Signal[] {
  const lexicalFile = maskGoLexicalNoise(root, file.current);
  const methods = descendants(root, "method_declaration");
  const bytesAliases = standardImportAliases(root, file.current, "bytes", "bytes");
  const httpAliases = standardImportAliases(root, file.current, "net/http", "http");
  const signals: Signal[] = [];

  for (const typeSpec of descendants(root, "type_spec")) {
    const nameNode = typeSpec.childForFieldName("name");
    const typeNode = typeSpec.childForFieldName("type");
    if (nameNode === null || typeNode?.type !== "struct_type") continue;

    const typeName = sourceText(nameNode, file.current);
    const bufferDeclarations = descendants(typeNode, "field_declaration").flatMap((field) => {
      const text = sourceText(field, file.current);
      const fields = [...bytesAliases].flatMap((alias) => {
        const match = new RegExp(
          `^\\s*([A-Za-z_]\\w*(?:\\s*,\\s*[A-Za-z_]\\w*)*)\\s+${escapeRegExp(alias)}\\s*\\.\\s*Buffer\\b`,
        ).exec(text);
        return match?.[1]?.split(",").map((name) => name.trim()).filter(Boolean) ?? [];
      });
      return fields.map((name) => ({ node: field, name }));
    });
    if (bufferDeclarations.length === 0) continue;

    const typeMethods = methods.filter((method) => {
      const receiver = method.childForFieldName("receiver");
      return receiver !== null && new RegExp(`\\b${escapeRegExp(typeName)}\\b`).test(sourceText(receiver, file.current));
    });
    if (!implementsResponseWriter(typeMethods, file.current, httpAliases)) continue;

    const writeMethod = typeMethods.find((method) => {
      const name = method.childForFieldName("name");
      return name !== null && sourceText(name, file.current) === "Write";
    });
    if (writeMethod === undefined) continue;
    const writeBody = writeMethod.childForFieldName("body");
    if (writeBody === null) continue;
    const writeReceiver = methodReceiverName(writeMethod, file.current);
    if (writeReceiver === undefined) continue;
    const writeInput = sourceText(writeMethod, file.current)
      .match(/\bWrite\s*\(\s*([A-Za-z_]\w*)\s+\[\s*\]\s*byte\b/)?.[1];
    if (writeInput === undefined) continue;
    const accumulatingWrites = descendants(writeBody, "call_expression").flatMap((call) => {
      const fn = call.childForFieldName("function");
      const argumentsNode = call.childForFieldName("arguments");
      if (fn?.type !== "selector_expression" || argumentsNode === null) return [];
      const expression = sourceText(fn, file.current).replace(/\s/g, "");
      const declaration = bufferDeclarations.find(({ name }) => expression === `${writeReceiver}.${name}.Write`);
      const argument = argumentsNode.namedChildren.length === 1
        ? sourceText(argumentsNode.namedChildren[0]!, file.current).trim()
        : "";
      return declaration === undefined || argument !== writeInput ? [] : [{ call, declaration }];
    });
    const uses = responseWriterCallbackUses(root, lexicalFile, file.current, typeName, httpAliases);

    for (const { call: writeCall, declaration } of accumulatingWrites) {
      const bufferField = declaration.name;
      if (writeHasProvenBound(writeMethod, writeCall, file.current, writeReceiver, bufferField)) continue;
      for (const use of uses) {
        const writeLine = writeCall.startPosition.row + 1;
        const bufferLine = declaration.node.startPosition.row + 1;
        const typeLine = typeSpec.startPosition.row + 1;
        const changedEvidence = [
          { line: writeLine, snippet: sourceText(writeCall, file.current).trim() },
          { line: bufferLine, snippet: sourceText(declaration.node, file.current).trim() },
          ...use.relationships.map((node) => ({
            line: node.startPosition.row + 1,
            snippet: sourceText(node, file.current).trim(),
          })),
          { line: use.line, snippet: sourceText(use.node, file.current).trim() },
        ].find((evidence) => changed(file, evidence.line));
        if (changedEvidence === undefined) continue;

        signals.push({
          ruleId: "go-http.provider-response-buffer-limit",
          path: file.path,
          line: changedEvidence.line,
          message:
            `${typeName} accumulates body data written by ${use.method} into ${bufferField} without a proven cap, ` +
            "streaming/backpressure, or spill strategy.",
          snippet: changedEvidence.snippet.slice(0, 300),
          data: {
            wrapper: typeName,
            bufferField,
            bufferLine,
            writeLine,
            callbackVariable: use.variable,
            callbackMethod: use.method,
            callbackLine: use.line,
            relationshipLines: use.relationships.map((node) => node.startPosition.row + 1),
            typeLine,
          },
        });
      }
    }
  }
  return signals;
}

function standardImportAliases(root: Node, source: string, path: string, defaultAlias: string): Set<string> {
  const aliases = new Set<string>();
  for (const spec of descendants(root, "import_spec")) {
    const text = sourceText(spec, source).trim();
    const match = /^(?:([A-Za-z_]\w*)\s+)?["`]([^"`]+)["`]$/.exec(text);
    if (match?.[2] !== path) continue;
    const alias = match[1] ?? defaultAlias;
    if (alias !== "_" && alias !== ".") aliases.add(alias);
  }
  return aliases;
}

function implementsResponseWriter(methods: Node[], source: string, httpAliases: Set<string>): boolean {
  const compactSignatures = new Map<string, string>();
  for (const method of methods) {
    const name = method.childForFieldName("name");
    if (name === null) continue;
    const body = method.childForFieldName("body");
    const signature = source.slice(method.startIndex, body?.startIndex ?? method.endIndex).replace(/\s/g, "");
    compactSignatures.set(sourceText(name, source), signature);
  }
  const header = compactSignatures.get("Header") ?? "";
  const writeHeader = compactSignatures.get("WriteHeader") ?? "";
  const write = compactSignatures.get("Write") ?? "";
  const headerType = [...httpAliases].some((alias) =>
    new RegExp(`Header\\(\\)(?:[A-Za-z_]\\w*)?${escapeRegExp(alias)}\\.Header$`).test(header)
  );
  return headerType &&
    /WriteHeader\((?:[A-Za-z_]\w*)?int\)$/.test(writeHeader) &&
    /Write\((?:[A-Za-z_]\w*)?\[\]byte\)\((?:[A-Za-z_]\w*)?int,(?:[A-Za-z_]\w*)?error\)$/.test(write);
}

function methodReceiverName(method: Node, source: string): string | undefined {
  const receiver = method.childForFieldName("receiver");
  if (receiver === null) return undefined;
  return sourceText(receiver, source).match(/\(\s*([A-Za-z_]\w*)\s+/)?.[1];
}

function writeHasProvenBound(
  writeMethod: Node,
  accumulatingWrite: Node,
  source: string,
  writeReceiver: string,
  bufferField: string,
): boolean {
  const methodText = maskGoLexicalNoise(writeMethod, source);
  const input = methodText.match(/\bWrite\s*\(\s*([A-Za-z_]\w*)\s+\[\s*\]\s*byte\b/)?.[1];
  if (input === undefined) return false;

  const compact = (value: string) => value.replace(/\s/g, "");
  const inputLength = `len\\(${escapeRegExp(input)}\\)`;
  const bufferExpression = `${escapeRegExp(writeReceiver)}\\.${escapeRegExp(bufferField)}`;
  const bufferLength = `${bufferExpression}\\.Len\\(\\)`;
  const bound = `(?:(?:[A-Za-z_]\\w*\\.)*(?:max(?:imum)?\\w*|(?:limit|cap|quota|budget)\\w*|[A-Za-z_]\\w*(?:limit|cap|quota|budget)\\w*)|[1-9]\\d*)`;
  const sum = `(?:${bufferLength}\\+${inputLength}|${inputLength}\\+${bufferLength})`;
  const remaining = `(?:${bound}-${bufferLength})`;

  const body = writeMethod.childForFieldName("body");
  if (body === null) return false;
  for (const branch of topLevelStatements(body).filter((node) =>
    node.type === "if_statement" && node.endIndex <= accumulatingWrite.startIndex
  )) {
    const consequence = [...branch.namedChildren].find((child) => child.type === "block") ?? null;
    const condition = [...branch.namedChildren].find((child) => child.type === "binary_expression") ?? null;
    const initializer = [...branch.namedChildren].find((child) => child.type === "short_var_declaration") ?? null;
    if (condition === null || consequence === null || !hasUnconditionalTopLevelReturn(consequence)) continue;
    const conditionText = compact(maskGoLexicalNoise(condition, source));
    const consequenceText = compact(maskGoLexicalNoise(consequence, source));
    const unboundedWrite = new RegExp(
      `${bufferExpression}\\.Write\\(${escapeRegExp(input)}\\)`,
    ).test(consequenceText);
    if (initializer === null) {
      const rejectsOverflow = [
        new RegExp(`^${sum}(?:>|>=)${bound}$`, "i"),
        new RegExp(`^${bound}(?:<|<=)${sum}$`, "i"),
        new RegExp(`^${inputLength}(?:>|>=)${remaining}$`, "i"),
        new RegExp(`^${remaining}(?:<|<=)${inputLength}$`, "i"),
      ].some((pattern) => pattern.test(conditionText));
      if (rejectsOverflow && !unboundedWrite) return true;
      continue;
    }

    const initializerText = compact(maskGoLexicalNoise(initializer, source));
    const room = new RegExp(`^([A-Za-z_]\\w*):=${bound}-${bufferLength}$`, "i").exec(initializerText)?.[1];
    if (room === undefined) continue;
    if (!new RegExp(`^${escapeRegExp(room)}(?:<|<=)${inputLength}$`).test(conditionText)) continue;
    const boundedWrite = new RegExp(
      `${bufferExpression}\\.Write\\(${escapeRegExp(input)}\\[:${escapeRegExp(room)}\\]\\)`,
    ).test(consequenceText);
    const guardsPositiveRoom = descendants(consequence, "if_statement").some((inner) => {
      const innerCondition = [...inner.namedChildren].find((child) => child.type === "binary_expression");
      const innerBlock = [...inner.namedChildren].find((child) => child.type === "block");
      if (innerCondition === undefined || innerBlock === undefined) return false;
      const conditionText = compact(maskGoLexicalNoise(innerCondition, source));
      const blockText = compact(maskGoLexicalNoise(innerBlock, source));
      return new RegExp(`(?:${escapeRegExp(room)}>0|0<${escapeRegExp(room)})`).test(conditionText) &&
        new RegExp(`${bufferExpression}\\.Write\\(${escapeRegExp(input)}\\[:${escapeRegExp(room)}\\]\\)`).test(blockText);
    });
    if (boundedWrite && guardsPositiveRoom && !unboundedWrite) return true;
  }
  return false;
}

function topLevelStatements(block: Node): Node[] {
  return [...block.namedChildren].find((child) => child.type === "statement_list")?.namedChildren ?? [];
}

function hasUnconditionalTopLevelReturn(block: Node): boolean {
  const statements = [...block.namedChildren].find((child) => child.type === "statement_list");
  return statements?.namedChildren.some((child) => child.type === "return_statement") === true;
}

function responseWriterCallbackUses(
  root: Node,
  lexicalSource: string,
  source: string,
  typeName: string,
  httpAliases: Set<string>,
): BufferedWriterUse[] {
  const functions = [
    ...descendants(root, "function_declaration"),
    ...descendants(root, "method_declaration"),
    ...descendants(root, "func_literal"),
  ];
  const interfaceCallbacks = responseWriterCallbackInterfaces(root, source, httpAliases);
  const concreteCallbacks = responseWriterCallbackMethods(root, source, httpAliases);
  const callbackCollections = responseWriterCallbackCollections(root, source, interfaceCallbacks, concreteCallbacks);
  const constructors = responseWriterConstructors(root, lexicalSource, source, typeName);
  const uses: BufferedWriterUse[] = [];

  for (const fn of functions) {
    const body = fn.childForFieldName("body");
    if (body === null) continue;
    const aliases = new Set<string>();
    const aliasRelationships = new Map<string, Node[]>();
    const statements = descendants(body, "short_var_declaration")
      .concat(descendants(body, "assignment_statement"), descendants(body, "expression_statement"))
      .filter((node) => sameSyntaxNode(owningFunction(node), fn))
      .sort((left, right) => left.startIndex - right.startIndex);

    for (const statement of statements) {
      const text = sourceText(statement, lexicalSource).trim();
      const assignment = /^(?:var\s+)?([A-Za-z_]\w*)\s*(?::=|=)\s*(.+)$/.exec(text);
      if (assignment !== null) {
        const variable = assignment[1]!;
        const value = assignment[2]!;
        const direct = new RegExp(`^&\\s*${escapeRegExp(typeName)}\\s*\\{`).test(value);
        const constructor = [...constructors.entries()].find(([name]) =>
          new RegExp(`^(?:[A-Za-z_]\\w*\\.)*${escapeRegExp(name)}\\s*\\(`).test(value)
        );
        const alias = /^([A-Za-z_]\w*)$/.exec(value)?.[1];
        if (direct) {
          aliases.add(variable);
          aliasRelationships.set(variable, [statement]);
        } else if (constructor !== undefined) {
          aliases.add(variable);
          aliasRelationships.set(variable, [constructor[1], statement]);
        } else if (alias !== undefined && aliases.has(alias)) {
          aliases.add(variable);
          aliasRelationships.set(variable, [...(aliasRelationships.get(alias) ?? []), statement]);
        } else {
          aliases.delete(variable);
          aliasRelationships.delete(variable);
        }
      }

      for (const call of descendants(statement, "call_expression")) {
        const called = call.childForFieldName("function");
        const argumentsNode = call.childForFieldName("arguments");
        if (called?.type !== "selector_expression" || argumentsNode === null) continue;
        const methodNode = called.childForFieldName("field");
        const receiver = called.childForFieldName("operand");
        if (methodNode === null || receiver === null) continue;
        const method = sourceText(methodNode, source);
        if (!/^(?:Authenticate|Authorize|ServeHTTP|Handle|Invoke|Process|Render|WriteResponse)$/.test(method)) continue;
        const passed = argumentsNode.namedChildren
          .map((argument, position) => ({ name: sourceText(argument, source).trim(), position }))
          .find(({ name }) => aliases.has(name));
        if (passed === undefined) continue;
        if (!hasCallbackProvenance(
          fn,
          receiver,
          method,
          call,
          source,
          interfaceCallbacks,
          concreteCallbacks,
          callbackCollections,
          passed.position,
        )) continue;
        uses.push({
          variable: passed.name,
          method,
          line: call.startPosition.row + 1,
          node: call,
          relationships: aliasRelationships.get(passed.name) ?? [],
        });
      }
    }
  }
  return uses;
}

function owningFunction(node: Node): Node | null {
  let current = node.parent;
  while (current !== null) {
    if (["function_declaration", "method_declaration", "func_literal"].includes(current.type)) return current;
    current = current.parent;
  }
  return null;
}

function sameSyntaxNode(left: Node | null, right: Node): boolean {
  return left !== null && left.type === right.type && left.startIndex === right.startIndex && left.endIndex === right.endIndex;
}

type CallbackContracts = Map<string, Map<string, Set<number>>>;

function responseWriterCallbackInterfaces(root: Node, source: string, httpAliases: Set<string>): CallbackContracts {
  const callbacks: CallbackContracts = new Map();
  for (const typeSpec of descendants(root, "type_spec")) {
    const name = typeSpec.childForFieldName("name");
    const type = typeSpec.childForFieldName("type");
    if (name === null || type?.type !== "interface_type") continue;
    for (const method of descendants(type, "method_elem")) {
      const methodName = method.childForFieldName("name");
      const parameters = directParameterList(method);
      if (methodName === null || parameters === undefined) continue;
      const positions = responseWriterParameterPositions(parameters, source, httpAliases);
      if (positions.size === 0) continue;
      addCallbackContract(callbacks, sourceText(name, source), sourceText(methodName, source), positions);
    }
  }
  return callbacks;
}

function responseWriterCallbackMethods(root: Node, source: string, httpAliases: Set<string>): CallbackContracts {
  const callbacks: CallbackContracts = new Map();
  for (const method of descendants(root, "method_declaration")) {
    const name = method.childForFieldName("name");
    const receiver = method.childForFieldName("receiver");
    const parameters = directParameterList(method);
    if (name === null || receiver === null || parameters === undefined) continue;
    const positions = responseWriterParameterPositions(parameters, source, httpAliases);
    if (positions.size === 0) continue;
    const receiverType = sourceText(receiver, source).match(/\*?\s*([A-Za-z_]\w*)\s*\)$/)?.[1];
    if (receiverType === undefined) continue;
    addCallbackContract(callbacks, receiverType, sourceText(name, source), positions);
  }
  return callbacks;
}

function directParameterList(node: Node): Node | undefined {
  return [...node.namedChildren].find((child) => child.type === "parameter_list");
}

function responseWriterParameterPositions(parameters: Node, source: string, httpAliases: Set<string>): Set<number> {
  const positions = new Set<number>();
  let position = 0;
  for (const parameter of parameters.namedChildren.filter((child) =>
    child.type === "parameter_declaration" || child.type === "variadic_parameter_declaration"
  )) {
    const type = parameter.childForFieldName("type");
    if (type === null) continue;
    const prefix = source.slice(parameter.startIndex, type.startIndex).trim();
    const width = prefix === "" ? 1 : prefix.split(",").length;
    const isResponseWriter = [...httpAliases].some((alias) =>
      new RegExp(`^${escapeRegExp(alias)}\\s*\\.\\s*ResponseWriter$`).test(sourceText(type, source).trim())
    );
    if (isResponseWriter) {
      for (let offset = 0; offset < width; offset += 1) positions.add(position + offset);
    }
    position += width;
  }
  return positions;
}

function addCallbackContract(
  contracts: CallbackContracts,
  typeName: string,
  method: string,
  positions: Set<number>,
): void {
  const methods = contracts.get(typeName) ?? new Map<string, Set<number>>();
  methods.set(method, positions);
  contracts.set(typeName, methods);
}

function responseWriterCallbackCollections(
  root: Node,
  source: string,
  interfaces: CallbackContracts,
  concrete: CallbackContracts,
): CallbackContracts {
  const collections: CallbackContracts = new Map();
  for (const field of descendants(root, "field_declaration")) {
    const text = sourceText(field, source).replace(/\s/g, "");
    const match = /^([A-Za-z_]\w*)(?:\[\]|map\[[^\]]+\])\*?([A-Za-z_]\w*)$/.exec(text);
    if (match === null) continue;
    const [, fieldName, elementType] = match;
    if (fieldName === undefined || elementType === undefined) continue;
    const methods = interfaces.get(elementType) ?? concrete.get(elementType);
    if (methods !== undefined) collections.set(fieldName, methods);
  }
  return collections;
}

function responseWriterConstructors(root: Node, lexicalSource: string, source: string, typeName: string): Map<string, Node> {
  const constructors = new Map<string, Node>();
  for (const fn of descendants(root, "function_declaration")) {
    const name = fn.childForFieldName("name");
    const body = fn.childForFieldName("body");
    if (name === null || body === null) continue;
    const signature = source.slice(fn.startIndex, body.startIndex).replace(/\s/g, "");
    if (!new RegExp(`\\*${escapeRegExp(typeName)}$`).test(signature)) continue;
    const allocationReturn = descendants(body, "return_statement").find((statement) =>
      sameSyntaxNode(owningFunction(statement), fn) &&
      new RegExp(`^return\\s+&\\s*${escapeRegExp(typeName)}\\s*\\{`).test(sourceText(statement, lexicalSource).trim())
    );
    if (allocationReturn !== undefined) constructors.set(sourceText(name, source), allocationReturn);
  }
  return constructors;
}

function hasCallbackProvenance(
  fn: Node,
  receiver: Node,
  method: string,
  call: Node,
  source: string,
  interfaceCallbacks: CallbackContracts,
  concreteCallbacks: CallbackContracts,
  callbackCollections: CallbackContracts,
  argumentPosition: number,
): boolean {
  const receiverText = sourceText(receiver, source);
  if (receiver.type !== "identifier") return false;

  for (const parameter of descendants(fn, "parameter_declaration")) {
    if (!sameSyntaxNode(owningFunction(parameter), fn)) continue;
    const name = parameter.childForFieldName("name");
    const type = parameter.childForFieldName("type");
    if (name === null || type === null || sourceText(name, source) !== receiverText) continue;
    const typeText = sourceText(type, source).replace(/^\*+/, "");
    if (interfaceCallbacks.get(typeText)?.get(method)?.has(argumentPosition) === true) return true;
    if (concreteCallbacks.get(typeText)?.get(method)?.has(argumentPosition) === true) return true;
  }

  for (const range of descendants(fn, "range_clause")) {
    if (!sameSyntaxNode(owningFunction(range), fn) || range.startIndex > call.startIndex) continue;
    const left = range.childForFieldName("left");
    const right = range.childForFieldName("right");
    if (left === null || right === null) continue;
    const bindsReceiver = descendants(left, "identifier").some((node) => sourceText(node, source) === receiverText);
    const collection = sourceText(right, source).match(/\.\s*([A-Za-z_]\w*)\s*$/)?.[1];
    if (bindsReceiver && collection !== undefined &&
      callbackCollections.get(collection)?.get(method)?.has(argumentPosition) === true) return true;
  }

  return false;
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
    const lexicalBody = maskGoLexicalNoise(body, file.current);
    const acquisitions = clientResponseAcquisitions(lexicalBody, body.startPosition.row + 1);

    for (const acquisition of acquisitions) {
      const name = escapeRegExp(acquisition.name);
      if (new RegExp(`\\b${name}\\s*\\.\\s*Body\\s*\\.\\s*Close\\s*\\(`).test(lexicalBody)) continue;
      if (bodyTransfersOwnership(lexicalBody, name)) continue;
      if (bodyUsesCloseHelper(lexicalBody, name)) continue;

      const consumption = firstResponseBodyConsumption(lexicalBody, name);
      if (consumption === undefined) continue;
      const line = body.startPosition.row + 1 + lexicalBody.slice(0, consumption.index).split("\n").length - 1;
      if (!changed(file, acquisition.line, line)) continue;

      signals.push({
        ruleId: "go-http.client-response-body-close",
        path: file.path,
        line,
        message: `${acquisition.name}.Body is consumed in this function without being closed or returned to an owner.`,
        snippet: bodyText.slice(consumption.index, consumption.index + consumption.text.length).trim().slice(0, 300),
        data: { response: acquisition.name, acquisitionLine: acquisition.line, consumer: consumption.consumer },
      });
    }
  }
  return signals;
}

function maskGoLexicalNoise(container: Node, source: string): string {
  const text = sourceText(container, source);
  const nodes = ["comment", "interpreted_string_literal", "raw_string_literal", "rune_literal"]
    .flatMap((type) => descendants(container, type))
    .sort((left, right) => right.startIndex - left.startIndex);
  let masked = text;
  for (const node of nodes) {
    const start = node.startIndex - container.startIndex;
    const end = node.endIndex - container.startIndex;
    const replacement = masked.slice(start, end).replace(/[^\r\n]/g, " ");
    masked = masked.slice(0, start) + replacement + masked.slice(end);
  }
  return masked;
}

function clientResponseAcquisitions(body: string, bodyStartLine: number): ClientResponseAcquisition[] {
  const acquisitions: ClientResponseAcquisition[] = [];
  const assignment = /\b([A-Za-z_]\w*)\s*(?:,\s*[A-Za-z_]\w*)?\s*:?=\s*(?:http\.(?:Get|Post|Head|PostForm)|(?:[A-Za-z_]\w*\.)*(?:client|httpClient|httpclient|DefaultClient|hc)\.(?:Do|Get|Post|Head|PostForm)|(?:[A-Za-z_]\w*\.)*(?:transport|roundTripper|roundtripper|rt)\.RoundTrip)\s*\(/g;
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
