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
        const previousTree = file.previous === undefined ? undefined : await parseGo(file.previous);
        try {
          if (tree.rootNode.hasError) throw new Error("Go source contains syntax errors");
          signals.push(...responseWriterCapabilitySignals(file, tree.rootNode));
          signals.push(...providerResponseBufferSignals(file, tree.rootNode));
          signals.push(...clientResponseBodyCloseSignals(file, tree.rootNode));
          signals.push(...cancelledResponsePublicationSignals(
            file,
            tree.rootNode,
            previousTree?.rootNode.hasError === false ? previousTree.rootNode : undefined,
          ));
        } finally {
          previousTree?.delete();
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
function cancelledResponsePublicationSignals(file: SourceRevision, root: Node, previousRoot?: Node): Signal[] {
  const httpAliases = standardImportAliases(root, file.current, "net/http", "http");
  const contextAliases = standardImportAliases(root, file.current, "context", "context");
  if (httpAliases.size === 0 || contextAliases.size === 0) return [];
  const lexicalFile = maskGoLexicalNoise(root, file.current);
  const methods = descendants(root, "method_declaration");
  const bodyConsumerPaths = standardBodyConsumerPaths(root, file.current);
  const previousSignatures = previousRoot === undefined || file.previous === undefined
    ? new Set<string>()
    : new Set(cancelledResponsePublicationSignals({
      path: file.path,
      current: file.previous,
      status: "repository",
      changedLines: new Set(),
    }, previousRoot).map(cancelledResponsePublicationSignature));
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
          const evidenceNodes = [
            state.responseDeclaration,
            state.completionDeclaration,
            ...controlActivationNodes(publisher.asyncStart, publisher.method.childForFieldName("body")),
            publisher.asyncStart,
            publisher.assignment,
            publisher.signal,
            waitReceiveNode(waiter.completionCase),
            waitReceiveNode(waiter.cancellationCase),
            waiter.cancellationReturn,
            owner.waitCall,
            ...controlActivationNodes(owner.bodyUse, owner.method.childForFieldName("body")),
            owner.bodyUse,
          ];
          const currentSignature = cancelledResponsePublicationSignatureParts(
            state,
            publisher,
            waiter,
            owner,
          );
          const newlyActivated = file.status === "modified" && file.previous !== undefined &&
            goSourceSemantics(file.current) !== goSourceSemantics(file.previous) &&
            !previousSignatures.has(currentSignature);
          const evidence = firstChangedNode(file, root, previousRoot, evidenceNodes) ??
            (newlyActivated
              ? firstChangedNode(
                file,
                root,
                previousRoot,
                [
                  ...responseOwnerActivationStatements(owner, file.current),
                  ...cancellationActivationStatements(waiter.cancellationCase),
                ],
              ) ?? publisher.asyncStart
              : undefined);
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

function cancelledResponsePublicationSignature(signal: Signal): string {
  return [
    signal.data.ownerType,
    signal.data.responseField,
    signal.data.completionField,
    signal.data.producer,
    signal.data.waiter,
    signal.data.responseOwner,
  ].join("|");
}

function cancelledResponsePublicationSignatureParts(
  state: OwnedResponseState,
  publisher: PublishedResponse,
  waiter: CancellationWaiter,
  owner: ResponseOwner,
): string {
  return [
    state.typeName,
    state.responseField,
    state.completionField,
    publisher.methodName,
    waiter.methodName,
    owner.methodName,
  ].join("|");
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
      if (!sameSyntaxNode(owningFunction(node), method) || !directlyReachableInBlock(body, node, lexicalFile)) return false;
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
    sameSyntaxNode(owningFunction(node), method) && directlyReachableInBlock(body, node, lexicalFile) &&
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
    if (!directlyReachableInBlock(body, node, lexicalFile)) return false;
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
      sameSyntaxNode(owningFunction(node), method) && directlyReachableInBlock(body, node, source) &&
      receiverBindingPreserved(method, receiver, node, source) &&
      descendants(node, "call_expression").some((call) =>
        executesWithin(call, node, source) && pathEquals(callPath(call, source), [receiver, producerName])
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
      if (!sameSyntaxNode(owningFunction(select), method) || !directlyReachableInBlock(body, select, lexicalSource)) continue;
      const cases = select.namedChildren.filter((child) => child.type === "communication_case");
      const completionCase = cases.find((item) =>
        communicationReceiveMatches(item, lexicalSource, receiver, state.completionField)
      );
      const cancellationCase = cases.find((item) =>
        communicationReceivesContextDone(item, lexicalSource, receiver, state.contextFields)
      );
      if (completionCase === undefined || cancellationCase === undefined) continue;
      const cancellationReturn = descendants(cancellationCase, "return_statement")
        .filter((item) => sameSyntaxNode(owningFunction(item), method) &&
          reachableWithinBoundary(cancellationCase, item, lexicalSource))
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

function reachableWithinBoundary(boundary: Node, node: Node, source: string): boolean {
  let current: Node | null = node;
  while (current !== null && !sameSyntaxNode(current, boundary)) {
    const parent: Node | null = current.parent;
    if (parent === null) return false;
    if (parent.type === "if_statement") {
      const value = booleanLiteral(parent.childForFieldName("condition"), source);
      const consequence = parent.childForFieldName("consequence");
      const alternative = parent.childForFieldName("alternative");
      if (value === false && consequence !== null && containsNode(consequence, current)) return false;
      if (value === true && alternative !== null && containsNode(alternative, current)) return false;
    }
    if (parent.type === "for_statement" && forConditionBoolean(parent, source) === false) return false;
    if (parent.type === "expression_case" && !expressionCaseCanExecute(parent, source)) return false;
    if (parent.type === "statement_list") {
      const statements = parent.namedChildren;
      const containing = statements.find((statement) => containsNode(statement, current!));
      if (containing === undefined) return false;
      if (statements.some((statement) => statement.endIndex < containing.startIndex &&
        unconditionallyTerminatesBefore(parent, statement, containing, source))) return false;
    }
    current = parent;
  }
  return current !== null;
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
  const returnIndex = topLevel.findIndex((statement) => containsNode(statement, waiter.cancellationReturn));
  if (returnIndex < 0) return false;
  return topLevel.slice(0, returnIndex).some((statement, index) => {
    if (!priorStatementsCannotBypass(topLevel.slice(0, index), waiter.method, lexicalSource)) return false;
    if (statementSynchronizesCompletion(
      statement, waiter.receiver, state.completionField, lexicalSource, waiter.method, source,
    )) return true;
    if (statement.type !== "expression_statement") return false;
    return descendants(statement, "call_expression").some((call) => {
      if (!executesWithin(call, statement, lexicalSource) ||
        !callExecutesOnAllPathsWithinStatement(call, statement, lexicalSource) ||
        !receiverBindingPreserved(waiter.method, waiter.receiver, call, source)) return false;
      const path = callPath(call, lexicalSource);
      if (path?.length !== 2 || path[0] !== waiter.receiver) return false;
      const helper = methods.find((method) => methodName(method, source) === path[1]);
      return helper !== undefined && helperSynchronizesCompletion(helper, state, lexicalSource, source);
    });
  });
}

function callExecutesOnAllPathsWithinStatement(call: Node, statement: Node, source: string): boolean {
  const statementOwner = owningFunction(statement);
  const callOwner = owningFunction(call);
  if (statementOwner === null || callOwner === null) return false;
  if (sameSyntaxNode(callOwner, statementOwner)) return true;
  if (callOwner.type !== "func_literal") return false;
  const invocation = directInvocationOfLiteral(callOwner);
  const body = callOwner.childForFieldName("body");
  if (invocation === null || body === null || !executesWithin(invocation, statement, source)) return false;
  return allPathsPerformInBlock(body, (candidate) => {
    if (!["expression_statement", "assignment_statement", "short_var_declaration", "return_statement"]
      .includes(candidate.type)) return false;
    return containsNode(candidate, call) && sameSyntaxNode(owningFunction(call), callOwner);
  }, source);
}

function statementSynchronizesCompletion(
  statement: Node,
  receiver: string,
  completionField: string,
  source: string,
  bindingOwner?: Node,
  bindingSource?: string,
): boolean {
  const bindingPreserved = (use: Node): boolean => {
    if (bindingOwner === undefined || bindingSource === undefined) return true;
    const body = bindingOwner.childForFieldName("body");
    return body !== null && bindingPathPreserved(bindingOwner, receiver, use, bindingSource, body.startIndex);
  };
  const directReceiveStatement = ["expression_statement", "assignment_statement", "short_var_declaration"]
    .includes(statement.type);
  if (directReceiveStatement && [statement, ...descendants(statement, "unary_expression")].some((candidate) => {
    if (candidate.type !== "unary_expression" || !executesWithin(candidate, statement, source)) return false;
    if (!pathEquals(receiveTargetPath(candidate, source), [receiver, completionField])) return false;
    if (!bindingPreserved(candidate)) return false;
    const owner = owningFunction(candidate);
    const statementOwner = owningFunction(statement);
    if (statementOwner !== null && sameSyntaxNode(owner, statementOwner)) return true;
    const body = owner?.childForFieldName("body");
    return body !== null && body !== undefined && directlyReachableInBlock(body, candidate, source) &&
      allPathsReachStatement(body, candidate, source) &&
      canCompleteNormallyAfter(body, candidate, source);
  })) return true;

  return allPathsPerformInSequence(
    [statement],
    (candidate) => directStatementReceivesCompletion(candidate, receiver, completionField, source) &&
      bindingPreserved(candidate),
    source,
  );
}

function directStatementReceivesCompletion(
  statement: Node,
  receiver: string,
  completionField: string,
  source: string,
): boolean {
  if (statement.type === "communication_case") {
    return communicationReceiveTextMatches(waitReceiveNode(statement), source, receiver, completionField);
  }
  if (!["expression_statement", "assignment_statement", "short_var_declaration", "return_statement"]
    .includes(statement.type)) return false;
  const owner = owningFunction(statement);
  if (owner === null) return false;
  return descendants(statement, "unary_expression").some((candidate) =>
    sameSyntaxNode(owningFunction(candidate), owner) &&
    pathEquals(receiveTargetPath(candidate, source), [receiver, completionField])
  );
}

function directInvokedLiteralBody(statement: Node, source: string): Node | undefined {
  if (["go_statement", "defer_statement"].includes(statement.type)) return undefined;
  for (const literal of descendants(statement, "func_literal")) {
    const invocation = directInvocationOfLiteral(literal);
    if (invocation === null || !executesWithin(invocation, statement, source)) continue;
    const body = literal.childForFieldName("body");
    if (body !== null) return body;
  }
  return undefined;
}

function allPathsPerformInBlock(
  block: Node,
  action: (statement: Node) => boolean,
  source: string,
): boolean {
  return allPathsPerformInSequence(topLevelStatements(block), action, source);
}

function allPathsPerformInSequence(
  statements: Node[],
  action: (statement: Node) => boolean,
  source: string,
): boolean {
  if (statements.length === 0) return false;
  const [statement, ...rest] = statements;
  if (statement === undefined) return false;
  if (action(statement)) return true;

  const literalBody = directInvokedLiteralBody(statement, source);
  if (literalBody !== undefined && allPathsPerformInBlock(literalBody, action, source)) return true;

  if (statement.type === "if_statement") {
    const condition = booleanLiteral(statement.childForFieldName("condition"), source);
    const consequence = statement.childForFieldName("consequence");
    if (consequence === null) return false;
    const onTrue = [...controlledStatements(consequence), ...rest];
    const alternative = statement.childForFieldName("alternative");
    const onFalse = [...controlledStatements(alternative), ...rest];
    if (condition === true) return allPathsPerformInSequence(onTrue, action, source);
    if (condition === false) return allPathsPerformInSequence(onFalse, action, source);
    return allPathsPerformInSequence(onTrue, action, source) &&
      allPathsPerformInSequence(onFalse, action, source);
  }

  if (statement.type === "expression_switch_statement" || statement.type === "type_switch_statement") {
    const caseType = statement.type === "expression_switch_statement" ? "expression_case" : "type_case";
    const cases = directControlCases(statement, caseType);
    if (cases.length === 0 || !cases.some((candidate) => isDefaultCase(candidate, source))) return false;
    return cases.every((_, index) => {
      const path = switchCasePath(cases, index, rest, source);
      return path !== undefined && allPathsPerformInSequence(path, action, source);
    });
  }

  if (statement.type === "select_statement") {
    const cases = directControlCases(statement, "communication_case");
    // A select without a default either chooses one of its communication cases
    // or blocks. When every selectable path synchronizes, neither outcome can
    // return from the cancellation arm before completion.
    if (cases.length === 0) return false;
    return cases.every((candidate) => {
      const path = selectCasePath(candidate, rest, source);
      return path !== undefined && allPathsPerformInSequence(path, action, source);
    });
  }

  if (["return_statement", "goto_statement", "break_statement", "continue_statement", "fallthrough_statement"]
    .includes(statement.type)) return false;
  if (["for_statement"]
    .includes(statement.type)) return false;
  if (statement.type === "expression_statement") {
    const call = unwrapExpression(statement.namedChildren[0]);
    if (call?.type === "call_expression" && pathEquals(callPath(call, source), ["panic"]) &&
      unshadowedBuiltin(call, "panic", source)) return false;
  }
  return allPathsPerformInSequence(rest, action, source);
}

function directControlCases(
  control: Node,
  type: "expression_case" | "type_case" | "communication_case",
): Node[] {
  return [...descendants(control, type), ...descendants(control, "default_case")]
    .filter((candidate) => {
      return sameSyntaxNode(nearestAncestorOfTypes(candidate, new Set([control.type])), control);
    })
    .sort((left, right) => left.startIndex - right.startIndex);
}

function caseStatements(caseNode: Node): Node[] {
  return caseNode.namedChildren.find((child) => child.type === "statement_list")?.namedChildren ?? [];
}

function switchCasePath(cases: Node[], index: number, continuation: Node[], source: string): Node[] | undefined {
  const statements = caseStatements(cases[index]!);
  const transferIndex = statements.findIndex((statement) =>
    statement.type === "break_statement" || statement.type === "fallthrough_statement"
  );
  if (transferIndex < 0) return [...statements, ...continuation];
  const transfer = statements[transferIndex]!;
  const prefix = statements.slice(0, transferIndex);
  if (transfer.type === "break_statement") {
    const control = nearestAncestorOfTypes(cases[index]!, new Set([
      "expression_switch_statement",
      "type_switch_statement",
    ]));
    return control !== null && breakTargetsControl(transfer, control, source)
      ? [...prefix, ...continuation]
      : undefined;
  }
  const control = nearestAncestorOfTypes(cases[index]!, new Set([
    "expression_switch_statement",
    "type_switch_statement",
  ]));
  if (control?.type === "type_switch_statement") return undefined;
  if (transferIndex !== statements.length - 1 || index + 1 >= cases.length) return undefined;
  const following = switchCasePath(cases, index + 1, continuation, source);
  return following === undefined ? undefined : [...prefix, ...following];
}

function selectCasePath(caseNode: Node, continuation: Node[], source: string): Node[] | undefined {
  const statements = caseStatements(caseNode);
  const breakIndex = statements.findIndex((statement) => statement.type === "break_statement");
  if (breakIndex < 0) return [caseNode, ...statements, ...continuation];
  const transfer = statements[breakIndex]!;
  const control = nearestAncestorOfTypes(caseNode, new Set(["select_statement"]));
  if (control === null || !breakTargetsControl(transfer, control, source)) return undefined;
  return [caseNode, ...statements.slice(0, breakIndex), ...continuation];
}

function controlledStatements(node: Node | null): Node[] {
  if (node === null) return [];
  if (node.type === "block") return topLevelStatements(node);
  if (node.type === "if_statement") return [node];
  if (node.type === "else_clause") {
    const branch = node.namedChildren.find((child) => child.type === "block" || child.type === "if_statement");
    return controlledStatements(branch ?? null);
  }
  return [];
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
      !directlyReachableInBlock(body, call, lexicalSource)) return false;
    if (!producerCleanupPrecedesSignal(call, publisher)) return false;
    if (!sameSyntaxNode(enclosingBlock(call), enclosingBlock(publisher.assignment)!)) return false;
    return producerCleanupClosesPublishedResponse(
      call, publisher, state, assignedName, lexicalSource, source,
    );
  });
  if (directlyClosed) return true;

  return descendants(body, "call_expression").some((invocation) => {
    if (!sameSyntaxNode(owningFunction(invocation), publisher.method) ||
      invocation.startIndex <= publisher.assignment.endIndex || !directlyReachableInBlock(body, invocation, lexicalSource)) return false;
    if (publisher.signal.type !== "defer_statement" && invocation.endIndex >= publisher.signal.startIndex) return false;
    if (directStatementContaining(body, invocation)?.type !== "expression_statement") return false;
    const literal = invocation.childForFieldName("function");
    if (literal?.type !== "func_literal" || callArguments(invocation).length !== 0) return false;
    const literalBody = literal.childForFieldName("body");
    if (literalBody === null) return false;
    return allPathsPerformInBlock(
      literalBody,
      (statement) => statementCallsPublishedResponseCleanup(
        statement, literal, publisher, state, assignedName, lexicalSource, source,
      ),
      lexicalSource,
    );
  });
}

function producerCleanupClosesPublishedResponse(
  call: Node,
  publisher: PublishedResponse,
  state: OwnedResponseState,
  assignedName: string | undefined,
  lexicalSource: string,
  source: string,
): boolean {
  const path = callPath(call, lexicalSource);
  if (pathEquals(path, [publisher.receiver, state.responseField, "Body", "Close"])) {
    return bindingPathPreserved(
      publisher.method, publisher.receiver, call, source, publisher.assignment.endIndex,
    ) && selectorPathPreserved(
      publisher.method,
      [publisher.receiver, state.responseField],
      call,
      source,
      publisher.assignment.endIndex,
    );
  }
  return assignedName !== undefined && pathEquals(path, [assignedName, "Body", "Close"]) &&
    bindingPathPreserved(publisher.method, assignedName, call, source, publisher.assignment.endIndex);
}

function statementCallsPublishedResponseCleanup(
  statement: Node,
  literal: Node,
  publisher: PublishedResponse,
  state: OwnedResponseState,
  assignedName: string | undefined,
  lexicalSource: string,
  source: string,
): boolean {
  if (!["expression_statement", "assignment_statement", "short_var_declaration", "defer_statement", "return_statement"]
    .includes(statement.type)) return false;
  return descendants(statement, "call_expression").some((call) =>
    sameSyntaxNode(owningFunction(call), literal) &&
    producerCleanupClosesPublishedResponse(call, publisher, state, assignedName, lexicalSource, source)
  );
}

function producerCleanupPrecedesSignal(cleanup: Node, publisher: PublishedResponse): boolean {
  const deferredCleanup = nearestAncestorOfTypes(cleanup, new Set(["defer_statement"]));
  if (publisher.signal.type !== "defer_statement") {
    return deferredCleanup === null && cleanup.endIndex < publisher.signal.startIndex;
  }
  // Direct cleanup runs before the completion defer at function return. A
  // deferred cleanup does so only when it was registered after the completion
  // defer, because Go executes defers in LIFO order.
  return deferredCleanup === null || deferredCleanup.startIndex > publisher.signal.startIndex;
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
      directlyReachableInBlock(body, call, lexicalSource) &&
      receiverBindingPreserved(method, receiver, call, source) &&
      pathEquals(callPath(call, lexicalSource), [receiver, waiter.methodName])
    );
    for (const waitCall of waitCalls) {
      const bodyUse = responseBodyUseAfter(body, waitCall, [receiver, state.responseField], lexicalSource, bodyConsumerPaths);
      if (bodyUse === undefined) continue;
      if (waitCallHasTerminatingErrorGuard(waitCall, bodyUse, lexicalSource) &&
        !responseBodyUseCloses(bodyUse, lexicalSource)) continue;
      if (hasUnconditionalTerminationBetween(body, waitCall, bodyUse, lexicalSource)) continue;
      if (callerReobservesCompletion(
        body, waitCall, bodyUse, receiver, state, methods, lexicalSource, source,
      )) continue;
      owners.push({ method, methodName: name, waitCall, bodyUse });
    }

    for (const wrapper of wrappers) {
      for (const wrapperCall of descendants(body, "call_expression").filter((call) =>
        sameSyntaxNode(owningFunction(call), method) && isDirectStatement(body, call) &&
        directlyReachableInBlock(body, call, lexicalSource) && pathEquals(callPath(call, lexicalSource), [receiver, wrapper.name])
      )) {
        const responseName = assignedIdentifier(wrapperCall, source);
        if (responseName === undefined) continue;
        const bodyUse = responseBodyUseAfter(body, wrapperCall, [responseName], lexicalSource, bodyConsumerPaths);
        if (bodyUse === undefined || !sameSyntaxNode(enclosingBlock(wrapperCall), enclosingBlock(bodyUse)!)) continue;
        if (hasUnconditionalTerminationBetween(body, wrapperCall, bodyUse, lexicalSource)) continue;
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
    if (call.startIndex <= waitCall.endIndex || !directlyReachableInBlock(body, call, source)) return false;
    const waitOwner = owningFunction(waitCall);
    const callOwner = owningFunction(call);
    if (waitOwner === null || callOwner === null) return false;
    if (!sameSyntaxNode(callOwner, waitOwner) && !executesWithin(call, body, source)) return false;
    const path = callPath(call, source);
    const bodyPath = [...responsePath, "Body"];
    const owner = waitOwner;
    if (!bindingPathPreserved(owner, responsePath[0]!, call, source, waitCall.endIndex)) return false;
    if (pathEquals(path, [...bodyPath, "Close"]) || pathEquals(path, [...bodyPath, "Read"])) return true;
    if (path === undefined || !bodyConsumerPaths.has(path.join("."))) return false;
    if (!localNameUnshadowedAtUse(owner, path[0]!, call, source)) return false;
    return callArguments(call).some((argument) => pathEquals(selectorPath(argument, source), bodyPath));
  });
}

function callerReobservesCompletion(
  body: Node,
  waitCall: Node,
  bodyUse: Node,
  receiver: string,
  state: OwnedResponseState,
  methods: Node[],
  lexicalSource: string,
  source: string,
): boolean {
  const owner = owningFunction(waitCall);
  if (owner === null) return false;
  return topLevelStatements(body).some((statement) => {
    if (statement.startIndex <= waitCall.endIndex || statement.endIndex >= bodyUse.startIndex) return false;
    if (statementSynchronizesCompletion(
      statement, receiver, state.completionField, lexicalSource, owner, source,
    )) return true;
    if (statement.type !== "expression_statement") return false;
    return descendants(statement, "call_expression").some((call) => {
      if (!executesWithin(call, statement, lexicalSource) ||
        !receiverBindingPreserved(owner, receiver, call, source)) return false;
      const path = callPath(call, lexicalSource);
      if (path?.length !== 2 || path[0] !== receiver) return false;
      const helper = methods.find((method) => methodName(method, source) === path[1]);
      return helper !== undefined && helperSynchronizesCompletion(helper, state, lexicalSource, source);
    });
  });
}

function responseBodyUseCloses(bodyUse: Node, source: string): boolean {
  const path = callPath(bodyUse, source);
  return path !== undefined && path.length >= 2 && path.at(-2) === "Body" && path.at(-1) === "Close";
}

function waitCallHasTerminatingErrorGuard(waitCall: Node, bodyUse: Node, source: string): boolean {
  let current: Node | null = waitCall.parent;
  while (current !== null && current.type !== "if_statement") {
    if (current.type === "statement_list" || current.type === "block") {
      current = null;
      break;
    }
    current = current.parent;
  }
  if (current !== null) {
    const initializer = current.namedChildren.find((child) => child.type === "short_var_declaration");
    if (initializer !== undefined && containsNode(initializer, waitCall)) {
      const sides = assignmentSides(initializer);
      if (sides?.left.type !== "identifier") return false;
      return errorGuardReturns(current, sourceText(sides.left, source).trim(), source);
    }
  }

  const errorName = assignedIdentifier(waitCall, source);
  const owner = owningFunction(waitCall);
  const body = owner?.childForFieldName("body");
  if (errorName === undefined || owner === null || body == null) return false;
  const waitStatement = topLevelStatementContaining(body, waitCall);
  const useStatement = topLevelStatementContaining(body, bodyUse);
  if (waitStatement === undefined || useStatement === undefined) return false;
  return topLevelStatements(body).some((statement) =>
    statement.type === "if_statement" && statement.startIndex > waitStatement.endIndex &&
    statement.endIndex < useStatement.startIndex && errorGuardReturns(statement, errorName, source) &&
    bindingPathPreserved(owner, errorName, statement, source, waitCall.endIndex)
  );
}

function errorGuardReturns(guard: Node, errorName: string, source: string): boolean {
  const condition = guard.childForFieldName("condition");
  const consequence = guard.childForFieldName("consequence");
  if (condition === null || consequence === null ||
    sourceText(condition, source).replace(/\s/g, "") !== `${errorName}!=nil`) return false;
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
      sameSyntaxNode(owningFunction(call), method) && directlyReachableInBlock(body, call, lexicalSource) &&
      pathEquals(callPath(call, lexicalSource), [receiver, waiter.methodName])
    );
    if (waitCall === undefined || !receiverBindingPreserved(method, receiver, waitCall, source)) continue;
    const responseReturn = descendants(body, "return_statement").find((statement) =>
      sameSyntaxNode(owningFunction(statement), method) && directlyReachableInBlock(body, statement, lexicalSource) &&
      statement.startIndex > waitCall.endIndex &&
      statement.namedChildren.some((child) => pathEquals(selectorPath(child, lexicalSource), [receiver, state.responseField]))
    );
    if (responseReturn === undefined ||
      !bindingPathPreserved(method, receiver, responseReturn, source, waitCall.endIndex) ||
      hasUnconditionalTerminationBetween(body, waitCall, responseReturn, lexicalSource)) continue;
    if (callerReobservesCompletion(
      body, waitCall, responseReturn, receiver, state, methods, lexicalSource, source,
    )) continue;
    wrappers.push({ name });
  }
  return wrappers;
}

function helperSynchronizesCompletion(
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
    statementSynchronizesCompletion(statement, receiver, state.completionField, lexicalSource, method, source)
  );
  if (receive === undefined || !directlyReachableInBlock(body, receive, lexicalSource)) return false;
  if (!receiverBindingPreserved(method, receiver, receive, source)) return false;
  if (!allPathsReachStatement(body, receive, lexicalSource)) return false;
  return canCompleteNormallyAfter(body, receive, lexicalSource);
}

function allPathsReachStatement(body: Node, target: Node, source: string): boolean {
  const targetStatement = topLevelStatementContaining(body, target);
  if (targetStatement === undefined) return false;
  const owner = owningFunction(target);
  if (owner === null) return false;
  return priorStatementsCannotBypass(
    topLevelStatements(body).filter((statement) => statement.endIndex < targetStatement.startIndex),
    owner,
    source,
  );
}

function priorStatementsCannotBypass(statements: Node[], owner: Node, source: string): boolean {
  const ownerBody = owner.childForFieldName("body");
  if (ownerBody === null) return false;
  return !statements.some((statement) => {
    return [
      ...descendants(statement, "return_statement"),
      ...descendants(statement, "goto_statement"),
      ...descendants(statement, "continue_statement"),
    ].some((candidate) => sameSyntaxNode(owningFunction(candidate), owner) &&
      reachableWithinBoundary(ownerBody, candidate, source)) ||
      descendants(statement, "break_statement").some((candidate) =>
        sameSyntaxNode(owningFunction(candidate), owner) &&
        reachableWithinBoundary(ownerBody, candidate, source) &&
        breakEscapesStatement(candidate, statement, source)
      ) ||
      descendants(statement, "call_expression").some((call) =>
        sameSyntaxNode(owningFunction(call), owner) &&
        reachableWithinBoundary(ownerBody, call, source) &&
        pathEquals(callPath(call, source), ["panic"]) && unshadowedBuiltin(call, "panic", source)
      );
  });
}

function breakEscapesStatement(breakStatement: Node, statement: Node, source: string): boolean {
  const target = breakTargetControl(breakStatement, source);
  return target === null || !containsNode(statement, target);
}

function breakTargetsControl(breakStatement: Node, control: Node, source: string): boolean {
  return sameSyntaxNode(breakTargetControl(breakStatement, source), control);
}

function breakTargetControl(breakStatement: Node, source: string): Node | null {
  const text = sourceText(breakStatement, source).trim();
  if (text === "break") {
    return nearestAncestorOfTypes(breakStatement, new Set([
      "for_statement",
      "expression_switch_statement",
      "type_switch_statement",
      "select_statement",
    ]));
  }
  const label = /^break\s+([A-Za-z_]\w*)$/.exec(text)?.[1];
  if (label === undefined) return null;
  let current = breakStatement.parent;
  while (current !== null) {
    if (current.type === "labeled_statement") {
      const declared = current.namedChildren.find((child) => child.type === "label_name" || child.type === "identifier");
      if (declared !== undefined && sourceText(declared, source).trim() === label) {
        return current.namedChildren.find((child) => [
          "for_statement",
          "expression_switch_statement",
          "type_switch_statement",
          "select_statement",
        ].includes(child.type)) ?? null;
      }
    }
    current = current.parent;
  }
  return null;
}

function canCompleteNormallyAfter(body: Node, node: Node, source: string): boolean {
  const containing = directStatementContaining(body, node);
  if (containing === undefined ||
    !["expression_statement", "assignment_statement", "short_var_declaration"].includes(containing.type)) return false;
  return !topLevelStatements(body).some((statement) =>
    statement.startIndex > containing.endIndex &&
    (statement.type === "goto_statement" ||
      (statement.type === "expression_statement" && (() => {
        const call = unwrapExpression(statement.namedChildren[0]);
        return call?.type === "call_expression" && pathEquals(callPath(call, source), ["panic"]) &&
          unshadowedBuiltin(call, "panic", source);
      })()))
  );
}

function executesWithin(node: Node, boundary: Node, source: string): boolean {
  let current: Node | null = node;
  while (current !== null && !sameSyntaxNode(current, boundary)) {
    if (current.type === "func_literal") {
      const body = current.childForFieldName("body");
      if (body === null || !directlyReachableInBlock(body, node, source)) return false;
      const invocation = directInvocationOfLiteral(current);
      if (invocation === null) return false;
      current = invocation;
      continue;
    }
    const parent: Node | null = current.parent;
    if (parent !== null && ["go_statement", "defer_statement"].includes(parent.type) &&
      !sameSyntaxNode(parent, boundary)) return false;
    current = parent;
  }
  return current !== null;
}

function directInvocationOfLiteral(literal: Node): Node | null {
  let expression = literal;
  while (expression.parent?.type === "parenthesized_expression" && expression.parent.namedChildren.length === 1) {
    expression = expression.parent;
  }
  const invocation = expression.parent;
  if (invocation?.type !== "call_expression") return null;
  const called = unwrapExpression(invocation.childForFieldName("function"));
  return sameSyntaxNode(called ?? null, literal) ? invocation : null;
}

function receiverBindingPreserved(method: Node, receiver: string, use: Node, source: string): boolean {
  const body = method.childForFieldName("body");
  return body !== null && bindingPathPreserved(method, receiver, use, source, body.startIndex);
}

function bindingPathPreserved(
  owner: Node,
  name: string,
  use: Node,
  source: string,
  afterIndex: number,
): boolean {
  let lexicalOwner = owningFunction(use);
  while (lexicalOwner !== null && !sameSyntaxNode(lexicalOwner, owner)) {
    const body = lexicalOwner.childForFieldName("body");
    const signature = source.slice(lexicalOwner.startIndex, body?.startIndex ?? lexicalOwner.endIndex);
    if (new RegExp(`(?:\\(|,)\\s*${escapeRegExp(name)}(?:\\s|,)`).test(signature)) return false;
    lexicalOwner = owningFunction(lexicalOwner);
  }
  if (lexicalOwner === null) return false;

  for (const assignment of descendants(owner, "assignment_statement")) {
    if (assignment.startIndex <= afterIndex || assignment.endIndex >= use.startIndex) continue;
    if (!executesBeforeUse(owner, assignment, use, source)) continue;
    const left = assignmentSides(assignment)?.left;
    if (left !== undefined && directlyAssignsIdentifier(left, name, source) &&
      !assignmentPreservesIdentifier(assignment, name, source)) return false;
  }
  for (const declaration of [
    ...descendants(owner, "short_var_declaration"),
    ...descendants(owner, "var_spec"),
    ...descendants(owner, "const_spec"),
  ]) {
    if (declaration.startIndex <= afterIndex || declaration.endIndex >= use.startIndex ||
      !declarationNames(declaration, source).has(name)) continue;
    const scope = enclosingBlock(declaration);
    if (scope !== null && containsNode(scope, use)) return false;
  }
  if (rangeAssignmentChangesBinding(owner, name, use, source, afterIndex)) return false;
  if (communicationAssignmentChangesBinding(owner, name, use, source, afterIndex)) return false;
  if (lexicalControlBindingShadows(owner, name, use, source)) return false;
  return true;
}

function selectorPathPreserved(
  owner: Node,
  path: string[],
  use: Node,
  source: string,
  afterIndex: number,
): boolean {
  return !descendants(owner, "assignment_statement").some((assignment) => {
    if (assignment.startIndex <= afterIndex || assignment.endIndex >= use.startIndex ||
      !executesBeforeUse(owner, assignment, use, source)) return false;
    const left = assignmentSides(assignment)?.left;
    if (left === undefined) return false;
    if ([left, ...descendants(left, "selector_expression")].some((candidate) =>
      pathEquals(selectorPath(candidate, source), path)
    )) return true;
    return sourceText(left, source).split(",").some((candidate) =>
      candidate.replace(/\s/g, "") === path.join(".")
    );
  });
}

function executesBeforeUse(owner: Node, node: Node, use: Node, source: string): boolean {
  const body = owner.childForFieldName("body");
  if (body === null || node.endIndex >= use.startIndex) return false;
  const nodeBlock = enclosingBlock(node);
  if (nodeBlock !== null && containsNode(nodeBlock, use)) {
    return directlyReachableInBlock(body, node, source) && executesWithin(node, nodeBlock, source);
  }
  const statement = topLevelStatementContaining(body, node);
  return statement !== undefined && statement.endIndex < use.startIndex &&
    directlyReachableInBlock(body, node, source) && executesWithin(node, statement, source);
}

function rangeAssignmentChangesBinding(
  owner: Node,
  name: string,
  use: Node,
  source: string,
  afterIndex: number,
): boolean {
  const escaped = escapeRegExp(name);
  return descendants(owner, "range_clause").some((clause) => {
    if (clause.startIndex <= afterIndex || clause.endIndex >= use.startIndex ||
      !new RegExp(`(?:^|[,;\\s])${escaped}\\s*=(?!=)`).test(sourceText(clause, source))) return false;
    const loop = clause.parent;
    const body = owner.childForFieldName("body");
    return loop !== null && body !== null && containsNode(loop, use) &&
      directlyReachableInBlock(body, use, source);
  });
}

function communicationAssignmentChangesBinding(
  owner: Node,
  name: string,
  use: Node,
  source: string,
  afterIndex: number,
): boolean {
  const body = owner.childForFieldName("body");
  if (body === null) return false;
  return descendants(owner, "communication_case").some((clause) => {
    if (clause.startIndex <= afterIndex || clause.startIndex >= use.startIndex) return false;
    let execution: Node = clause;
    let lexicalOwner = owningFunction(clause);
    while (lexicalOwner !== null && !sameSyntaxNode(lexicalOwner, owner)) {
      if (lexicalOwner.type !== "func_literal" ||
        !localNameUnshadowedAtUse(lexicalOwner, name, clause, source)) return false;
      const invocation = definiteClosureInvocation(lexicalOwner, execution, owner, use, source);
      if (invocation === null) return false;
      execution = invocation;
      lexicalOwner = owningFunction(lexicalOwner);
    }
    if (lexicalOwner === null) return false;
    if (ownerLocalDeclarationShadows(owner, name, clause, source)) return false;
    const receive = clause.namedChildren.find((child) => child.type === "receive_statement");
    const left = receive?.childForFieldName("left");
    const right = receive?.childForFieldName("right");
    if (left === undefined || left === null || right === undefined || right === null ||
      source.slice(left.endIndex, right.startIndex).trim() !== "=" ||
      !directlyAssignsIdentifier(left, name, source)) return false;
    const selection = nearestAncestorOfTypes(clause, new Set(["select_statement"]));
    if (selection === null) return false;
    if (containsNode(clause, use)) {
      return directlyReachableInBlock(body, use, source) && executesWithin(selection, owner, source);
    }
    const executedNode = sameSyntaxNode(execution, clause) ? selection : execution;
    if (executedNode.endIndex >= use.startIndex || !executesBeforeUse(owner, executedNode, use, source)) return false;
    // A receive assignment in any selectable arm makes the receiver reaching a
    // later use path-dependent. Do not attribute that use to the pre-select
    // receiver, even when another arm or a default could preserve it.
    return true;
  });
}

function definiteClosureInvocation(
  literal: Node,
  relationship: Node,
  owner: Node,
  use: Node,
  source: string,
): Node | null {
  const body = literal.childForFieldName("body");
  if (body === null || !directlyReachableInBlock(body, relationship, source)) return null;

  const direct = directInvocationOfLiteral(literal);
  if (direct !== null) return synchronousInvocation(direct) ? direct : null;

  const binding = closureLiteralBinding(literal, source);
  if (binding === undefined || !containsNode(binding.scope, use)) return null;

  for (const call of descendants(owner, "call_expression")) {
    if (call.startIndex <= binding.node.endIndex || call.endIndex >= use.startIndex ||
      !containsNode(binding.scope, call)) continue;
    const path = callPath(call, source);
    if (path?.length !== 1 || !closureNameMayReferenceLiteral(
      owner, binding, path[0]!, call, source,
    )) continue;
    const execution = synchronousCallExecution(owner, call, use, path[0]!, source);
    if (execution !== null) return execution;
  }
  for (const call of descendants(owner, "call_expression")) {
    if (call.startIndex <= binding.node.endIndex || call.endIndex >= use.startIndex ||
      !pathEquals(callPath(call, source)?.slice(-1), ["Do"]) || !synchronousInvocation(call)) continue;
    const callback = unwrapExpression(callArguments(call)[0]);
    if (callback?.type !== "identifier") continue;
    const callbackName = sourceText(callback, source).trim();
    if (!closureNameMayReferenceLiteral(owner, binding, callbackName, call, source) ||
      !standardOnceReceiver(call, owner, source)) continue;
    const execution = synchronousCallExecution(owner, call, use, callbackName, source);
    if (execution !== null) return execution;
  }
  return null;
}

interface ClosureLiteralBinding {
  name: string;
  node: Node;
  scope: Node;
}

function closureLiteralBinding(literal: Node, source: string): ClosureLiteralBinding | undefined {
  let binding: Node | null = literal.parent;
  while (binding !== null && ![
    "short_var_declaration", "var_spec", "assignment_statement", "statement_list", "block",
  ].includes(binding.type)) binding = binding.parent;
  if (binding === null || !["short_var_declaration", "var_spec", "assignment_statement"].includes(binding.type)) {
    return undefined;
  }
  const sides = assignmentSides(binding);
  if (sides === undefined || !sameSyntaxNode(unwrapExpression(sides.right) ?? null, literal)) return undefined;
  const left = unwrapExpression(sides.left);
  if (left?.type !== "identifier") return undefined;
  const name = sourceText(left, source).trim();
  const scope = enclosingBlock(binding);
  return /^[A-Za-z_]\w*$/.test(name) && scope !== null ? { name, node: binding, scope } : undefined;
}

function closureNameMayReferenceLiteral(
  owner: Node,
  origin: ClosureLiteralBinding,
  calledName: string,
  call: Node,
  source: string,
): boolean {
  const lineage = new Map<string, boolean>([[origin.name, true]]);
  const bindings = [
    ...descendants(owner, "short_var_declaration"),
    ...descendants(owner, "var_spec"),
    ...descendants(owner, "assignment_statement"),
  ].filter((candidate) =>
    candidate.startIndex >= origin.node.startIndex && candidate.endIndex < call.startIndex &&
    sameSyntaxNode(owningFunction(candidate), owner)
  ).sort((left, right) => left.startIndex - right.startIndex);

  for (const candidate of bindings) {
    if (sameSyntaxNode(candidate, origin.node)) continue;
    const pairs = simpleBindingPairs(candidate, source);
    const updates = pairs.map(({ name, right }) => ({
      name,
      derivesFromOrigin: right.type === "identifier" && lineage.get(sourceText(right, source).trim()) === true,
    }));
    for (const { name, derivesFromOrigin } of updates) {
      if (candidate.type === "short_var_declaration" || candidate.type === "var_spec") {
        const scope = enclosingBlock(candidate);
        if (scope !== null && containsNode(scope, call)) lineage.set(name, derivesFromOrigin);
        continue;
      }
      if (!lineage.has(name)) continue;
      if (derivesFromOrigin) {
        lineage.set(name, true);
      } else if (assignmentDefinitelyExecutesBeforeCall(owner, candidate, call, source)) {
        lineage.set(name, false);
      }
    }
  }
  if (lineage.get(calledName) !== true) return false;

  let lexicalOwner = owningFunction(call);
  while (lexicalOwner !== null && !sameSyntaxNode(lexicalOwner, owner)) {
    if (lexicalOwner.type !== "func_literal" ||
      !localNameUnshadowedAtUse(lexicalOwner, calledName, call, source)) return false;
    lexicalOwner = owningFunction(lexicalOwner);
  }
  return lexicalOwner !== null;
}

function simpleBindingPairs(node: Node, source: string): Array<{ name: string; right: Node }> {
  const sides = assignmentSides(node);
  if (sides === undefined) return [];
  const left = sides.left.type === "expression_list" ? sides.left.namedChildren : [unwrapExpression(sides.left)];
  const right = sides.right.type === "expression_list" ? sides.right.namedChildren : [unwrapExpression(sides.right)];
  if (left.length !== right.length) return [];
  return left.flatMap((candidate, index) => {
    const value = right[index];
    return candidate?.type === "identifier" && value !== undefined
      ? [{ name: sourceText(candidate, source).trim(), right: value }]
      : [];
  });
}

function standardOnceReceiver(call: Node, owner: Node, source: string): boolean {
  const path = callPath(call, source);
  if (path?.length !== 2 || path[1] !== "Do") return false;
  const receiver = path[0]!;
  let root = owner;
  while (root.parent !== null) root = root.parent;
  const aliases = standardImportAliases(root, source, "sync", "sync");
  if (aliases.size === 0 || ![...aliases].some((alias) => localNameUnshadowedAtUse(owner, alias, call, source))) {
    return false;
  }
  const declarations = [
    ...descendants(root, "var_spec"),
    ...descendants(root, "short_var_declaration"),
  ].filter((declaration) => {
    if (declaration.startIndex >= call.startIndex || !declarationNames(declaration, source).has(receiver)) return false;
    const declarationOwner = owningFunction(declaration);
    if (declarationOwner === null) return true;
    const scope = enclosingBlock(declaration);
    return sameSyntaxNode(declarationOwner, owner) && scope !== null && containsNode(scope, call);
  }).sort((left, right) => right.startIndex - left.startIndex);
  const declaration = declarations[0];
  if (declaration === undefined || ![...aliases].some((alias) =>
    new RegExp(`\\b${escapeRegExp(receiver)}\\b[\\s:=]*${escapeRegExp(alias)}\\.Once\\b`).test(
      sourceText(declaration, source).replace(/\s+/g, " "),
    )
  )) return false;
  return !descendants(owner, "assignment_statement").some((assignment) =>
    assignment.startIndex > declaration.endIndex && assignment.endIndex < call.startIndex &&
    directlyAssignsIdentifier(assignmentSides(assignment)?.left ?? assignment, receiver, source) &&
    assignmentDefinitelyExecutesBeforeCall(owner, assignment, call, source)
  );
}

function assignmentDefinitelyExecutesBeforeCall(owner: Node, assignment: Node, call: Node, source: string): boolean {
  const ownerBody = owner.childForFieldName("body");
  const block = enclosingBlock(assignment);
  if (ownerBody === null || block === null || !containsNode(block, call) || assignment.endIndex >= call.startIndex) {
    return false;
  }
  return directlyReachableInBlock(ownerBody, assignment, source);
}

function synchronousCallExecution(
  owner: Node,
  call: Node,
  use: Node,
  calledName: string,
  source: string,
): Node | null {
  let execution = call;
  let lexicalOwner = owningFunction(call);
  while (lexicalOwner !== null && !sameSyntaxNode(lexicalOwner, owner)) {
    if (lexicalOwner.type !== "func_literal" ||
      !localNameUnshadowedAtUse(lexicalOwner, calledName, call, source)) return null;
    const body = lexicalOwner.childForFieldName("body");
    const invocation = directInvocationOfLiteral(lexicalOwner) ??
      definiteClosureInvocation(lexicalOwner, execution, owner, use, source);
    if (body === null || invocation === null || !synchronousInvocation(invocation) ||
      !directlyReachableInBlock(body, execution, source)) return null;
    execution = invocation;
    lexicalOwner = owningFunction(lexicalOwner);
  }
  return lexicalOwner !== null && synchronousInvocation(execution) &&
    executesBeforeUse(owner, execution, use, source) ? execution : null;
}

function synchronousInvocation(call: Node): boolean {
  let current: Node | null = call.parent;
  while (current !== null && current.type !== "statement_list" && current.type !== "block") {
    if (["go_statement", "defer_statement"].includes(current.type)) return false;
    current = current.parent;
  }
  return true;
}

function ownerLocalDeclarationShadows(owner: Node, name: string, use: Node, source: string): boolean {
  return [
    ...descendants(owner, "short_var_declaration"),
    ...descendants(owner, "var_spec"),
    ...descendants(owner, "const_spec"),
  ].some((declaration) => {
    if (declaration.endIndex >= use.startIndex || !sameSyntaxNode(owningFunction(declaration), owner) ||
      !declarationNames(declaration, source).has(name)) return false;
    const scope = enclosingBlock(declaration);
    return scope !== null && containsNode(scope, use);
  }) || lexicalControlBindingShadows(owner, name, use, source);
}

function directlyAssignsIdentifier(node: Node, name: string, source: string): boolean {
  const candidate = unwrapExpression(node);
  if (candidate?.type === "identifier") return sourceText(candidate, source).trim() === name;
  if (candidate?.type !== "expression_list") return false;
  return candidate.namedChildren.some((child) =>
    child.type === "identifier" && sourceText(child, source).trim() === name
  );
}

function assignmentPreservesIdentifier(assignment: Node, name: string, source: string): boolean {
  const sides = assignmentSides(assignment);
  if (sides === undefined || sides.left.type !== "identifier") return false;
  if (sourceText(sides.left, source).trim() !== name ||
    source.slice(sides.left.endIndex, sides.right.startIndex).trim() !== "=") return false;
  const right = unwrapExpression(sides.right);
  return right?.type === "identifier" && sourceText(right, source).trim() === name;
}

function localNameUnshadowedAtUse(owner: Node, name: string, use: Node, source: string): boolean {
  const body = owner.childForFieldName("body");
  const signature = source.slice(owner.startIndex, body?.startIndex ?? owner.endIndex);
  if (new RegExp(`(?:\\(|,)\\s*${escapeRegExp(name)}(?:\\s|,)`).test(signature)) return false;
  return ![
    ...descendants(owner, "short_var_declaration"),
    ...descendants(owner, "var_spec"),
    ...descendants(owner, "const_spec"),
  ].some((declaration) => {
    if (declaration.endIndex >= use.startIndex || !declarationNames(declaration, source).has(name)) return false;
    const scope = enclosingBlock(declaration);
    return scope !== null && containsNode(scope, use);
  }) && !lexicalControlBindingShadows(owner, name, use, source);
}

function lexicalControlBindingShadows(owner: Node, name: string, use: Node, source: string): boolean {
  const escaped = escapeRegExp(name);
  return [
    ...descendants(owner, "range_clause"),
    ...descendants(owner, "type_switch_statement"),
    ...descendants(owner, "communication_case"),
  ].some((binder) => {
    if (binder.startIndex >= use.startIndex ||
      !new RegExp(`(?:^|[,;\\s])${escaped}\\s*:=`).test(sourceText(binder, source))) return false;
    const controller = binder.type === "range_clause" ? binder.parent : binder;
    return controller !== null && containsNode(controller, use);
  });
}

function controlActivationNodes(node: Node, boundary: Node | null): Node[] {
  const nodes: Node[] = [];
  let current = node.parent;
  while (current !== null && (boundary === null || !sameSyntaxNode(current, boundary))) {
    if (current.type === "if_statement" || current.type === "for_statement") {
      const condition = current.childForFieldName("condition");
      if (condition !== null) nodes.push(condition);
    } else if (current.type === "expression_case") {
      const value = current.childForFieldName("value");
      if (value !== null) nodes.push(value);
    }
    current = current.parent;
  }
  return nodes.reverse();
}

function cancellationActivationStatements(cancellationCase: Node): Node[] {
  return [
    ...descendants(cancellationCase, "expression_statement"),
    ...descendants(cancellationCase, "assignment_statement"),
    ...descendants(cancellationCase, "short_var_declaration"),
    ...descendants(cancellationCase, "send_statement"),
    ...descendants(cancellationCase, "inc_statement"),
  ].sort((left, right) => left.startIndex - right.startIndex);
}

function responseOwnerActivationStatements(owner: ResponseOwner, source: string): Node[] {
  const selections = descendants(owner.method, "select_statement")
    .filter((selection) =>
      selection.endIndex < owner.waitCall.startIndex && sameSyntaxNode(owningFunction(selection), owner.method)
    );
  const receiver = methodReceiverName(owner.method, source);
  if (receiver === undefined) return selections.sort((left, right) => left.startIndex - right.startIndex);
  const closureNames = new Set(descendants(owner.method, "func_literal").flatMap((literal) => {
    if (literal.endIndex >= owner.waitCall.startIndex || !descendants(literal, "communication_case").some((clause) => {
      const receive = clause.namedChildren.find((child) => child.type === "receive_statement");
      const left = receive?.childForFieldName("left");
      const right = receive?.childForFieldName("right");
      return left !== undefined && left !== null && right !== undefined && right !== null &&
        source.slice(left.endIndex, right.startIndex).trim() === "=" &&
        directlyAssignsIdentifier(left, receiver, source);
    })) return [];
    const binding = closureLiteralBinding(literal, source);
    return binding === undefined ? [] : [binding.name];
  }));
  let expanded = true;
  while (expanded) {
    expanded = false;
    for (const statement of [
      ...descendants(owner.method, "short_var_declaration"),
      ...descendants(owner.method, "var_spec"),
      ...descendants(owner.method, "assignment_statement"),
    ].filter((candidate) => candidate.endIndex < owner.waitCall.startIndex)) {
      for (const pair of simpleBindingPairs(statement, source)) {
        if (pair.right.type === "identifier" && closureNames.has(sourceText(pair.right, source).trim()) &&
          !closureNames.has(pair.name)) {
          closureNames.add(pair.name);
          expanded = true;
        }
      }
    }
    for (const literal of descendants(owner.method, "func_literal")) {
      if (literal.endIndex >= owner.waitCall.startIndex || !descendants(literal, "call_expression").some((call) => {
        const path = callPath(call, source);
        return path?.length === 1 && closureNames.has(path[0]!);
      })) continue;
      const binding = closureLiteralBinding(literal, source);
      if (binding !== undefined && !closureNames.has(binding.name)) {
        closureNames.add(binding.name);
        expanded = true;
      }
    }
  }
  const closureStatements = [
    ...descendants(owner.method, "short_var_declaration"),
    ...descendants(owner.method, "var_spec"),
    ...descendants(owner.method, "assignment_statement"),
    ...descendants(owner.method, "expression_statement"),
  ].filter((statement) =>
    statement.endIndex < owner.waitCall.startIndex && sameSyntaxNode(owningFunction(statement), owner.method) &&
    [...closureNames].some((name) => new RegExp(`\\b${escapeRegExp(name)}\\b`).test(sourceText(statement, source)))
  );
  return [...selections, ...closureStatements].sort((left, right) => left.startIndex - right.startIndex);
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

function directlyReachableInBlock(block: Node, node: Node, source: string): boolean {
  if (!containsNode(block, node)) return false;
  const expressionCase = enclosingExpressionCase(node, block);
  if (expressionCase !== undefined) {
    const statements = expressionCase.namedChildren.find((child) => child.type === "statement_list");
    const statement = statements?.namedChildren.find((candidate) => containsNode(candidate, node));
    if (statements === undefined || statement === undefined || !expressionCaseCanExecute(expressionCase, source)) return false;
    if (statements.namedChildren.some((candidate) =>
      candidate.endIndex < statement.startIndex &&
      unconditionallyTerminatesBefore(statements, candidate, statement, source)
    )) return false;
    return directlyReachableInBlock(block, expressionCase, source);
  }
  const communicationCase = enclosingCommunicationCase(node, block);
  if (communicationCase !== undefined) {
    const statements = communicationCase.namedChildren.find((child) => child.type === "statement_list");
    const statement = statements?.namedChildren.find((candidate) => containsNode(candidate, node));
    if (statements === undefined || statement === undefined) return false;
    if (statements.namedChildren.some((candidate) =>
      candidate.endIndex < statement.startIndex &&
      unconditionallyTerminatesBefore(statements, candidate, statement, source)
    )) return false;
    return directlyReachableInBlock(block, communicationCase, source);
  }
  let target = node;
  let currentBlock = enclosingBlock(node);
  while (currentBlock !== null) {
    const scope = currentBlock;
    const statement = directStatementContaining(scope, target);
    if (statement === undefined) return false;
    if (topLevelStatements(scope).some((candidate) =>
      candidate.endIndex < statement.startIndex &&
      unconditionallyTerminatesBefore(scope, candidate, statement, source)
    )) return false;
    if (sameSyntaxNode(scope, block)) return true;
    if (!nestedBlockCanExecute(scope, source)) return false;
    target = scope;
    currentBlock = enclosingBlock(scope);
  }
  return false;
}

function enclosingExpressionCase(node: Node, boundary: Node): Node | undefined {
  let current = node.parent;
  while (current !== null && !sameSyntaxNode(current, boundary)) {
    if (current.type === "expression_case") return current;
    current = current.parent;
  }
  return undefined;
}

function enclosingCommunicationCase(node: Node, boundary: Node): Node | undefined {
  let current = node.parent;
  while (current !== null && !sameSyntaxNode(current, boundary)) {
    if (current.type === "communication_case") return current;
    current = current.parent;
  }
  return undefined;
}

function expressionCaseCanExecute(expressionCase: Node, source: string): boolean {
  const expressionSwitch = expressionCase.parent;
  if (expressionSwitch?.type !== "expression_switch_statement") return true;
  const switchValue = booleanLiteral(expressionSwitch.childForFieldName("value"), source);
  const caseValue = booleanLiteral(expressionCase.childForFieldName("value"), source);
  return switchValue === undefined || caseValue === undefined || switchValue === caseValue;
}

function nestedBlockCanExecute(block: Node, source: string): boolean {
  let controller = block.parent;
  if (controller?.type === "else_clause") controller = controller.parent;
  if (controller === null) return false;
  if (controller?.type === "if_statement") {
    const condition = booleanLiteral(controller.childForFieldName("condition"), source);
    const consequence = controller.childForFieldName("consequence");
    if (consequence !== null && containsNode(consequence, block) && condition === false) return false;
    const alternative = controller.childForFieldName("alternative");
    if (alternative !== null && containsNode(alternative, block) && condition === true) return false;
  }
  if (controller?.type === "for_statement") {
    if (forConditionBoolean(controller, source) === false) return false;
  }
  return true;
}

function booleanLiteral(node: Node | null, source: string): boolean | undefined {
  const expression = unwrapExpression(node);
  if (expression?.type === "true") return true;
  if (expression?.type === "false") return false;
  return undefined;
}

function forConditionBoolean(loop: Node, source: string): boolean | undefined {
  const direct = booleanLiteral(loop.childForFieldName("condition"), source);
  if (direct !== undefined) return direct;
  const body = loop.childForFieldName("body");
  if (body === null) return undefined;
  const header = source.slice(loop.startIndex, body.startIndex).replace(/[\s()]/g, "");
  if (header === "forfalse") return false;
  if (header === "fortrue") return true;
  return undefined;
}

function unconditionalForLoop(loop: Node, source: string): boolean {
  const body = loop.childForFieldName("body");
  if (body === null) return false;
  const header = source.slice(loop.startIndex, body.startIndex).replace(/[\s()]/g, "");
  return header === "for" || header === "for;;" || forConditionBoolean(loop, source) === true;
}

function unconditionallyTerminatesBefore(
  block: Node,
  candidate: Node,
  target: Node,
  source: string,
): boolean {
  if (candidate.type === "labeled_statement") {
    const nested = candidate.namedChildren.find((child) => child.type !== "label_name");
    return nested !== undefined && unconditionallyTerminatesBefore(block, nested, target, source);
  }
  if (candidate.type === "return_statement") return true;
  if (candidate.type === "goto_statement") {
    const label = candidate.namedChildren.find((child) => child.type === "label_name");
    if (label === undefined) return true;
    const name = sourceText(label, source);
    const destination = [
      ...topLevelStatements(block),
      ...descendants(block, "labeled_statement"),
    ].find((statement) => {
      const destinationLabel = statement.childForFieldName("label");
      return statement.type === "labeled_statement" && destinationLabel !== null &&
        sourceText(destinationLabel, source) === name;
    });
    if (destination === undefined) return true;
    return destination.startIndex < candidate.startIndex || destination.startIndex > target.startIndex;
  }
  if (candidate.type === "if_statement") {
    const condition = booleanLiteral(candidate.childForFieldName("condition"), source);
    const consequence = candidate.childForFieldName("consequence");
    const alternative = candidate.childForFieldName("alternative");
    const consequenceTerminates = consequence !== null &&
      branchUnconditionallyTerminates(block, consequence, target, source);
    const alternativeTerminates = alternative !== null &&
      branchUnconditionallyTerminates(block, alternative, target, source);
    if (condition === true) return consequenceTerminates;
    if (condition === false) return alternativeTerminates;
    return consequenceTerminates && alternativeTerminates;
  }
  if (candidate.type === "expression_switch_statement" || candidate.type === "type_switch_statement") {
    const caseType = candidate.type === "expression_switch_statement" ? "expression_case" : "type_case";
    const cases = [
      ...descendants(candidate, caseType),
      ...descendants(candidate, "default_case"),
    ].filter((caseNode) =>
      nearestAncestorOfTypes(caseNode, new Set(["expression_switch_statement", "type_switch_statement"]))?.id ===
        candidate.id
    );
    return cases.length > 0 && cases.some((caseNode) => isDefaultCase(caseNode, source)) &&
      cases.every((caseNode, index) =>
        switchCaseUnconditionallyTerminates(block, cases, index, target, source));
  }
  if (candidate.type === "select_statement") {
    const cases = [
      ...descendants(candidate, "communication_case"),
      ...descendants(candidate, "default_case"),
    ].filter((caseNode) =>
      nearestAncestorOfTypes(caseNode, new Set(["select_statement"]))?.id === candidate.id
    );
    // With no default, a select either chooses one of these cases or blocks
    // forever. Neither outcome reaches the following statement when every
    // selectable arm terminates.
    return cases.length === 0 ||
      cases.every((caseNode) => caseUnconditionallyTerminates(block, caseNode, target, source));
  }
  if (candidate.type === "for_statement") {
    if (!unconditionalForLoop(candidate, source)) return false;
    return !loopCanExit(candidate, source);
  }
  if (candidate.type !== "expression_statement") return false;
  const expression = unwrapExpression(candidate.namedChildren[0]);
  return expression?.type === "call_expression" &&
    pathEquals(callPath(expression, source), ["panic"]) &&
    unshadowedBuiltin(expression, "panic", source);
}

function switchCaseUnconditionallyTerminates(
  block: Node,
  cases: Node[],
  index: number,
  target: Node,
  source: string,
): boolean {
  const current = cases[index];
  if (current === undefined) return false;
  if (caseUnconditionallyTerminates(block, current, target, source)) return true;
  const statements = current.namedChildren.find((child) => child.type === "statement_list")?.namedChildren ?? [];
  const last = statements.at(-1);
  return last?.type === "fallthrough_statement" &&
    switchCaseUnconditionallyTerminates(block, cases, index + 1, target, source);
}

function loopCanExit(loop: Node, source: string): boolean {
  const body = loop.childForFieldName("body");
  if (body === null) return true;
  return [
    ...descendants(loop, "break_statement"),
    ...descendants(loop, "goto_statement"),
  ].some((candidate) => {
    if (!sameSyntaxNode(owningFunction(candidate), owningFunction(loop)!)) return false;
    if (candidate.type === "goto_statement") return directlyReachableInBlock(body, candidate, source);
    return nearestBreakableAncestor(candidate)?.id === loop.id &&
      directlyReachableInBlock(body, candidate, source);
  });
}

function nearestBreakableAncestor(node: Node): Node | null {
  let current = node.parent;
  while (current !== null) {
    if (["for_statement", "expression_switch_statement", "type_switch_statement", "select_statement"]
      .includes(current.type)) return current;
    current = current.parent;
  }
  return null;
}

function branchUnconditionallyTerminates(
  block: Node,
  branch: Node,
  target: Node,
  source: string,
): boolean {
  if (branch.type === "else_clause") {
    const nested = branch.namedChildren.find((child) =>
      child.type === "block" || child.type === "if_statement");
    return nested !== undefined && branchUnconditionallyTerminates(block, nested, target, source);
  }
  if (branch.type === "block") {
    return statementSequenceUnconditionallyTerminates(block, topLevelStatements(branch), target, source);
  }
  return unconditionallyTerminatesBefore(block, branch, target, source);
}

function caseUnconditionallyTerminates(
  block: Node,
  caseNode: Node,
  target: Node,
  source: string,
): boolean {
  const statements = caseNode.namedChildren.find((child) => child.type === "statement_list");
  return statements !== undefined &&
    statementSequenceUnconditionallyTerminates(block, statements.namedChildren, target, source);
}

function statementSequenceUnconditionallyTerminates(
  block: Node,
  statements: Node[],
  target: Node,
  source: string,
): boolean {
  const owner = owningFunction(target);
  for (const statement of statements) {
    if (unconditionallyTerminatesBefore(block, statement, target, source)) return true;
    if (owner !== null && statementCanBypassRemainder(statement, owner)) return false;
  }
  return false;
}

function statementCanBypassRemainder(statement: Node, owner: Node): boolean {
  return [
    ...descendants(statement, "break_statement"),
    ...descendants(statement, "continue_statement"),
    ...descendants(statement, "goto_statement"),
  ].some((candidate) => sameSyntaxNode(owningFunction(candidate), owner));
}

function isDefaultCase(caseNode: Node, source: string): boolean {
  return caseNode.type === "default_case" || /^default\s*:/.test(sourceText(caseNode, source).trimStart());
}

function nearestAncestorOfTypes(node: Node, types: Set<string>): Node | null {
  let current = node.parent;
  while (current !== null) {
    if (types.has(current.type)) return current;
    current = current.parent;
  }
  return null;
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

function hasUnconditionalTerminationBetween(
  block: Node,
  before: Node,
  after: Node,
  source: string,
): boolean {
  const beforeStatement = topLevelStatementContaining(block, before);
  const afterStatement = topLevelStatementContaining(block, after);
  if (beforeStatement === undefined || afterStatement === undefined) return true;
  return topLevelStatements(block).some((statement) =>
    statement.startIndex > beforeStatement.endIndex && statement.endIndex < afterStatement.startIndex &&
    unconditionallyTerminatesBefore(block, statement, afterStatement, source)
  );
}

function topLevelStatementContaining(block: Node, node: Node): Node | undefined {
  let current: Node | null = node;
  while (current !== null && current.parent !== null) {
    if (current.parent.type === "statement_list" && sameSyntaxNode(current.parent.parent, block)) return current;
    current = current.parent;
  }
  return undefined;
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

function firstChangedNode(file: SourceRevision, root: Node, previousRoot: Node | undefined, nodes: Node[]): Node | undefined {
  return nodes.find((node) => nodeSemanticallyChanged(file, root, previousRoot, node));
}

function nodeSemanticallyChanged(
  file: SourceRevision,
  root: Node,
  previousRoot: Node | undefined,
  node: Node,
): boolean {
  const line = node.startPosition.row + 1;
  const endLine = node.endPosition.row + 1;
  if (!changed(file, line, endLine)) return false;
  if (file.status !== "modified" || file.previous === undefined || previousRoot === undefined) {
    return semanticallyChanged(file, line, endLine);
  }

  const previousNode = correspondingPreviousNode(root, previousRoot, node, file.current, file.previous);
  if (previousNode !== undefined && previousNode.type === node.type) {
    return goSourceSemantics(sourceText(node, file.current)) !==
      goSourceSemantics(sourceText(previousNode, file.previous));
  }
  return semanticallyChanged(file, line, endLine);
}

/**
 * Map an evidence node to the same declaration and comment-insensitive AST
 * path in the previous revision. Line-number comparison is insufficient when
 * an unrelated edit shifts a multiline comment inside an evidence node.
 */
function correspondingPreviousNode(
  root: Node,
  previousRoot: Node,
  node: Node,
  currentSource: string,
  previousSource: string,
): Node | undefined {
  const owner = enclosingNamedDeclaration(node) ?? root;
  const identity = declarationIdentity(owner, currentSource);
  if (identity === undefined) return undefined;
  const previousOwner = owner.type === "source_file"
    ? previousRoot
    : descendants(previousRoot, owner.type).find((candidate) =>
      declarationIdentity(candidate, previousSource) === identity
    );
  if (previousOwner === undefined) return undefined;

  const path: number[] = [];
  let current = node;
  while (!sameSyntaxNode(current, owner)) {
    const parent = current.parent;
    if (parent === null) return undefined;
    const siblings = semanticNamedChildren(parent);
    const index = siblings.findIndex((candidate) => sameSyntaxNode(candidate, current));
    if (index < 0) return undefined;
    path.unshift(index);
    current = parent;
  }

  let previous = previousOwner;
  for (const index of path) {
    previous = semanticNamedChildren(previous)[index]!;
    if (previous === undefined) return undefined;
  }
  return previous;
}

function enclosingNamedDeclaration(node: Node): Node | undefined {
  let current: Node | null = node;
  while (current !== null) {
    if (["method_declaration", "function_declaration", "type_spec"].includes(current.type)) return current;
    current = current.parent;
  }
  return undefined;
}

function declarationIdentity(node: Node, source: string): string | undefined {
  if (node.type === "source_file") return "source_file";
  const name = node.childForFieldName("name");
  if (name === null) return undefined;
  if (node.type === "method_declaration") {
    const receiver = methodReceiverType(node, source);
    return receiver === undefined ? undefined : `${node.type}:${receiver}.${sourceText(name, source)}`;
  }
  return `${node.type}:${sourceText(name, source)}`;
}

function semanticNamedChildren(node: Node): Node[] {
  return node.namedChildren.filter((child) => child.type !== "comment");
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
  if (goSourceSemantics(file.current) === goSourceSemantics(file.previous)) return false;
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
  return goSourceSemantics(line);
}

function goSourceSemantics(source: string): string {
  let quote: '"' | "'" | "`" | undefined;
  let escaped = false;
  let blockComment = false;
  let lineComment = false;
  let semantic = "";
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index]!;
    const next = source[index + 1];
    if (lineComment) {
      if (character === "\n") lineComment = false;
      continue;
    }
    if (blockComment) {
      if (character === "*" && next === "/") {
        blockComment = false;
        index += 1;
      }
      continue;
    }
    if (quote === undefined && character === "/" && next === "/") {
      lineComment = true;
      index += 1;
      continue;
    }
    if (quote === undefined && character === "/" && next === "*") {
      blockComment = true;
      index += 1;
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
  if (block.type === "statement_list") return block.namedChildren;
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
