/**
 * @name KNFSd decoded count missing a complete guard pair
 * @description Finds same-function decoded-count storage flows unless both a
 *              rejecting upper-bound check and an XDR stream-presence check
 *              precede the sink. Results still require independent review of
 *              remote reachability and interprocedural service bounds.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id tobabz/knfsd-missing-counted-data-guard-pair
 * @tags security
 *       external/cwe/cwe-400
 */

import cpp

bindingset[path]
private predicate isServerPath(string path) {
  path.matches("%fs/nfsd/%") or
  path.matches("%net/sunrpc/%")
}

private predicate isStorageSink(FunctionCall call, Expr size) {
  exists(Function target |
    target = call.getTarget() and
    (
      target.getName() = "kmalloc" or
      target.getName() = "kmalloc_noprof" or
      target.getName() = "__kmalloc" or
      target.getName() = "__kmalloc_noprof" or
      target.getName() = "kzalloc" or
      target.getName() = "kzalloc_noprof"
    ) and
    size = call.getArgument(0)
  )
  or
  exists(Function target |
    target = call.getTarget() and
    target.getName() = "memcpy" and
    size = call.getArgument(2)
  )
  or
  exists(Function target |
    target = call.getTarget() and
    target.getName() = "svcxdr_tmpalloc" and
    size = call.getArgument(1)
  )
  or
  exists(Function target |
    target = call.getTarget() and
    (target.getName() = "svcxdr_dupstr" or target.getName() = "svcxdr_savemem") and
    size = call.getArgument(2)
  )
  or
  exists(Function target |
    target = call.getTarget() and
    target.getName() = "svc_fill_symlink_pathname" and
    size = call.getArgument(3)
  )
}

private Declaration getDecodedDeclaration(FunctionCall decode) {
  decode.getTarget().getName() = "xdr_stream_decode_u32" and
  result = decode.getArgument(1).(AddressOfExpr).getAddressable()
}

private predicate expressionUses(Expr expression, Declaration declaration) {
  exists(Access access |
    access = expression.getAChild*() and
    access.getTarget() = declaration
  )
}

private predicate rejectingUpperBound(
  FunctionCall decode, FunctionCall sink, Declaration decoded, IfStmt guard
) {
  exists(RelationalOperation comparison, ReturnStmt exit |
    comparison = guard.getCondition().getAChild*() and
    expressionUses(comparison.getGreaterOperand(), decoded) and
    exit = guard.getThen().getAChild*() and
    decode.getLocation().getStartLine() < guard.getLocation().getStartLine() and
    guard.getLocation().getEndLine() < sink.getLocation().getStartLine()
  )
}

private predicate streamPresenceCheck(
  FunctionCall decode, FunctionCall sink, Declaration decoded
) {
  exists(FunctionCall presence |
    presence.getTarget().getName() = "xdr_inline_decode" and
    expressionUses(presence.getArgument(1), decoded) and
    decode.getLocation().getStartLine() < presence.getLocation().getStartLine() and
    presence.getLocation().getStartLine() < sink.getLocation().getStartLine()
  )
  or
  exists(IfStmt guard, FunctionCall remaining |
    rejectingUpperBound(decode, sink, decoded, guard) and
    remaining = guard.getCondition().getAChild*() and
    remaining.getTarget().getName() = "xdr_stream_remaining"
  )
}

private predicate completeGuardPair(
  FunctionCall decode, FunctionCall sink, Declaration decoded
) {
  exists(IfStmt upperBound |
    rejectingUpperBound(decode, sink, decoded, upperBound)
  ) and
  streamPresenceCheck(decode, sink, decoded)
}

from FunctionCall decode, FunctionCall sink, Expr size, Declaration decoded, Function enclosing
where
  decoded = getDecodedDeclaration(decode) and
  isStorageSink(sink, size) and
  expressionUses(size, decoded) and
  enclosing = decode.getEnclosingFunction() and
  enclosing = sink.getEnclosingFunction() and
  decode.getLocation().getStartLine() < sink.getLocation().getStartLine() and
  isServerPath(enclosing.getFile().getRelativePath()) and
  not completeGuardPair(decode, sink, decoded)
select sink,
  "Decoded XDR count " + decoded.getName() + " reaches storage in " + enclosing.getName() +
    " without a locally proven complete upper-bound and stream-presence guard pair."
