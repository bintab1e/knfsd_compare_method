import cpp

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

  private Declaration getPresenceResult(FunctionCall presence) {
    exists(AssignExpr assignment |
      presence = assignment.getRValue().getAChild*() and
      result = assignment.getLValue().(Access).getTarget()
    )
    or
    exists(Variable variable |
      presence = variable.getInitializer().getExpr().getAChild*() and
      result = variable
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

  private predicate terminatingServicePresenceCheck(
    FunctionCall decode, FunctionCall sink, Declaration decoded
  ) {
    exists(
      FunctionCall presence, Declaration checked, IfStmt guard, NotExpr negation,
      ReturnStmt exit
    |
      presence.getTarget().getName() = "xdr_inline_decode" and
      expressionUses(presence.getArgument(1), decoded) and
      checked = getPresenceResult(presence) and
      negation = guard.getCondition().getAChild*() and
      expressionUses(negation.getOperand(), checked) and
      exit = guard.getThen().getAChild*() and
      decode.getLocation().getStartLine() < presence.getLocation().getStartLine() and
      presence.getLocation().getStartLine() < guard.getLocation().getStartLine() and
      guard.getLocation().getEndLine() < sink.getLocation().getStartLine()
    )
  }

  private predicate completeGuardPair(
    FunctionCall decode, FunctionCall sink, Declaration decoded
  ) {
    exists(IfStmt upperBound |
      rejectingUpperBound(decode, sink, decoded, upperBound)
    ) and
    streamPresenceCheck(decode, sink, decoded)
    or
    terminatingServicePresenceCheck(decode, sink, decoded)
  }

  predicate missingCompleteGuardPair(
    FunctionCall sink, Declaration decoded, Function enclosing
  ) {
    exists(FunctionCall decode, Expr size |
      decoded = getDecodedDeclaration(decode) and
      isStorageSink(sink, size) and
      expressionUses(size, decoded) and
      enclosing = decode.getEnclosingFunction() and
      enclosing = sink.getEnclosingFunction() and
      decode.getLocation().getStartLine() < sink.getLocation().getStartLine() and
      not completeGuardPair(decode, sink, decoded)
    )
  }
