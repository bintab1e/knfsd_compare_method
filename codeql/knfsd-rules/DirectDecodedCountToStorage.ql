/**
 * @name KNFSd direct decoded-count to storage candidate
 * @description Finds same-function flows where a declaration populated by
 *              xdr_stream_decode_u32 is later referenced by a relevant
 *              allocation, reservation, or copy size. Results require
 *              independent guard and remote-reachability review.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id tobabz/knfsd-direct-decoded-count-to-storage
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

from FunctionCall decode, FunctionCall sink, Expr size, Declaration decoded, Function enclosing
where
  decoded = getDecodedDeclaration(decode) and
  isStorageSink(sink, size) and
  expressionUses(size, decoded) and
  enclosing = decode.getEnclosingFunction() and
  enclosing = sink.getEnclosingFunction() and
  decode.getLocation().getStartLine() < sink.getLocation().getStartLine() and
  isServerPath(enclosing.getFile().getRelativePath())
select sink,
  "Decoded XDR count " + decoded.getName() + " reaches a storage-size argument in " +
    enclosing.getName() +
    "; verify both required guards and remote KNFSd reachability."
