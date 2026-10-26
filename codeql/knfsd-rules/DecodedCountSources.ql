/**
 * @name KNFSd decoded XDR count sources
 * @description Inventories remotely controlled counted-data length decodes in
 *              the KNFSd and server-side RPC scope. This is evidence for
 *              candidate generation, not a vulnerability verdict.
 * @kind problem
 * @problem.severity recommendation
 * @precision high
 * @id tobabz/knfsd-xdr-decoded-count-sources
 * @tags security
 *       external/cwe/cwe-400
 */

import cpp

bindingset[path]
private predicate isServerPath(string path) {
  path.matches("%fs/nfsd/%") or
  path.matches("%net/sunrpc/%")
}

from FunctionCall decode, Function target, Function enclosing
where
  target = decode.getTarget() and
  target.getName() = "xdr_stream_decode_u32" and
  enclosing = decode.getEnclosingFunction() and
  isServerPath(enclosing.getFile().getRelativePath())
select decode,
  "Decoded XDR count source in " + enclosing.getName() +
    "; retain it only when remote KNFSd dispatch and a storage sink are independently proven."
