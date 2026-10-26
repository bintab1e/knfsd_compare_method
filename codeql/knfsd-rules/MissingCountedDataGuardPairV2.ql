/**
 * @name KNFSd decoded count missing a complete guard pair
 * @description Finds strict-scope decoded-count storage flows unless either a
 *              field bound plus presence check or a terminating same-count
 *              presence check over the finite RPC service request is proven.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id tobabz/knfsd-missing-counted-data-guard-pair
 * @tags security
 *       external/cwe/cwe-400
 */

import cpp
import CountedDataGuardPair

bindingset[path]
private predicate isServerPath(string path) {
  path.matches("%fs/nfsd/%") or
  path.matches("%net/sunrpc/%")
}

private predicate isStrictScope(Function function) {
  function.getName() = "nfs3svc_decode_symlinkargs" or
  function.getName() = "nfsd4_decode_compound" or
  function.getName() = "nfsd4_decode_create" or
  function.getName() = "nfsd4_decode_open" or
  function.getName() = "nfsd4_decode_open_claim4" or
  function.getName() = "nfsd4_decode_component4" or
  function.getName() = "nfsd4_decode_setclientid" or
  function.getName() = "nfsd4_decode_exchange_id" or
  function.getName() = "nfsd4_decode_opaque" or
  function.getName() = "svcauth_gss_legacy_init" or
  function.getName() = "gss_read_proxy_verf"
}

from FunctionCall sink, Declaration decoded, Function enclosing
where
  missingCompleteGuardPair(sink, decoded, enclosing) and
  isServerPath(enclosing.getFile().getRelativePath()) and
  isStrictScope(enclosing)
select sink,
  "Decoded XDR count " + decoded.getName() + " reaches storage in " + enclosing.getName() +
    " without a proven field-bound guard pair or terminating finite-service presence guard."
