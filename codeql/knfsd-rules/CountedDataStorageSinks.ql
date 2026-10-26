/**
 * @name KNFSd counted-data storage sinks
 * @description Inventories allocation, reservation, and copy calls that can
 *              consume decoded counted-data lengths in KNFSd and server-side
 *              RPC code. This is evidence for candidate generation, not a
 *              vulnerability verdict.
 * @kind problem
 * @problem.severity recommendation
 * @precision medium
 * @id tobabz/knfsd-xdr-storage-sinks
 * @tags security
 *       external/cwe/cwe-400
 */

import cpp

bindingset[path]
private predicate isServerPath(string path) {
  path.matches("%fs/nfsd/%") or
  path.matches("%net/sunrpc/%")
}

bindingset[name]
private predicate isStorageSink(string name) {
  name = "kmalloc" or
  name = "kmalloc_noprof" or
  name = "__kmalloc" or
  name = "__kmalloc_noprof" or
  name = "kzalloc" or
  name = "kzalloc_noprof" or
  name = "kmalloc_flex" or
  name = "kzalloc_objs" or
  name = "memcpy" or
  name = "svcxdr_tmpalloc" or
  name = "svcxdr_dupstr" or
  name = "svcxdr_savemem" or
  name = "svc_fill_symlink_pathname"
}

private predicate isRelevantFunction(Function function) {
  function.getName().regexpMatch("nfs.*decode.*") or
  function.getName().regexpMatch("nfsd.*decode.*") or
  function.getName().regexpMatch("svcxdr_.*") or
  function.getName() = "nfsd3_proc_symlink" or
  function.getName() = "svc_fill_symlink_pathname" or
  function.getName() = "svcauth_gss_legacy_init" or
  function.getName() = "gss_read_proxy_verf"
}

from FunctionCall sink, Function target, Function enclosing
where
  target = sink.getTarget() and
  isStorageSink(target.getName()) and
  enclosing = sink.getEnclosingFunction() and
  isRelevantFunction(enclosing) and
  isServerPath(enclosing.getFile().getRelativePath())
select sink,
  "Review storage sink " + target.getName() + " in " + enclosing.getName() +
    " for a decoded count, a dominating finite upper bound, and a dominating stream-presence check."
