import cpp
import CountedDataGuardPair

from FunctionCall sink, Declaration decoded, Function enclosing
where missingCompleteGuardPair(sink, decoded, enclosing)
select sink,
  "Decoded XDR count " + decoded.getName() + " reaches storage in " + enclosing.getName() +
    " without a proven field-bound guard pair or terminating finite-service presence guard."
