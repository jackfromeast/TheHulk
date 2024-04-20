import javascript
import DOM
import semmle.javascript.security.dataflow.RequestForgeryCustomizations


/**
 * Description:
 * 
 * Sink nodes for client-side open redirect vulnerabilities.
 * 
 * TODO: Consider using extends instead of instanceof
 */
class ClientSideDomainManipulationSink extends DataFlow::Node {
    ClientSideDomainManipulationSink() {
        exists(DataFlow::PropWrite pw |
            pw.getBase() = DataFlow::globalVarRef("document") and
            pw.getPropertyName() = "domain" and
            this = pw.getRhs()
        )
    }
}
