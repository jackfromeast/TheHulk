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
class ClientSideCookieManipulationSink extends DataFlow::Node {
    ClientSideCookieManipulationSink() {
        exists(DataFlow::PropWrite pw |
            pw.getBase() = DataFlow::globalVarRef("document") and
            pw.getPropertyName() = "cookie" and
            this = pw.getRhs()
        )
    }
}
