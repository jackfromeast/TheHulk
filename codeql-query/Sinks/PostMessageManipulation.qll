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
class PostMessageManipulationSink extends DataFlow::Node {
    PostMessageManipulationSink() {
        exists(DataFlow::PropWrite pw |
            pw.getBase() = DataFlow::globalVarRef("window") and
            pw.getPropertyName() = "postMessage" and
            this = pw.getRhs()
        )
    }
}
