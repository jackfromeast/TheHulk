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
class ClientSideOpenRedirectSink extends DataFlow::Node {
    ClientSideOpenRedirectSink() {
        this instanceof WindowURLManipulationSink
    }
}


class WindowURLManipulationSink extends DataFlow::Node {
    WindowURLManipulationSink() {
        exists(DataFlow::PropWrite pw |
            pw.getBase() = DataFlow::globalVarRef("window") and
            pw.getPropertyName() = "location" and
            this = pw.getRhs()
        )
    }
}
