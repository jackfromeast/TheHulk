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
class RegexInjectionSink extends DataFlow::Node {
    RegexInjectionSink() {
        exists(DataFlow::InvokeNode invokeNode |
            invokeNode.getCalleeName() = "RegExp" and
            this = invokeNode.getArgument(0)
        )
    }
}

