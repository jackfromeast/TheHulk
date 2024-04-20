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
class WebSocketHijackingSink extends DataFlow::Node {
    WebSocketHijackingSink() {
        this instanceof NewSocketSink
    }
}


class NewSocketSink extends DataFlow::Node {
    NewSocketSink() {
        exists(DataFlow::InvokeNode invokeNode |
            invokeNode.getCalleeName() = "WebSocket" and
            this = invokeNode.getArgument(0)
        )
    }
}
