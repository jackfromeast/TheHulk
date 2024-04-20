import javascript
import DOM
import semmle.javascript.security.dataflow.RequestForgeryCustomizations


/**
 * Description:
 * 
 * Sink nodes for client-side cross-site scripting vulnerabilities.
 * 
 * TODO: Consider using extends instead of instanceof
 */
class ClientSideRequestForgerySink extends DataFlow::Node {
    ClientSideRequestForgerySink() {
        this instanceof RequestForgery::Sink or
        this instanceof FetchRequestSink or
        this instanceof XMLHttpRequestRequestSink or
        this instanceof AsyncRequestSink or
        this instanceof JQueryAjaxRequestSink
    }
}


class FetchRequestSink extends DataFlow::Node {
    FetchRequestSink() {
        exists(DataFlow::CallNode callNode |
            callNode.getCalleeName() = "fetch" and
            this = callNode.getArgument(0)
        )
    }
}

class XMLHttpRequestRequestSink extends DataFlow::Node {
    XMLHttpRequestRequestSink() {
        exists(DataFlow::CallNode callNode |
            callNode.getReceiver().toString() = "XMLHttpRequest" and
            callNode.getCalleeName() = "open" and
            this = callNode.getArgument(0)
        )
    }
}

class AsyncRequestSink extends DataFlow::Node {
    AsyncRequestSink() {
        exists(DataFlow::CallNode callNode |
            callNode.getCalleeName() = "asyncRequest" and
            this = callNode.getArgument(0)
        )
    }
}

class JQueryAjaxRequestSink extends DataFlow::Node {
    JQueryAjaxRequestSink() {
        exists(DataFlow::CallNode callNode |
            callNode.getCalleeName() = "ajax" and
            this = callNode.getArgument(0)
        )
    }
}


