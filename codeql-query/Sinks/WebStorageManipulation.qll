import javascript
import DOM


/**
 * Description:
 * 
 * Sink nodes for client-side web storage manipulation vulnerabilities.
 * 
 * E.g.
 * localStorage.setItem("key", "value")
 * sessionStorage.setItem("key", "value")
 */
class WebStorageManipulationSink extends DataFlow::Node {
    WebStorageManipulationSink() {
        exists(DataFlow::CallNode callNode |
            callNode.getReceiver() instanceof WebStorageObject and
            callNode.getCalleeName() = "setItem" and
            callNode.getAnArgument() = this
        )
    }
}

class WebStorageObject extends DataFlow::Node {
    WebStorageObject() {
        exists(Variable a | 
            a.getName() in ["localStorage", "sessionStorage"] |
            this = a.getAReference().flow())
        or
        exists(Variable a |
            a.getADefinition().getSource().flow() instanceof WebStorageObject and
            this = a.getAReference().flow()
        )
    }
}

