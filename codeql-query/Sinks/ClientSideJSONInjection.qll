import javascript
import DOM

/**
 * Description:
 * 
 * Sink nodes for client-side web storage manipulation vulnerabilities.
 * 
 */
class ClientSideJSONInjectionSink extends DataFlow::Node {
    ClientSideJSONInjectionSink() {
        exists(DataFlow::CallNode callNode |
            callNode.getReceiver() instanceof JSONObject and
            callNode.getCalleeName() = "parse" and
            callNode.getAnArgument() = this
        )
    }
}

class JSONObject extends DataFlow::Node {
    JSONObject() {
        exists(Variable a | 
            a.getName().toString() = "JSON" |
            this = a.getAReference().flow())
        or
        exists(Variable a |
            a.getADefinition().getSource().flow() instanceof JSONObject and
            this = a.getAReference().flow()
        )
    }
}

