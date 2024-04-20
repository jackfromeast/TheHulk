import javascript
import DOM
import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom
import semmle.javascript.security.dataflow.DomBasedXssCustomizations


/**
 * Description:
 * 
 * Sink nodes for client-side html injection vulnerabilities.
 * The following patterns are included:
 * 
 * 1/ document.write(T)
 * 2/ document.writeln(T)
 * 3/ element.innerHTML = T (in XSS)
 * 4/ element.outerHTML = T (in XSS)
 * 5/ element.insertAdjacentHTML(T)
 * 6/ element.insertAdjacentElement(T)
 * 7/ element.replaceChild(T)
 * 8/ element.appendChild(T)
 * 9/ element.append(T)
 * 
 */
class HTMLInjectionSink extends DataFlow::Node {
    HTMLInjectionSink() {
        exists(DomMethodCallNodeExtended callNode | 
            callNode.interpretsArgumentsAsHtml(this)
        )
    }
}


class DomMethodCallNodeExtended extends DomMethodCallNode {
    DomMethodCallNodeExtended() {
        isDomNode(this.getReceiver())
    }

    override predicate interpretsArgumentsAsHtml(DataFlow::Node arg) {
        exists(int argPos, string name |
            arg = this.getArgument(argPos) and
            name = this.getMethodName() |
            
            // individual signatures:
            name = "write"
            or
            name = "writeln"
            or
            name = "insertAdjacentHTML" and argPos = 1
            or
            name = "insertAdjacentElement" and argPos = 1
            or
            name = "insertBefore" and argPos = 0
            or
            name = "createElement" and argPos = 0
            or
            name = "appendChild" and argPos = 0
            or 
            name = "append" and argPos = 0
            or 
            name = "replaceChild" and argPos = 0
        )
        }
}
