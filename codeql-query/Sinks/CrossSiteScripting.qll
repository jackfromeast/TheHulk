import javascript
import DOM
import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom
import semmle.javascript.security.dataflow.DomBasedXssCustomizations


/**
 * Description:
 * 
 * Sink nodes for client-side cross-site scripting vulnerabilities.
 * 
 * TODO: Consider using extends instead of instanceof
 */
class CrossSiteScriptingSink extends DataFlow::Node {
    CrossSiteScriptingSink() {
        // The builtin "DomBasedXss::Sink" contains the following sinks:
        // 1/ LibrarySink, library sinks from jQuery, AngularJS, and etc.
        // 2/ WriteUrlSink
        // 3/ DomSink (e.g. innerHTML, outerHTML)
        // 4/ HtmlParserSink
        // 5/ DangerouslySetInnerHtmlSink
        // 6/ VueTemplateSink, VueCreateElementSink
        // 7/ EmailHtmlBodySink
        // 8/ VHtmlSink
        // 9/ SafePipe
        // 10/ SinkFromModel
        this instanceof DomBasedXss::Sink or
        this instanceof SetScriptElemSink or
        this instanceof DynamicFunctionConstructorSink or
        this instanceof InnerHTMLSink
    }
}


// TODO: Check & Add the following pattern to the XSS sink
// $('<div>').append('TAINT');

/**
 * Description:
 * 
 * This class contains the dataflow nodes which try to set the src/textContent property of 
 * a script element.
 * 
 * E.g. 
 * let a = document.createElement("script");
 * a.src = "http://example.com"
 * a.textContent = "alert(1)"
 */
class SetScriptElemSink extends DataFlow::Node {
    DOMScriptElement scriptElem;
    
    SetScriptElemSink() {
        exists(DataFlow::PropWrite pw |
            pw.getPropertyName() in ["src", "textContent"] |
            scriptElem = pw.getBase() and
            this = pw.getRhs()
        )
    }
}

/**
 * Description:
 * 
 * This class contains the dataflow nodes which try to create a function dynamically.
 * 
 * E.g. 
 * let a = new Function("alert(1)");
 */
class DynamicFunctionConstructorSink extends DataFlow::Node {
    DynamicFunctionConstructorSink() {
        exists(DataFlow::InvokeNode invokeNode |
            invokeNode.getCalleeNode() instanceof FunctionConstructor and
            this = invokeNode.getArgument(0)
        )
    }
}

/**
 * Description:
 * 
 * This class represents dataflow nodes that attempt to assign a value to the property `innerHTML`.
 * 
 * E.g.
 * element.innerHTML = p;
 */
class InnerHTMLSink extends DataFlow::Node {
    InnerHTMLSink() {
        exists(DataFlow::PropWrite propertyWrite |
            propertyWrite.getPropertyName() = "innerHTML" and
            this = propertyWrite.getRhs()
        )
    }
}


/**
 * Description:
 * 
 * This class contains the dataflow nodes which is/might be a script element.
 * In the client-side javascript, there are many ways to create a script element.
 * 1/ document.createElement("script")
 * 
 * E.g.
 * let a = document.createElement("script");
 * 
 * Note:
 * Besides, there is another to check whether the element is a DOM element or not.
 * `isDomNode(this)` from DOM.qll
 * However, this method is based on their type checking (inference) system and may not be accurate.
 * 
 * This DOMScriptElement() is a recursive function call
 */
class DOMScriptElement extends DataFlow::Node {

    DOMScriptElement() {
        exists(Variable a, DataFlow::CallNode callNode|
            callNode.getCalleeName() = "createElement" and
            callNode.getAnArgument().asExpr().toString() = "'script'" |
            a.getADefinition().getSource().flow() = callNode and
            this = a.getAReference().flow()
        ) or 
        exists(Variable a |
            a.getADefinition().getSource().flow() instanceof DOMScriptElement and
            this = a.getAReference().flow()
        )
    }
}

/**
 * Description:
 * 
 * This class contains the dataflow nodes that points to the Function constructor.
 * Included function constructors:
 * 1/ Function
 * 2/ eval
 * 3/ setTimeout
 * 4/ setInterval
 * 
 * E.g.
 * let a = Function;
 * let b = a;
 * let c = b;
 * let d = new c(T);
 * 
 * Note: 
 * This FunctionConstructor() is a recursive function call
 */
class FunctionConstructor extends DataFlow::Node {
    FunctionConstructor() {
        exists(Variable a | 
            a.getName() in ["Function", "eval", "setTimeout", "setInterval"] |
            this = a.getAReference().flow())
        or
        exists(Variable a |
            a.getADefinition().getSource().flow() instanceof FunctionConstructor and
            this = a.getAReference().flow()
        )
    }
}


