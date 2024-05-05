/**
 * @name Dangerous Document Lookup
 * @description Finding all the builtin property lookups (e.g. currentScript) on the document object
 *              which will return a DOM element and can be shadowed by injected scripts.
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript
import DOM



/** 
 * Refer to https://html.spec.whatwg.org/multipage/dom.html#the-document-object
 * Contains a list of all the builtin properties of the 'document' object.
 */
predicate isDOMBuiltinProperty(string propNames) {
  propNames = [
    "parseHTMLUnsafe",
    "domain",
    "location",
    "referrer",
    "cookie",
    "lastModified",
    "readyState",
    "title",
    "dir",
    "body",
    "head",
    "images",
    "applets",
    "links",
    "forms",
    "embeds",
    "plugins",
    "scripts",
    "currentScript",
    "getElementsByName",
    "open",
    "close",
    "write",
    "writeln",
    "defaultView",
    "hasFocus",
    "designMode",
    "execCommand",
    "queryCommandEnabled",
    "queryCommandIndeterm",
    "queryCommandState",
    "queryCommandSupported",
    "queryCommandValue",
    "hidden",
    "visibilityState",
    "onvisibilitychange",
    "onwebkitvisibilitychange",
  ]
}

// The return type of the following lookups is HTMLCollection or HTMLElement or String
predicate isDangerousDOMBuiltinProperty(string propNames) {
  propNames = [
    "parseHTMLUnsafe",
    "domain",
    "location",
    "referrer",
    "cookie",
    "lastModified",
    "title",
    "dir",
    "body",
    "head",
    "images",
    "applets",
    "links",
    "forms",
    "embeds",
    "plugins",
    "scripts",
    "currentScript",
    "open",
    "queryCommandValue"
  ]
}

/**
 * Find all the reference in the code to the 'document' object.
 * 
 * We are interested in the following two patterns:
 * 1/ Using the globalVarRef function to get the reference to the 'document' object
 * 2/ If the object is used in a property read, where the property is a builtin DOM property
 */
class DocumentNode extends DataFlow::Node {
    DocumentNode() {
      this = DataFlow::globalVarRef("document") or 
      exists(DataFlow::PropRead read |
        isDOMBuiltinProperty(read.getPropertyName()) and
        read.getBase() = this
      )
    }
}


class DangerousDocumentLookupAsSource extends DataFlow::Node {
  DangerousDocumentLookupAsSource() {
        exists(DataFlow::PropRead read |
            // Capture the reading of a property from the 'document' object
            read.getBase() instanceof DocumentNode and 
            read = this
        )
    }
}