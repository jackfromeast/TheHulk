/**
 * @name DOM-Clobbering
 * @description Finding potential DOM clobbering vulnerabilities with the following pattern:
 *              var s= document.createElement(‘script’);
                s.src = window.BOOMR.url || DEFAULT_BOOMR_SRC;
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id js/xss-through-dom
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript
//  import semmle.javascript.security.dataflow.XssThroughDomQuery
import DataFlow::PathGraph
import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom
import semmle.javascript.security.dataflow.DomBasedXssCustomizations

import Sinks.TheHulkSink

//  import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom
//  import semmle.javascript.security.dataflow.DomBasedXssCustomizations
//  import semmle.javascript.security.dataflow.UnsafeJQueryPluginCustomizations::UnsafeJQueryPlugin as UnsafeJQuery
//  import semmle.javascript.frameworks.jQuery
//  import semmle.javascript.security.dataflow.Xss::Shared as Shared
//  import semmle.javascript.frameworks.ClientRequests::ClientRequest


/**
 * DOM Clobbering Code Patterns G
 * window.BOOMR.url is clobberable or its definition sites can be clobbered by another document.
 * 
 * var s= document.createElement(‘script’);
   s.src = window.BOOMR.url || DEFAULT_BOOMR_SRC;

 * refer to the Github example from 
 * https://www.ruhrsec.de/downloads/slides/Everything-You-Wanted-to-Know-About-DOM-Clobbering-But-Were-Afraid-to-Ask-Soheil-Khodayari-RuhrSec.pdf
 */
class WindowPropLookupAsSource extends DataFlow::Node {
    WindowPropLookupAsSource() {
        exists(DataFlow::PropRead read |
            // Capture the reading of a property from the 'window' object
            read.getBase() = DataFlow::globalVarRef("window") and 
            read = this
        )
    }
}

class DocumentPropLookupAsSource extends DataFlow::Node {
    DocumentPropLookupAsSource() {
        exists(DataFlow::PropRead read |
            // Capture the reading of a property from the 'document' object
            read.getBase() = DataFlow::globalVarRef("document") and 
            read = this
        )
    }
}

predicate propReadAsTaintStep(DataFlow::Node pred, DataFlow::Node succ){
    exists(DataFlow::PropRead pr | 
        pr.getBase() = pred and
        pr.flowsTo(succ)
    )
}


class DebuggingConfig extends TaintTracking::Configuration {
    // Configuration baseConfig;
  
    DebuggingConfig() { this = "DOMClobberingPatternG-1" }
      
      override predicate isSource(DataFlow::Node source) { 
        source instanceof WindowPropLookupAsSource or
        source instanceof DocumentPropLookupAsSource 
      }
  
      // Extended here to include the SocketWriteSink
      override predicate isSink(DataFlow::Node sink) { 
        // sink instanceof ClientSideSinks
        sink instanceof CrossSiteScriptingSink
      }
  
      override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {
        DataFlow::localFieldStep(pred, succ) or
        TaintTracking::arrayStep(pred, succ) or
        propReadAsTaintStep(pred, succ)
      }
  
  }
  
  from DebuggingConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
  where cfg.hasFlowPath(source, sink)
  select sink.getNode(), source, sink,
    "$@ is potentially clobberable and flows to the XSS sink.", source.getNode(), source.getNode().toString()
  