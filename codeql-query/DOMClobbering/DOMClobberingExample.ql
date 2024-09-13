/**
 * @name DOM-Clobbering-bilibili.com-69605160da
 * @description Finding potential DOM clobbering vulnerabilities with the identified cloudable sources
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.1
 * @precision high
 * @id js/xss-through-dom
 * @tags security
 *       external/cwe/cwe-079
 */

 import javascript
 import DataFlow::PathGraph
 import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom
 import semmle.javascript.security.dataflow.DomBasedXssCustomizations

 
 
 predicate propReadAsTaintStep(DataFlow::Node pred, DataFlow::Node succ){
     exists(DataFlow::PropRead pr | 
         pr.getBase() = pred and
         pr.flowsTo(succ)
     )
 }
 

 class IdentifiedClobberableSource extends DataFlow::Node {
     IdentifiedClobberableSource() {
        this instanceof IdentifiedClobberableSourceWinTypeOne or
        this instanceof IdentifiedClobberableSourceDocTypeOne or
        this instanceof IdentifiedClobberableSourceDocTypeTwo or
        this instanceof IdentifiedClobberableSourceDOMAPI
     }
 }


class IdentifiedClobberableSourceWinTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceWinTypeOne() {
      exists(DataFlow::PropRead propRead |
        exists(Location loc |
          propRead.asExpr().getLocation() = loc and
          (
            // id=11, type=WIN-TYPE-1, prop=webpackChunkwebpackLogReporter 
            (
                loc.getFile().getAbsolutePath().matches("%s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
                loc.getStartLine() = 2 and loc.getEndLine() = 2 and
                loc.getStartColumn() <= 120956 and loc.getEndColumn() >= 120956
            ) or
            // id=12, type=WIN-TYPE-1, prop=webpackChunkwebpackLogReporter
            (
                loc.getFile().getAbsolutePath().matches("%s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
                loc.getStartLine() = 2 and loc.getEndLine() = 2 and
                loc.getStartColumn() <= 120950 and loc.getEndColumn() >= 120950
            )
          )
        ) and
        this = propRead
      )
    }
}

class IdentifiedClobberableSourceDocTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeOne() {
        exists(DataFlow::PropRead propRead |
          exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (
              // id=299, type=DOC-TYPE-1, prop=$el 
              (
                  loc.getFile().getAbsolutePath().matches("%69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
                  loc.getStartLine() = 26 and loc.getEndLine() = 26 and
                  loc.getStartColumn() <= 44399 and loc.getEndColumn() >= 44399
              )
            )
          ) and
          this = propRead
        )
    }
}

class IdentifiedClobberableSourceDocTypeTwo extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeTwo() {
        exists(DataFlow::PropRead propRead |
          exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (
              // id=299, type=DOC-TYPE-1, prop=$el 
              (
                  loc.getFile().getAbsolutePath().matches("%s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
                  loc.getStartLine() = 2 and loc.getEndLine() = 2 and
                  loc.getStartColumn() <= 21246 and loc.getEndColumn() >= 21246
              )
            )
          ) and
          this = propRead
        )
    }
}


class IdentifiedClobberableSourceDOMAPI extends DataFlow::Node {
    IdentifiedClobberableSourceDOMAPI() {
        exists(DataFlow::PropRead propRead |
          exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (
              // id=323, type=API-TYPE-2, API=querySelector, property=iframe[src=\"https://s1.hdslb.com/bfs/seed/jinkela/short/cols/iframe.html\"]
              (
                  loc.getFile().getAbsolutePath().matches("%s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
                  loc.getStartLine() = 2 and loc.getEndLine() = 2 and
                  loc.getStartColumn() <= 21112 and loc.getEndColumn() >= 21112
              ) or (
                loc.getFile().getAbsolutePath().matches("%/home/xxxxxxxxxxxx/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-04-22-45/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/index.6965ff6a.js") and
                loc.getStartLine() = 01 and loc.getEndLine() = 01 and
                loc.getStartColumn() <= 48270 and loc.getEndColumn() >= 48270
            )
          )) and 
          this = propRead.getALocalSource()
        )
    }
}

 class DebuggingConfig extends TaintTracking::Configuration {
     // Configuration baseConfig;
   
     DebuggingConfig() { this = "DOM-Clobbering-bilibili.com-69605160da" }
       
       override predicate isSource(DataFlow::Node source) { 
         source instanceof IdentifiedClobberableSource
       }
   
       // Extended here to include the SocketWriteSink
       override predicate isSink(DataFlow::Node sink) { 
         sink instanceof DomBasedXss::Sink
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
   