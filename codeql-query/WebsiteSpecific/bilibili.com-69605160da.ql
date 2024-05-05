/**
* @name DOM-Clobbering-bilibili.com-[object Object]
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
        
class IdentifiedClobberableSourceWinTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceWinTypeOne() {
        exists(DataFlow::PropRead propRead |
        exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (// id=1, type=WIN-TYPE-1, prop=__v_isRef 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 52072 and loc.getEndColumn() >= 52072
        ) or // id=2, type=WIN-TYPE-1, prop=$el 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 44400 and loc.getEndColumn() >= 44400
        ) or // id=5, type=WIN-TYPE-1, prop=bsource 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 4353 and loc.getEndColumn() >= 4353
        ) or // id=6, type=WIN-TYPE-1, prop=__v_isRef 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 52072 and loc.getEndColumn() >= 52072
        ) or // id=7, type=WIN-TYPE-1, prop=$el 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 44400 and loc.getEndColumn() >= 44400
        ) or // id=10, type=WIN-TYPE-1, prop=bsource 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 4353 and loc.getEndColumn() >= 4353
        ) or // id=11, type=WIN-TYPE-1, prop=__v_isRef 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 52072 and loc.getEndColumn() >= 52072
        ) or // id=12, type=WIN-TYPE-1, prop=$el 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 44400 and loc.getEndColumn() >= 44400
        ) or // id=13, type=WIN-TYPE-1, prop=__v_isRef 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 52072 and loc.getEndColumn() >= 52072
        ) or // id=14, type=WIN-TYPE-1, prop=$el 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 44400 and loc.getEndColumn() >= 44400
        ) or // id=15, type=WIN-TYPE-1, prop=__v_isRef 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 52072 and loc.getEndColumn() >= 52072
        ) or // id=16, type=WIN-TYPE-1, prop=$el 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 44400 and loc.getEndColumn() >= 44400
        ) or // id=17, type=WIN-TYPE-1, prop=__v_isRef 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 52072 and loc.getEndColumn() >= 52072
        ) or // id=18, type=WIN-TYPE-1, prop=$el 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 44400 and loc.getEndColumn() >= 44400
        ) or // id=19, type=WIN-TYPE-1, prop=__v_isRef 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 52072 and loc.getEndColumn() >= 52072
        ) or // id=20, type=WIN-TYPE-1, prop=$el 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 44400 and loc.getEndColumn() >= 44400
        ) or // id=21, type=WIN-TYPE-1, prop=__v_isRef 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 52072 and loc.getEndColumn() >= 52072
        ) or // id=22, type=WIN-TYPE-1, prop=$el 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 44400 and loc.getEndColumn() >= 44400
        ) or // id=23, type=WIN-TYPE-1, prop=__v_isRef 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 52072 and loc.getEndColumn() >= 52072
        ) or // id=24, type=WIN-TYPE-1, prop=$el 
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/vendor.84ea2c28.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 44400 and loc.getEndColumn() >= 44400
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
            ()
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
            ()
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
            (// id=3, type=DOM-API, prop=meta, api=getElementsByTagName
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/index.6965ff6a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13605 and loc.getEndColumn() >= 13605
        ) or // id=4, type=DOM-API, prop=meta, api=getElementsByTagName
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25971 and loc.getEndColumn() >= 25971
        ) or // id=8, type=DOM-API, prop=meta, api=getElementsByTagName
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/static/laputa-home/client/assets/index.6965ff6a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13605 and loc.getEndColumn() >= 13605
        ) or // id=9, type=DOM-API, prop=meta, api=getElementsByTagName
        (
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/test-crawler-04-05-11-16/bilibili.com/69605160da/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25971 and loc.getEndColumn() >= 25971
        ))
        ) and
        this = propRead
      )
  }
}
class IdentifiedClobberableSource extends DataFlow::Node {
    IdentifiedClobberableSource() {
    this instanceof IdentifiedClobberableSourceWinTypeOne or
    this instanceof IdentifiedClobberableSourceDocTypeOne or
    this instanceof IdentifiedClobberableSourceDocTypeTwo or
    this instanceof IdentifiedClobberableSourceDOMAPI
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

DebuggingConfig() { this = "DOM-Clobbering-bilibili.com-[object Object]" }
    
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
