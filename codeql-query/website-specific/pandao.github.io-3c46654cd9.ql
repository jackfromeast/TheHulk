/**
* @name DOM-Clobbering-pandao.github.io-3c46654cd9
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
            (
        (   // id=1, type=WIN-TYPE-1, prop=nodeName 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 31440 and loc.getEndColumn() >= 31440
        ) or 
        (   // id=2, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 31474 and loc.getEndColumn() >= 31474
        ) or 
        (   // id=3, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 32047 and loc.getEndColumn() >= 32047
        ) or 
        (   // id=945, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/editormd.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 29494 and loc.getEndColumn() >= 29494
        ) or 
        (   // id=1078, type=WIN-TYPE-1, prop=require 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/link-dialog/link-dialog.js") and
            loc.getStartLine() = 109 and loc.getEndLine() = 109 and
            loc.getStartColumn() <= 2 and loc.getEndColumn() >= 2
        ) or 
        (   // id=1079, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/link-dialog/link-dialog.js") and
            loc.getStartLine() = 113 and loc.getEndLine() = 113 and
            loc.getStartColumn() <= 7 and loc.getEndColumn() >= 7
        ) or 
        (   // id=1089, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 24571 and loc.getEndColumn() >= 24571
        ) or 
        (   // id=1090, type=WIN-TYPE-1, prop=selector 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 24696 and loc.getEndColumn() >= 24696
        ) or 
        (   // id=1313, type=WIN-TYPE-1, prop=require 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/reference-link-dialog/reference-link-dialog.js") and
            loc.getStartLine() = 129 and loc.getEndLine() = 129 and
            loc.getStartColumn() <= 2 and loc.getEndColumn() >= 2
        ) or 
        (   // id=1314, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/reference-link-dialog/reference-link-dialog.js") and
            loc.getStartLine() = 133 and loc.getEndLine() = 133 and
            loc.getStartColumn() <= 7 and loc.getEndColumn() >= 7
        ) or 
        (   // id=1779, type=WIN-TYPE-1, prop=require 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/preformatted-text-dialog/preformatted-text-dialog.js") and
            loc.getStartLine() = 148 and loc.getEndLine() = 148 and
            loc.getStartColumn() <= 2 and loc.getEndColumn() >= 2
        ) or 
        (   // id=1780, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/preformatted-text-dialog/preformatted-text-dialog.js") and
            loc.getStartLine() = 152 and loc.getEndLine() = 152 and
            loc.getStartColumn() <= 7 and loc.getEndColumn() >= 7
        ) or 
        (   // id=1867, type=WIN-TYPE-1, prop=require 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/table-dialog/table-dialog.js") and
            loc.getStartLine() = 194 and loc.getEndLine() = 194 and
            loc.getStartColumn() <= 2 and loc.getEndColumn() >= 2
        ) or 
        (   // id=1868, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/table-dialog/table-dialog.js") and
            loc.getStartLine() = 198 and loc.getEndLine() = 198 and
            loc.getStartColumn() <= 7 and loc.getEndColumn() >= 7
        ) or 
        (   // id=2633, type=WIN-TYPE-1, prop=require 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/html-entities-dialog/html-entities-dialog.js") and
            loc.getStartLine() = 149 and loc.getEndLine() = 149 and
            loc.getStartColumn() <= 2 and loc.getEndColumn() >= 2
        ) or 
        (   // id=2634, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/html-entities-dialog/html-entities-dialog.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 7 and loc.getEndColumn() >= 7
        ) or 
        (   // id=2661, type=WIN-TYPE-1, prop=onajaxStart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 7554 and loc.getEndColumn() >= 7554
        ) or 
        (   // id=2665, type=WIN-TYPE-1, prop=onajaxSend 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 7554 and loc.getEndColumn() >= 7554
        ) or 
        (   // id=2696, type=WIN-TYPE-1, prop=onajaxSuccess 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 7554 and loc.getEndColumn() >= 7554
        ) or 
        (   // id=2700, type=WIN-TYPE-1, prop=onajaxComplete 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 7554 and loc.getEndColumn() >= 7554
        ) or 
        (   // id=2704, type=WIN-TYPE-1, prop=onajaxStop 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 7554 and loc.getEndColumn() >= 7554
        ) or 
        (   // id=2747, type=WIN-TYPE-1, prop=getDefaultComputedStyle 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 23453 and loc.getEndColumn() >= 23453
        ) or 
        (   // id=2767, type=WIN-TYPE-1, prop=require 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/goto-line-dialog/goto-line-dialog.js") and
            loc.getStartLine() = 133 and loc.getEndLine() = 133 and
            loc.getStartColumn() <= 2 and loc.getEndColumn() >= 2
        ) or 
        (   // id=2768, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/plugins/goto-line-dialog/goto-line-dialog.js") and
            loc.getStartLine() = 137 and loc.getEndLine() = 137 and
            loc.getStartColumn() <= 7 and loc.getEndColumn() >= 7
        )
        )
        ) and
        this = propRead
      )
    }
}
class IdentifiedClobberableSourceDocTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeOne() {
        none()
    }
}
class IdentifiedClobberableSourceDocTypeTwo extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeTwo() {
        exists(DataFlow::PropRead propRead |
            exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (
        (   // id=2630, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 181 and loc.getEndColumn() >= 181
        ) or 
        (   // id=2631, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 238 and loc.getEndColumn() >= 238
        ) or 
        (   // id=2744, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 23442 and loc.getEndColumn() >= 23442
        ) or 
        (   // id=4589, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 29477 and loc.getEndColumn() >= 29477
        ) or 
        (   // id=5135, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/cdnjs.cloudflare.com/ajax/libs/clipboard.js/2.0.0/clipboard.min.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 1987 and loc.getEndColumn() >= 1987
        ))
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
        (   // id=4, type=DOM-API, prop=CodeMirror-scroll, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=5, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/en.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=6, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/en.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=21, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 16779 and loc.getEndColumn() >= 16779
        ) or 
        (   // id=22, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 40 and loc.getEndLine() = 40 and
            loc.getStartColumn() <= 2061 and loc.getEndColumn() >= 2061
        ) or 
        (   // id=24, type=DOM-API, prop=raphael-marker-endblock33-obj146, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=25, type=DOM-API, prop=raphael-marker-endblock33-obj147, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=26, type=DOM-API, prop=raphael-marker-endblock33-obj148, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=27, type=DOM-API, prop=raphael-marker-endblock33-obj150, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=28, type=DOM-API, prop=raphael-marker-endblock55-obj174, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=29, type=DOM-API, prop=raphael-marker-endblock55-obj180, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=30, type=DOM-API, prop=raphael-marker-endopen77-obj183, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=31, type=DOM-API, prop=pre, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6831 and loc.getEndColumn() >= 6831
        ) or 
        (   // id=32, type=DOM-API, prop=pre, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/prettify.min.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 15103 and loc.getEndColumn() >= 15103
        ) or 
        (   // id=33, type=DOM-API, prop=code, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/prettify.min.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 15103 and loc.getEndColumn() >= 15103
        ) or 
        (   // id=34, type=DOM-API, prop=xmp, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/prettify.min.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 15103 and loc.getEndColumn() >= 15103
        ) or 
        (   // id=35, type=DOM-API, prop=editormd-toc-menu, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=36, type=DOM-API, prop=markdown-toc, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=43, type=DOM-API, prop=li, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6831 and loc.getEndColumn() >= 6831
        ) or 
        (   // id=44, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 16779 and loc.getEndColumn() >= 16779
        ) or 
        (   // id=48, type=DOM-API, prop=editormd-tex, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=49, type=DOM-API, prop=katex, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=93, type=DOM-API, prop=flowchart, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=96, type=DOM-API, prop=tspan, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 969 and loc.getEndColumn() >= 969
        ) or 
        (   // id=106, type=DOM-API, prop=raphael-marker-block, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26477 and loc.getEndColumn() >= 26477
        ) or 
        (   // id=107, type=DOM-API, prop=raphael-marker-endblock33-obj192, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=109, type=DOM-API, prop=raphael-marker-endblock33-obj193, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=111, type=DOM-API, prop=raphael-marker-endblock33-obj194, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=112, type=DOM-API, prop=raphael-marker-block, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=115, type=DOM-API, prop=raphael-marker-endblock33-obj192, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=116, type=DOM-API, prop=raphael-marker-endblock33-obj193, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=117, type=DOM-API, prop=raphael-marker-endblock33-obj194, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=120, type=DOM-API, prop=raphael-marker-endblock33-obj196, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=122, type=DOM-API, prop=raphael-marker-endblock33-obj196, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=124, type=DOM-API, prop=sequence-diagram, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=138, type=DOM-API, prop=raphael-marker-endblock55-obj220, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=140, type=DOM-API, prop=raphael-marker-endblock55-obj220, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=144, type=DOM-API, prop=raphael-marker-endblock55-obj226, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=146, type=DOM-API, prop=raphael-marker-endblock55-obj226, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=148, type=DOM-API, prop=raphael-marker-open, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26477 and loc.getEndColumn() >= 26477
        ) or 
        (   // id=149, type=DOM-API, prop=raphael-marker-endopen77-obj229, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=151, type=DOM-API, prop=raphael-marker-open, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=152, type=DOM-API, prop=raphael-marker-endopen77-obj229, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=153, type=DOM-API, prop=markdown-toc-list, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=164, type=DOM-API, prop=alttext-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/en.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=165, type=DOM-API, prop=alttext-image, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/en.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=183, type=DOM-API, prop=raphael-marker-endblock33-obj192, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=184, type=DOM-API, prop=raphael-marker-endblock33-obj193, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=185, type=DOM-API, prop=raphael-marker-endblock33-obj194, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=186, type=DOM-API, prop=raphael-marker-endblock33-obj196, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=187, type=DOM-API, prop=raphael-marker-endblock55-obj220, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=188, type=DOM-API, prop=raphael-marker-endblock55-obj226, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=189, type=DOM-API, prop=raphael-marker-endopen77-obj229, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=226, type=DOM-API, prop=raphael-marker-endblock33-obj238, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=228, type=DOM-API, prop=raphael-marker-endblock33-obj239, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=230, type=DOM-API, prop=raphael-marker-endblock33-obj240, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=234, type=DOM-API, prop=raphael-marker-endblock33-obj238, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=235, type=DOM-API, prop=raphael-marker-endblock33-obj239, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=236, type=DOM-API, prop=raphael-marker-endblock33-obj240, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=239, type=DOM-API, prop=raphael-marker-endblock33-obj242, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=241, type=DOM-API, prop=raphael-marker-endblock33-obj242, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=257, type=DOM-API, prop=raphael-marker-endblock55-obj266, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=259, type=DOM-API, prop=raphael-marker-endblock55-obj266, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=263, type=DOM-API, prop=raphael-marker-endblock55-obj272, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=265, type=DOM-API, prop=raphael-marker-endblock55-obj272, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=268, type=DOM-API, prop=raphael-marker-endopen77-obj275, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=271, type=DOM-API, prop=raphael-marker-endopen77-obj275, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=318, type=DOM-API, prop=raphael-marker-endblock33-obj238, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=319, type=DOM-API, prop=raphael-marker-endblock33-obj239, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=320, type=DOM-API, prop=raphael-marker-endblock33-obj240, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=321, type=DOM-API, prop=raphael-marker-endblock33-obj242, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=322, type=DOM-API, prop=raphael-marker-endblock55-obj266, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=323, type=DOM-API, prop=raphael-marker-endblock55-obj272, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=324, type=DOM-API, prop=raphael-marker-endopen77-obj275, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=365, type=DOM-API, prop=raphael-marker-endblock33-obj284, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=367, type=DOM-API, prop=raphael-marker-endblock33-obj285, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=369, type=DOM-API, prop=raphael-marker-endblock33-obj286, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=373, type=DOM-API, prop=raphael-marker-endblock33-obj284, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=374, type=DOM-API, prop=raphael-marker-endblock33-obj285, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=375, type=DOM-API, prop=raphael-marker-endblock33-obj286, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=378, type=DOM-API, prop=raphael-marker-endblock33-obj288, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=380, type=DOM-API, prop=raphael-marker-endblock33-obj288, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=396, type=DOM-API, prop=raphael-marker-endblock55-obj312, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=398, type=DOM-API, prop=raphael-marker-endblock55-obj312, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=402, type=DOM-API, prop=raphael-marker-endblock55-obj318, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=404, type=DOM-API, prop=raphael-marker-endblock55-obj318, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=407, type=DOM-API, prop=raphael-marker-endopen77-obj321, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=410, type=DOM-API, prop=raphael-marker-endopen77-obj321, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=463, type=DOM-API, prop=raphael-marker-endblock33-obj284, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=464, type=DOM-API, prop=raphael-marker-endblock33-obj285, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=465, type=DOM-API, prop=raphael-marker-endblock33-obj286, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=466, type=DOM-API, prop=raphael-marker-endblock33-obj288, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=467, type=DOM-API, prop=raphael-marker-endblock55-obj312, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=468, type=DOM-API, prop=raphael-marker-endblock55-obj318, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=469, type=DOM-API, prop=raphael-marker-endopen77-obj321, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=507, type=DOM-API, prop=raphael-marker-endblock33-obj330, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=509, type=DOM-API, prop=raphael-marker-endblock33-obj331, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=511, type=DOM-API, prop=raphael-marker-endblock33-obj332, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=515, type=DOM-API, prop=raphael-marker-endblock33-obj330, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=516, type=DOM-API, prop=raphael-marker-endblock33-obj331, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=517, type=DOM-API, prop=raphael-marker-endblock33-obj332, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=520, type=DOM-API, prop=raphael-marker-endblock33-obj334, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=522, type=DOM-API, prop=raphael-marker-endblock33-obj334, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=538, type=DOM-API, prop=raphael-marker-endblock55-obj358, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=540, type=DOM-API, prop=raphael-marker-endblock55-obj358, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=544, type=DOM-API, prop=raphael-marker-endblock55-obj364, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=546, type=DOM-API, prop=raphael-marker-endblock55-obj364, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=549, type=DOM-API, prop=raphael-marker-endopen77-obj367, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=552, type=DOM-API, prop=raphael-marker-endopen77-obj367, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=565, type=DOM-API, prop=alttext-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 3477 and loc.getEndColumn() >= 3477
        ) or 
        (   // id=566, type=DOM-API, prop=alttext-image, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 3477 and loc.getEndColumn() >= 3477
        ) or 
        (   // id=588, type=DOM-API, prop=pui-search-submit, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=596, type=DOM-API, prop=raphael-marker-endblock33-obj330, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=597, type=DOM-API, prop=raphael-marker-endblock33-obj331, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=598, type=DOM-API, prop=raphael-marker-endblock33-obj332, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=599, type=DOM-API, prop=raphael-marker-endblock33-obj334, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=600, type=DOM-API, prop=raphael-marker-endblock55-obj358, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=601, type=DOM-API, prop=raphael-marker-endblock55-obj364, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=602, type=DOM-API, prop=raphael-marker-endopen77-obj367, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=642, type=DOM-API, prop=raphael-marker-endblock33-obj376, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=644, type=DOM-API, prop=raphael-marker-endblock33-obj377, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=646, type=DOM-API, prop=raphael-marker-endblock33-obj378, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=650, type=DOM-API, prop=raphael-marker-endblock33-obj376, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=651, type=DOM-API, prop=raphael-marker-endblock33-obj377, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=652, type=DOM-API, prop=raphael-marker-endblock33-obj378, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=655, type=DOM-API, prop=raphael-marker-endblock33-obj380, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=657, type=DOM-API, prop=raphael-marker-endblock33-obj380, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=673, type=DOM-API, prop=raphael-marker-endblock55-obj404, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=675, type=DOM-API, prop=raphael-marker-endblock55-obj404, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=679, type=DOM-API, prop=raphael-marker-endblock55-obj410, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=681, type=DOM-API, prop=raphael-marker-endblock55-obj410, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=684, type=DOM-API, prop=raphael-marker-endopen77-obj413, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=687, type=DOM-API, prop=raphael-marker-endopen77-obj413, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=696, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 3770 and loc.getEndColumn() >= 3770
        ) or 
        (   // id=697, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 3770 and loc.getEndColumn() >= 3770
        ) or 
        (   // id=723, type=DOM-API, prop=raphael-marker-endblock33-obj376, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=724, type=DOM-API, prop=raphael-marker-endblock33-obj377, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=725, type=DOM-API, prop=raphael-marker-endblock33-obj378, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=726, type=DOM-API, prop=raphael-marker-endblock33-obj380, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=727, type=DOM-API, prop=raphael-marker-endblock55-obj404, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=728, type=DOM-API, prop=raphael-marker-endblock55-obj410, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=729, type=DOM-API, prop=raphael-marker-endopen77-obj413, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=773, type=DOM-API, prop=raphael-marker-endblock33-obj422, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=775, type=DOM-API, prop=raphael-marker-endblock33-obj423, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=777, type=DOM-API, prop=raphael-marker-endblock33-obj424, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=781, type=DOM-API, prop=raphael-marker-endblock33-obj422, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=782, type=DOM-API, prop=raphael-marker-endblock33-obj423, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=783, type=DOM-API, prop=raphael-marker-endblock33-obj424, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=786, type=DOM-API, prop=raphael-marker-endblock33-obj426, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=788, type=DOM-API, prop=raphael-marker-endblock33-obj426, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=804, type=DOM-API, prop=raphael-marker-endblock55-obj450, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=806, type=DOM-API, prop=raphael-marker-endblock55-obj450, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=810, type=DOM-API, prop=raphael-marker-endblock55-obj456, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=812, type=DOM-API, prop=raphael-marker-endblock55-obj456, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=815, type=DOM-API, prop=raphael-marker-endopen77-obj459, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=818, type=DOM-API, prop=raphael-marker-endopen77-obj459, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=847, type=DOM-API, prop=raphael-marker-endblock33-obj422, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=848, type=DOM-API, prop=raphael-marker-endblock33-obj423, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=849, type=DOM-API, prop=raphael-marker-endblock33-obj424, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=850, type=DOM-API, prop=raphael-marker-endblock33-obj426, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=851, type=DOM-API, prop=raphael-marker-endblock55-obj450, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=852, type=DOM-API, prop=raphael-marker-endblock55-obj456, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=853, type=DOM-API, prop=raphael-marker-endopen77-obj459, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=897, type=DOM-API, prop=raphael-marker-endblock33-obj468, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=899, type=DOM-API, prop=raphael-marker-endblock33-obj469, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=901, type=DOM-API, prop=raphael-marker-endblock33-obj470, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=905, type=DOM-API, prop=raphael-marker-endblock33-obj468, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=906, type=DOM-API, prop=raphael-marker-endblock33-obj469, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=907, type=DOM-API, prop=raphael-marker-endblock33-obj470, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=910, type=DOM-API, prop=raphael-marker-endblock33-obj472, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=912, type=DOM-API, prop=raphael-marker-endblock33-obj472, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=928, type=DOM-API, prop=raphael-marker-endblock55-obj496, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=930, type=DOM-API, prop=raphael-marker-endblock55-obj496, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=934, type=DOM-API, prop=raphael-marker-endblock55-obj502, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=936, type=DOM-API, prop=raphael-marker-endblock55-obj502, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=939, type=DOM-API, prop=raphael-marker-endopen77-obj505, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=942, type=DOM-API, prop=raphael-marker-endopen77-obj505, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=946, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/editormd.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 16029 and loc.getEndColumn() >= 16029
        ) or 
        (   // id=966, type=DOM-API, prop=raphael-marker-endblock33-obj468, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=967, type=DOM-API, prop=raphael-marker-endblock33-obj469, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=968, type=DOM-API, prop=raphael-marker-endblock33-obj470, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=969, type=DOM-API, prop=raphael-marker-endblock33-obj472, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=970, type=DOM-API, prop=raphael-marker-endblock55-obj496, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=971, type=DOM-API, prop=raphael-marker-endblock55-obj502, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=972, type=DOM-API, prop=raphael-marker-endopen77-obj505, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1009, type=DOM-API, prop=raphael-marker-endblock33-obj514, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1011, type=DOM-API, prop=raphael-marker-endblock33-obj515, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1013, type=DOM-API, prop=raphael-marker-endblock33-obj516, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1017, type=DOM-API, prop=raphael-marker-endblock33-obj514, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1018, type=DOM-API, prop=raphael-marker-endblock33-obj515, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1019, type=DOM-API, prop=raphael-marker-endblock33-obj516, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1022, type=DOM-API, prop=raphael-marker-endblock33-obj518, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1024, type=DOM-API, prop=raphael-marker-endblock33-obj518, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1040, type=DOM-API, prop=raphael-marker-endblock55-obj542, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1042, type=DOM-API, prop=raphael-marker-endblock55-obj542, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1046, type=DOM-API, prop=raphael-marker-endblock55-obj548, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1048, type=DOM-API, prop=raphael-marker-endblock55-obj548, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1051, type=DOM-API, prop=raphael-marker-endopen77-obj551, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1054, type=DOM-API, prop=raphael-marker-endopen77-obj551, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=1082, type=DOM-API, prop=editormd-link-dialog, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1085, type=DOM-API, prop=editormd-dialog-1712345098236, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1086, type=DOM-API, prop=html,body, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1087, type=DOM-API, prop=html,body, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1088, type=DOM-API, prop=editormd-mask, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1098, type=DOM-API, prop=editormd-dialog-footer, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1112, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6831 and loc.getEndColumn() >= 6831
        ) or 
        (   // id=1182, type=DOM-API, prop=sizzle-1712345066568, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1183, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-url], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1184, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-url], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1186, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-title], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1187, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-title], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1194, type=DOM-API, prop=raphael-marker-endblock33-obj514, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1195, type=DOM-API, prop=raphael-marker-endblock33-obj515, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1196, type=DOM-API, prop=raphael-marker-endblock33-obj516, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1197, type=DOM-API, prop=raphael-marker-endblock33-obj518, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1198, type=DOM-API, prop=raphael-marker-endblock55-obj542, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1199, type=DOM-API, prop=raphael-marker-endblock55-obj548, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1200, type=DOM-API, prop=raphael-marker-endopen77-obj551, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1237, type=DOM-API, prop=raphael-marker-endblock33-obj560, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1239, type=DOM-API, prop=raphael-marker-endblock33-obj561, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1241, type=DOM-API, prop=raphael-marker-endblock33-obj562, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1245, type=DOM-API, prop=raphael-marker-endblock33-obj560, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1246, type=DOM-API, prop=raphael-marker-endblock33-obj561, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1247, type=DOM-API, prop=raphael-marker-endblock33-obj562, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1250, type=DOM-API, prop=raphael-marker-endblock33-obj564, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1252, type=DOM-API, prop=raphael-marker-endblock33-obj564, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1268, type=DOM-API, prop=raphael-marker-endblock55-obj588, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1270, type=DOM-API, prop=raphael-marker-endblock55-obj588, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1274, type=DOM-API, prop=raphael-marker-endblock55-obj594, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1276, type=DOM-API, prop=raphael-marker-endblock55-obj594, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1279, type=DOM-API, prop=raphael-marker-endopen77-obj597, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1282, type=DOM-API, prop=raphael-marker-endopen77-obj597, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=1321, type=DOM-API, prop=editormd-reference-link-dialog, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1344, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-name], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1345, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-name], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1347, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-url-id], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1348, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-url-id], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1537, type=DOM-API, prop=raphael-marker-endblock33-obj560, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1538, type=DOM-API, prop=raphael-marker-endblock33-obj561, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1539, type=DOM-API, prop=raphael-marker-endblock33-obj562, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1540, type=DOM-API, prop=raphael-marker-endblock33-obj564, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1541, type=DOM-API, prop=raphael-marker-endblock55-obj588, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1542, type=DOM-API, prop=raphael-marker-endblock55-obj594, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1543, type=DOM-API, prop=raphael-marker-endopen77-obj597, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1580, type=DOM-API, prop=raphael-marker-endblock33-obj606, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1582, type=DOM-API, prop=raphael-marker-endblock33-obj607, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1584, type=DOM-API, prop=raphael-marker-endblock33-obj608, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1588, type=DOM-API, prop=raphael-marker-endblock33-obj606, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1589, type=DOM-API, prop=raphael-marker-endblock33-obj607, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1590, type=DOM-API, prop=raphael-marker-endblock33-obj608, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1593, type=DOM-API, prop=raphael-marker-endblock33-obj610, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1595, type=DOM-API, prop=raphael-marker-endblock33-obj610, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1611, type=DOM-API, prop=raphael-marker-endblock55-obj634, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1613, type=DOM-API, prop=raphael-marker-endblock55-obj634, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1617, type=DOM-API, prop=raphael-marker-endblock55-obj640, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1619, type=DOM-API, prop=raphael-marker-endblock55-obj640, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1622, type=DOM-API, prop=raphael-marker-endopen77-obj643, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1625, type=DOM-API, prop=raphael-marker-endopen77-obj643, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=1670, type=DOM-API, prop=raphael-marker-endblock33-obj606, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1671, type=DOM-API, prop=raphael-marker-endblock33-obj607, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1672, type=DOM-API, prop=raphael-marker-endblock33-obj608, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1673, type=DOM-API, prop=raphael-marker-endblock33-obj610, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1674, type=DOM-API, prop=raphael-marker-endblock55-obj634, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1675, type=DOM-API, prop=raphael-marker-endblock55-obj640, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1676, type=DOM-API, prop=raphael-marker-endopen77-obj643, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=1726, type=DOM-API, prop=raphael-marker-endblock33-obj652, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1728, type=DOM-API, prop=raphael-marker-endblock33-obj653, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1730, type=DOM-API, prop=raphael-marker-endblock33-obj654, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1734, type=DOM-API, prop=raphael-marker-endblock33-obj652, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1735, type=DOM-API, prop=raphael-marker-endblock33-obj653, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1736, type=DOM-API, prop=raphael-marker-endblock33-obj654, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1739, type=DOM-API, prop=raphael-marker-endblock33-obj656, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1741, type=DOM-API, prop=raphael-marker-endblock33-obj656, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1757, type=DOM-API, prop=raphael-marker-endblock55-obj680, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1759, type=DOM-API, prop=raphael-marker-endblock55-obj680, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1763, type=DOM-API, prop=raphael-marker-endblock55-obj686, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1765, type=DOM-API, prop=raphael-marker-endblock55-obj686, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=1768, type=DOM-API, prop=raphael-marker-endopen77-obj689, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=1771, type=DOM-API, prop=raphael-marker-endopen77-obj689, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=1781, type=DOM-API, prop=editormd-preformatted-text-dialog, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1782, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 19200 and loc.getEndColumn() >= 19200
        ) or 
        (   // id=1803, type=DOM-API, prop=textarea, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6831 and loc.getEndColumn() >= 6831
        ) or 
        (   // id=1804, type=DOM-API, prop=CodeMirror, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1869, type=DOM-API, prop=editormd-menu, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1872, type=DOM-API, prop=[id='sizzle-1712345066568'] [title="Lowercase"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1873, type=DOM-API, prop=[id='sizzle-1712345066568'] [title="Lowercase"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1875, type=DOM-API, prop=[id='sizzle-1712345066568'] [title="ucwords"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1876, type=DOM-API, prop=[id='sizzle-1712345066568'] [title="ucwords"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1878, type=DOM-API, prop=[id='sizzle-1712345066568'] .editormd-menu > li > a, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1879, type=DOM-API, prop=[id='sizzle-1712345066568'] .editormd-menu > li > a, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=1885, type=DOM-API, prop=editormd-table-dialog, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1924, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 20618 and loc.getEndColumn() >= 20618
        ) or 
        (   // id=1944, type=DOM-API, prop=fa-btns, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=1960, type=DOM-API, prop=editormd-table-dialog-radio0, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/en.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1961, type=DOM-API, prop=editormd-table-dialog-radio1, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/en.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1962, type=DOM-API, prop=editormd-table-dialog-radio2, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/en.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1963, type=DOM-API, prop=editormd-table-dialog-radio3, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/en.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1986, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 8576 and loc.getEndColumn() >= 8576
        ) or 
        (   // id=2031, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-rows], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2032, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-rows], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2034, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-cols], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2035, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-cols], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2037, type=DOM-API, prop=[id='sizzle-1712345066568'] [name="table-align"]:checked, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2038, type=DOM-API, prop=[id='sizzle-1712345066568'] [name="table-align"]:checked, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2045, type=DOM-API, prop=raphael-marker-endblock33-obj652, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2046, type=DOM-API, prop=raphael-marker-endblock33-obj653, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2047, type=DOM-API, prop=raphael-marker-endblock33-obj654, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2048, type=DOM-API, prop=raphael-marker-endblock33-obj656, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2049, type=DOM-API, prop=raphael-marker-endblock55-obj680, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2050, type=DOM-API, prop=raphael-marker-endblock55-obj686, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2051, type=DOM-API, prop=raphael-marker-endopen77-obj689, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2077, type=DOM-API, prop=editormd-table-dialog-radio0, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 3770 and loc.getEndColumn() >= 3770
        ) or 
        (   // id=2078, type=DOM-API, prop=editormd-table-dialog-radio1, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 3770 and loc.getEndColumn() >= 3770
        ) or 
        (   // id=2079, type=DOM-API, prop=editormd-table-dialog-radio2, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 3770 and loc.getEndColumn() >= 3770
        ) or 
        (   // id=2080, type=DOM-API, prop=editormd-table-dialog-radio3, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 3770 and loc.getEndColumn() >= 3770
        ) or 
        (   // id=2097, type=DOM-API, prop=raphael-marker-endblock33-obj698, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2099, type=DOM-API, prop=raphael-marker-endblock33-obj699, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2101, type=DOM-API, prop=raphael-marker-endblock33-obj700, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2105, type=DOM-API, prop=raphael-marker-endblock33-obj698, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2106, type=DOM-API, prop=raphael-marker-endblock33-obj699, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2107, type=DOM-API, prop=raphael-marker-endblock33-obj700, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2110, type=DOM-API, prop=raphael-marker-endblock33-obj702, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2112, type=DOM-API, prop=raphael-marker-endblock33-obj702, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2128, type=DOM-API, prop=raphael-marker-endblock55-obj726, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2130, type=DOM-API, prop=raphael-marker-endblock55-obj726, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2134, type=DOM-API, prop=raphael-marker-endblock55-obj732, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2136, type=DOM-API, prop=raphael-marker-endblock55-obj732, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2139, type=DOM-API, prop=raphael-marker-endopen77-obj735, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2142, type=DOM-API, prop=raphael-marker-endopen77-obj735, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=2194, type=DOM-API, prop=raphael-marker-endblock33-obj698, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2195, type=DOM-API, prop=raphael-marker-endblock33-obj699, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2196, type=DOM-API, prop=raphael-marker-endblock33-obj700, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2197, type=DOM-API, prop=raphael-marker-endblock33-obj702, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2198, type=DOM-API, prop=raphael-marker-endblock55-obj726, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2199, type=DOM-API, prop=raphael-marker-endblock55-obj732, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2200, type=DOM-API, prop=raphael-marker-endopen77-obj735, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2237, type=DOM-API, prop=raphael-marker-endblock33-obj744, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2239, type=DOM-API, prop=raphael-marker-endblock33-obj745, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2241, type=DOM-API, prop=raphael-marker-endblock33-obj746, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2245, type=DOM-API, prop=raphael-marker-endblock33-obj744, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2246, type=DOM-API, prop=raphael-marker-endblock33-obj745, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2247, type=DOM-API, prop=raphael-marker-endblock33-obj746, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2250, type=DOM-API, prop=raphael-marker-endblock33-obj748, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2252, type=DOM-API, prop=raphael-marker-endblock33-obj748, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2268, type=DOM-API, prop=raphael-marker-endblock55-obj772, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2270, type=DOM-API, prop=raphael-marker-endblock55-obj772, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2274, type=DOM-API, prop=raphael-marker-endblock55-obj778, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2276, type=DOM-API, prop=raphael-marker-endblock55-obj778, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2279, type=DOM-API, prop=raphael-marker-endopen77-obj781, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2282, type=DOM-API, prop=raphael-marker-endopen77-obj781, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=2370, type=DOM-API, prop=raphael-marker-endblock33-obj744, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2371, type=DOM-API, prop=raphael-marker-endblock33-obj745, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2372, type=DOM-API, prop=raphael-marker-endblock33-obj746, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2373, type=DOM-API, prop=raphael-marker-endblock33-obj748, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2374, type=DOM-API, prop=raphael-marker-endblock55-obj772, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2375, type=DOM-API, prop=raphael-marker-endblock55-obj778, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2376, type=DOM-API, prop=raphael-marker-endopen77-obj781, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2413, type=DOM-API, prop=raphael-marker-endblock33-obj790, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2415, type=DOM-API, prop=raphael-marker-endblock33-obj791, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2417, type=DOM-API, prop=raphael-marker-endblock33-obj792, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2421, type=DOM-API, prop=raphael-marker-endblock33-obj790, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2422, type=DOM-API, prop=raphael-marker-endblock33-obj791, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2423, type=DOM-API, prop=raphael-marker-endblock33-obj792, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2426, type=DOM-API, prop=raphael-marker-endblock33-obj794, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2428, type=DOM-API, prop=raphael-marker-endblock33-obj794, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2444, type=DOM-API, prop=raphael-marker-endblock55-obj818, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2446, type=DOM-API, prop=raphael-marker-endblock55-obj818, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2450, type=DOM-API, prop=raphael-marker-endblock55-obj824, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2452, type=DOM-API, prop=raphael-marker-endblock55-obj824, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2455, type=DOM-API, prop=raphael-marker-endopen77-obj827, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2458, type=DOM-API, prop=raphael-marker-endopen77-obj827, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=2578, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/en.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=2632, type=DOM-API, prop=CodeMirror, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/codemirror/codemirror.min.js") and
            loc.getStartLine() = 53 and loc.getEndLine() = 53 and
            loc.getStartColumn() <= 244 and loc.getEndColumn() >= 244
        ) or 
        (   // id=2635, type=DOM-API, prop=editormd-dialog-html-entities-dialog, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=2656, type=DOM-API, prop=editormd-grid-table, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=2657, type=DOM-API, prop=editormd-dialog-mask, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=2692, type=DOM-API, prop=editormd-html-entity-btn, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=2740, type=DOM-API, prop=[id='sizzle-1712345066568'] .fa[name=preview], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2741, type=DOM-API, prop=[id='sizzle-1712345066568'] .fa[name=preview], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2742, type=DOM-API, prop=editormd-preview-close-btn, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=2785, type=DOM-API, prop=editormd-goto-line-dialog, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=2859, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-line-number], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2860, type=DOM-API, prop=[id='sizzle-1712345066568'] [data-line-number], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7275 and loc.getEndColumn() >= 7275
        ) or 
        (   // id=2885, type=DOM-API, prop=raphael-marker-endblock33-obj790, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2886, type=DOM-API, prop=raphael-marker-endblock33-obj791, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2887, type=DOM-API, prop=raphael-marker-endblock33-obj792, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2888, type=DOM-API, prop=raphael-marker-endblock33-obj794, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2889, type=DOM-API, prop=raphael-marker-endblock55-obj818, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2890, type=DOM-API, prop=raphael-marker-endblock55-obj824, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2891, type=DOM-API, prop=raphael-marker-endopen77-obj827, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=2928, type=DOM-API, prop=raphael-marker-endblock33-obj836, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2930, type=DOM-API, prop=raphael-marker-endblock33-obj837, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2932, type=DOM-API, prop=raphael-marker-endblock33-obj838, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2936, type=DOM-API, prop=raphael-marker-endblock33-obj836, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2937, type=DOM-API, prop=raphael-marker-endblock33-obj837, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2938, type=DOM-API, prop=raphael-marker-endblock33-obj838, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2941, type=DOM-API, prop=raphael-marker-endblock33-obj840, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2943, type=DOM-API, prop=raphael-marker-endblock33-obj840, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2959, type=DOM-API, prop=raphael-marker-endblock55-obj864, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2961, type=DOM-API, prop=raphael-marker-endblock55-obj864, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2965, type=DOM-API, prop=raphael-marker-endblock55-obj870, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2967, type=DOM-API, prop=raphael-marker-endblock55-obj870, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=2970, type=DOM-API, prop=raphael-marker-endopen77-obj873, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=2973, type=DOM-API, prop=raphael-marker-endopen77-obj873, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=3181, type=DOM-API, prop=raphael-marker-endblock33-obj836, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3182, type=DOM-API, prop=raphael-marker-endblock33-obj837, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3183, type=DOM-API, prop=raphael-marker-endblock33-obj838, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3184, type=DOM-API, prop=raphael-marker-endblock33-obj840, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3185, type=DOM-API, prop=raphael-marker-endblock55-obj864, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3186, type=DOM-API, prop=raphael-marker-endblock55-obj870, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3187, type=DOM-API, prop=raphael-marker-endopen77-obj873, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3249, type=DOM-API, prop=raphael-marker-endblock33-obj882, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3251, type=DOM-API, prop=raphael-marker-endblock33-obj883, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3253, type=DOM-API, prop=raphael-marker-endblock33-obj884, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3257, type=DOM-API, prop=raphael-marker-endblock33-obj882, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3258, type=DOM-API, prop=raphael-marker-endblock33-obj883, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3259, type=DOM-API, prop=raphael-marker-endblock33-obj884, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3262, type=DOM-API, prop=raphael-marker-endblock33-obj886, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3264, type=DOM-API, prop=raphael-marker-endblock33-obj886, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3280, type=DOM-API, prop=raphael-marker-endblock55-obj910, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3282, type=DOM-API, prop=raphael-marker-endblock55-obj910, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3286, type=DOM-API, prop=raphael-marker-endblock55-obj916, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3288, type=DOM-API, prop=raphael-marker-endblock55-obj916, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3291, type=DOM-API, prop=raphael-marker-endopen77-obj919, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3294, type=DOM-API, prop=raphael-marker-endopen77-obj919, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=3344, type=DOM-API, prop=raphael-marker-endblock33-obj882, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3345, type=DOM-API, prop=raphael-marker-endblock33-obj883, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3346, type=DOM-API, prop=raphael-marker-endblock33-obj884, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3347, type=DOM-API, prop=raphael-marker-endblock33-obj886, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3348, type=DOM-API, prop=raphael-marker-endblock55-obj910, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3349, type=DOM-API, prop=raphael-marker-endblock55-obj916, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3350, type=DOM-API, prop=raphael-marker-endopen77-obj919, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3387, type=DOM-API, prop=raphael-marker-endblock33-obj928, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3389, type=DOM-API, prop=raphael-marker-endblock33-obj929, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3391, type=DOM-API, prop=raphael-marker-endblock33-obj930, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3395, type=DOM-API, prop=raphael-marker-endblock33-obj928, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3396, type=DOM-API, prop=raphael-marker-endblock33-obj929, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3397, type=DOM-API, prop=raphael-marker-endblock33-obj930, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3400, type=DOM-API, prop=raphael-marker-endblock33-obj932, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3402, type=DOM-API, prop=raphael-marker-endblock33-obj932, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3418, type=DOM-API, prop=raphael-marker-endblock55-obj956, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3420, type=DOM-API, prop=raphael-marker-endblock55-obj956, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3424, type=DOM-API, prop=raphael-marker-endblock55-obj962, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3426, type=DOM-API, prop=raphael-marker-endblock55-obj962, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3429, type=DOM-API, prop=raphael-marker-endopen77-obj965, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3432, type=DOM-API, prop=raphael-marker-endopen77-obj965, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=3491, type=DOM-API, prop=raphael-marker-endblock33-obj928, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3492, type=DOM-API, prop=raphael-marker-endblock33-obj929, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3493, type=DOM-API, prop=raphael-marker-endblock33-obj930, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3494, type=DOM-API, prop=raphael-marker-endblock33-obj932, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3495, type=DOM-API, prop=raphael-marker-endblock55-obj956, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3496, type=DOM-API, prop=raphael-marker-endblock55-obj962, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3497, type=DOM-API, prop=raphael-marker-endopen77-obj965, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3534, type=DOM-API, prop=raphael-marker-endblock33-obj974, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3536, type=DOM-API, prop=raphael-marker-endblock33-obj975, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3538, type=DOM-API, prop=raphael-marker-endblock33-obj976, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3542, type=DOM-API, prop=raphael-marker-endblock33-obj974, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3543, type=DOM-API, prop=raphael-marker-endblock33-obj975, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3544, type=DOM-API, prop=raphael-marker-endblock33-obj976, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3547, type=DOM-API, prop=raphael-marker-endblock33-obj978, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3549, type=DOM-API, prop=raphael-marker-endblock33-obj978, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3565, type=DOM-API, prop=raphael-marker-endblock55-obj1002, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3567, type=DOM-API, prop=raphael-marker-endblock55-obj1002, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3571, type=DOM-API, prop=raphael-marker-endblock55-obj1008, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3573, type=DOM-API, prop=raphael-marker-endblock55-obj1008, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3576, type=DOM-API, prop=raphael-marker-endopen77-obj1011, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3579, type=DOM-API, prop=raphael-marker-endopen77-obj1011, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=3666, type=DOM-API, prop=raphael-marker-endblock33-obj974, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3667, type=DOM-API, prop=raphael-marker-endblock33-obj975, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3668, type=DOM-API, prop=raphael-marker-endblock33-obj976, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3669, type=DOM-API, prop=raphael-marker-endblock33-obj978, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3670, type=DOM-API, prop=raphael-marker-endblock55-obj1002, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3671, type=DOM-API, prop=raphael-marker-endblock55-obj1008, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3672, type=DOM-API, prop=raphael-marker-endopen77-obj1011, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3709, type=DOM-API, prop=raphael-marker-endblock33-obj1020, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3711, type=DOM-API, prop=raphael-marker-endblock33-obj1021, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3713, type=DOM-API, prop=raphael-marker-endblock33-obj1022, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3717, type=DOM-API, prop=raphael-marker-endblock33-obj1020, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3718, type=DOM-API, prop=raphael-marker-endblock33-obj1021, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3719, type=DOM-API, prop=raphael-marker-endblock33-obj1022, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3722, type=DOM-API, prop=raphael-marker-endblock33-obj1024, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3724, type=DOM-API, prop=raphael-marker-endblock33-obj1024, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3740, type=DOM-API, prop=raphael-marker-endblock55-obj1048, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3742, type=DOM-API, prop=raphael-marker-endblock55-obj1048, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3746, type=DOM-API, prop=raphael-marker-endblock55-obj1054, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3748, type=DOM-API, prop=raphael-marker-endblock55-obj1054, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3751, type=DOM-API, prop=raphael-marker-endopen77-obj1057, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3754, type=DOM-API, prop=raphael-marker-endopen77-obj1057, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=3859, type=DOM-API, prop=raphael-marker-endblock33-obj1020, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3860, type=DOM-API, prop=raphael-marker-endblock33-obj1021, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3861, type=DOM-API, prop=raphael-marker-endblock33-obj1022, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3862, type=DOM-API, prop=raphael-marker-endblock33-obj1024, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3863, type=DOM-API, prop=raphael-marker-endblock55-obj1048, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3864, type=DOM-API, prop=raphael-marker-endblock55-obj1054, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3865, type=DOM-API, prop=raphael-marker-endopen77-obj1057, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=3911, type=DOM-API, prop=raphael-marker-endblock33-obj1066, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3913, type=DOM-API, prop=raphael-marker-endblock33-obj1067, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3915, type=DOM-API, prop=raphael-marker-endblock33-obj1068, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3919, type=DOM-API, prop=raphael-marker-endblock33-obj1066, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3920, type=DOM-API, prop=raphael-marker-endblock33-obj1067, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3921, type=DOM-API, prop=raphael-marker-endblock33-obj1068, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3924, type=DOM-API, prop=raphael-marker-endblock33-obj1070, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3926, type=DOM-API, prop=raphael-marker-endblock33-obj1070, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3942, type=DOM-API, prop=raphael-marker-endblock55-obj1094, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3944, type=DOM-API, prop=raphael-marker-endblock55-obj1094, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3948, type=DOM-API, prop=raphael-marker-endblock55-obj1100, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3950, type=DOM-API, prop=raphael-marker-endblock55-obj1100, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=3953, type=DOM-API, prop=raphael-marker-endopen77-obj1103, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=3956, type=DOM-API, prop=raphael-marker-endopen77-obj1103, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=4041, type=DOM-API, prop=raphael-marker-endblock33-obj1066, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4042, type=DOM-API, prop=raphael-marker-endblock33-obj1067, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4043, type=DOM-API, prop=raphael-marker-endblock33-obj1068, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4044, type=DOM-API, prop=raphael-marker-endblock33-obj1070, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4045, type=DOM-API, prop=raphael-marker-endblock55-obj1094, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4046, type=DOM-API, prop=raphael-marker-endblock55-obj1100, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4047, type=DOM-API, prop=raphael-marker-endopen77-obj1103, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4122, type=DOM-API, prop=raphael-marker-endblock33-obj1112, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4124, type=DOM-API, prop=raphael-marker-endblock33-obj1113, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4126, type=DOM-API, prop=raphael-marker-endblock33-obj1114, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4130, type=DOM-API, prop=raphael-marker-endblock33-obj1112, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4131, type=DOM-API, prop=raphael-marker-endblock33-obj1113, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4132, type=DOM-API, prop=raphael-marker-endblock33-obj1114, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4135, type=DOM-API, prop=raphael-marker-endblock33-obj1116, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4137, type=DOM-API, prop=raphael-marker-endblock33-obj1116, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4153, type=DOM-API, prop=raphael-marker-endblock55-obj1140, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4155, type=DOM-API, prop=raphael-marker-endblock55-obj1140, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4159, type=DOM-API, prop=raphael-marker-endblock55-obj1146, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4161, type=DOM-API, prop=raphael-marker-endblock55-obj1146, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4164, type=DOM-API, prop=raphael-marker-endopen77-obj1149, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4167, type=DOM-API, prop=raphael-marker-endopen77-obj1149, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=4251, type=DOM-API, prop=raphael-marker-endblock33-obj1112, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4252, type=DOM-API, prop=raphael-marker-endblock33-obj1113, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4253, type=DOM-API, prop=raphael-marker-endblock33-obj1114, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4254, type=DOM-API, prop=raphael-marker-endblock33-obj1116, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4255, type=DOM-API, prop=raphael-marker-endblock55-obj1140, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4256, type=DOM-API, prop=raphael-marker-endblock55-obj1146, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4257, type=DOM-API, prop=raphael-marker-endopen77-obj1149, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4336, type=DOM-API, prop=raphael-marker-endblock33-obj1158, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4338, type=DOM-API, prop=raphael-marker-endblock33-obj1159, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4340, type=DOM-API, prop=raphael-marker-endblock33-obj1160, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4344, type=DOM-API, prop=raphael-marker-endblock33-obj1158, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4345, type=DOM-API, prop=raphael-marker-endblock33-obj1159, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4346, type=DOM-API, prop=raphael-marker-endblock33-obj1160, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4349, type=DOM-API, prop=raphael-marker-endblock33-obj1162, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4351, type=DOM-API, prop=raphael-marker-endblock33-obj1162, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4367, type=DOM-API, prop=raphael-marker-endblock55-obj1186, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4369, type=DOM-API, prop=raphael-marker-endblock55-obj1186, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4373, type=DOM-API, prop=raphael-marker-endblock55-obj1192, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4375, type=DOM-API, prop=raphael-marker-endblock55-obj1192, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4378, type=DOM-API, prop=raphael-marker-endopen77-obj1195, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4381, type=DOM-API, prop=raphael-marker-endopen77-obj1195, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=4434, type=DOM-API, prop=raphael-marker-endblock33-obj1158, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4435, type=DOM-API, prop=raphael-marker-endblock33-obj1159, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4436, type=DOM-API, prop=raphael-marker-endblock33-obj1160, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4437, type=DOM-API, prop=raphael-marker-endblock33-obj1162, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4438, type=DOM-API, prop=raphael-marker-endblock55-obj1186, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4439, type=DOM-API, prop=raphael-marker-endblock55-obj1192, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4440, type=DOM-API, prop=raphael-marker-endopen77-obj1195, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=4522, type=DOM-API, prop=raphael-marker-endblock33-obj1204, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4524, type=DOM-API, prop=raphael-marker-endblock33-obj1205, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4526, type=DOM-API, prop=raphael-marker-endblock33-obj1206, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4530, type=DOM-API, prop=raphael-marker-endblock33-obj1204, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4531, type=DOM-API, prop=raphael-marker-endblock33-obj1205, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4532, type=DOM-API, prop=raphael-marker-endblock33-obj1206, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4535, type=DOM-API, prop=raphael-marker-endblock33-obj1208, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4537, type=DOM-API, prop=raphael-marker-endblock33-obj1208, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4553, type=DOM-API, prop=raphael-marker-endblock55-obj1232, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4555, type=DOM-API, prop=raphael-marker-endblock55-obj1232, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4559, type=DOM-API, prop=raphael-marker-endblock55-obj1238, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4561, type=DOM-API, prop=raphael-marker-endblock55-obj1238, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=4564, type=DOM-API, prop=raphael-marker-endopen77-obj1241, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=4567, type=DOM-API, prop=raphael-marker-endopen77-obj1241, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
        ) or 
        (   // id=5278, type=DOM-API, prop=raphael-marker-endblock33-obj1204, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=5279, type=DOM-API, prop=raphael-marker-endblock33-obj1205, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=5280, type=DOM-API, prop=raphael-marker-endblock33-obj1206, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=5281, type=DOM-API, prop=raphael-marker-endblock33-obj1208, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=5282, type=DOM-API, prop=raphael-marker-endblock55-obj1232, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=5283, type=DOM-API, prop=raphael-marker-endblock55-obj1238, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=5284, type=DOM-API, prop=raphael-marker-endopen77-obj1241, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 22003 and loc.getEndColumn() >= 22003
        ) or 
        (   // id=5313, type=DOM-API, prop=editormd-dialog-close, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6941 and loc.getEndColumn() >= 6941
        ) or 
        (   // id=5347, type=DOM-API, prop=raphael-marker-endblock33-obj1250, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=5349, type=DOM-API, prop=raphael-marker-endblock33-obj1251, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=5351, type=DOM-API, prop=raphael-marker-endblock33-obj1252, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=5355, type=DOM-API, prop=raphael-marker-endblock33-obj1250, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=5356, type=DOM-API, prop=raphael-marker-endblock33-obj1251, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=5357, type=DOM-API, prop=raphael-marker-endblock33-obj1252, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=5360, type=DOM-API, prop=raphael-marker-endblock33-obj1254, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=5362, type=DOM-API, prop=raphael-marker-endblock33-obj1254, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=5378, type=DOM-API, prop=raphael-marker-endblock55-obj1278, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=5380, type=DOM-API, prop=raphael-marker-endblock55-obj1278, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=5384, type=DOM-API, prop=raphael-marker-endblock55-obj1284, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=5386, type=DOM-API, prop=raphael-marker-endblock55-obj1284, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 3778 and loc.getEndColumn() >= 3778
        ) or 
        (   // id=5389, type=DOM-API, prop=raphael-marker-endopen77-obj1287, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/lib/raphael.min.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 26600 and loc.getEndColumn() >= 26600
        ) or 
        (   // id=5392, type=DOM-API, prop=raphael-marker-endopen77-obj1287, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-15-24/pandao.github.io/3c46654cd9/source/pandao.github.io/editor.md/examples/js/jquery.min.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 24688 and loc.getEndColumn() >= 24688
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

DebuggingConfig() { this = "DOM-Clobbering-pandao.github.io-3c46654cd9" }
    
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
