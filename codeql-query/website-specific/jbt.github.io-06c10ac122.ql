/**
* @name DOM-Clobbering-jbt.github.io-06c10ac122
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
        (   // id=79, type=WIN-TYPE-1, prop=attachEvent 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16376 and loc.getEndColumn() >= 16376
        ) or 
        (   // id=108, type=WIN-TYPE-1, prop=previousActiveElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10507 and loc.getEndColumn() >= 10507
        ) or 
        (   // id=169, type=WIN-TYPE-1, prop=url 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 195 and loc.getEndLine() = 195 and
            loc.getStartColumn() <= 13 and loc.getEndColumn() >= 13
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
        (   // id=3, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/codemirror/lib/codemirror.js") and
            loc.getStartLine() = 8257 and loc.getEndLine() = 8257 and
            loc.getStartColumn() <= 18 and loc.getEndColumn() >= 18
        ) or 
        (   // id=4, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/codemirror/lib/codemirror.js") and
            loc.getStartLine() = 8258 and loc.getEndLine() = 8258 and
            loc.getStartColumn() <= 27 and loc.getEndColumn() >= 27
        ) or 
        (   // id=18, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/codemirror/lib/codemirror.js") and
            loc.getStartLine() = 8222 and loc.getEndLine() = 8222 and
            loc.getStartColumn() <= 41 and loc.getEndColumn() >= 41
        ) or 
        (   // id=39, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 952 and loc.getEndColumn() >= 952
        ) or 
        (   // id=44, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 9938 and loc.getEndColumn() >= 9938
        ) or 
        (   // id=107, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10509 and loc.getEndColumn() >= 10509
        ) or 
        (   // id=162, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3091 and loc.getEndColumn() >= 3091
        ) or 
        (   // id=299, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 299 and loc.getEndLine() = 299 and
            loc.getStartColumn() <= 13 and loc.getEndColumn() >= 13
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
        (   // id=2, type=DOM-API, prop=fileInput, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.html") and
            loc.getStartLine() = 43 and loc.getEndLine() = 43 and
            loc.getStartColumn() <= 139 and loc.getEndColumn() >= 139
        ) or 
        (   // id=5, type=DOM-API, prop=CodeMirror, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/codemirror/lib/codemirror.js") and
            loc.getStartLine() = 8258 and loc.getEndLine() = 8258 and
            loc.getStartColumn() <= 33 and loc.getEndColumn() >= 33
        ) or 
        (   // id=10, type=DOM-API, prop=out, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 83 and loc.getEndLine() = 83 and
            loc.getStartColumn() <= 24 and loc.getEndColumn() >= 24
        ) or 
        (   // id=12, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 91 and loc.getEndLine() = 91 and
            loc.getStartColumn() <= 22 and loc.getEndColumn() >= 22
        ) or 
        (   // id=13, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 94 and loc.getEndLine() = 94 and
            loc.getStartColumn() <= 22 and loc.getEndColumn() >= 22
        ) or 
        (   // id=15, type=DOM-API, prop=h1, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 37 and loc.getEndLine() = 37 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=16, type=DOM-API, prop=h1, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 37 and loc.getEndLine() = 37 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=32, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=33, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=41, type=DOM-API, prop=.sweet-alert, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10101 and loc.getEndColumn() >= 10101
        ) or 
        (   // id=42, type=DOM-API, prop=.sweet-alert, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10101 and loc.getEndColumn() >= 10101
        ) or 
        (   // id=52, type=DOM-API, prop=input, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10178 and loc.getEndColumn() >= 10178
        ) or 
        (   // id=53, type=DOM-API, prop=input, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10178 and loc.getEndColumn() >= 10178
        ) or 
        (   // id=54, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10965 and loc.getEndColumn() >= 10965
        ) or 
        (   // id=58, type=DOM-API, prop=.sa-input-error, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11086 and loc.getEndColumn() >= 11086
        ) or 
        (   // id=59, type=DOM-API, prop=.sa-input-error, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11086 and loc.getEndColumn() >= 11086
        ) or 
        (   // id=60, type=DOM-API, prop=.sa-error-container, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11151 and loc.getEndColumn() >= 11151
        ) or 
        (   // id=61, type=DOM-API, prop=.sa-error-container, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11151 and loc.getEndColumn() >= 11151
        ) or 
        (   // id=65, type=DOM-API, prop=h2, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13099 and loc.getEndColumn() >= 13099
        ) or 
        (   // id=66, type=DOM-API, prop=h2, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13099 and loc.getEndColumn() >= 13099
        ) or 
        (   // id=67, type=DOM-API, prop=p, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13123 and loc.getEndColumn() >= 13123
        ) or 
        (   // id=68, type=DOM-API, prop=p, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13123 and loc.getEndColumn() >= 13123
        ) or 
        (   // id=69, type=DOM-API, prop=button.cancel, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13146 and loc.getEndColumn() >= 13146
        ) or 
        (   // id=70, type=DOM-API, prop=button.cancel, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13146 and loc.getEndColumn() >= 13146
        ) or 
        (   // id=71, type=DOM-API, prop=button.confirm, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13181 and loc.getEndColumn() >= 13181
        ) or 
        (   // id=72, type=DOM-API, prop=button.confirm, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13181 and loc.getEndColumn() >= 13181
        ) or 
        (   // id=77, type=DOM-API, prop=.sa-icon, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13593 and loc.getEndColumn() >= 13593
        ) or 
        (   // id=78, type=DOM-API, prop=.sa-icon, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13593 and loc.getEndColumn() >= 13593
        ) or 
        (   // id=80, type=DOM-API, prop=.sa-icon.sa-success, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13855 and loc.getEndColumn() >= 13855
        ) or 
        (   // id=81, type=DOM-API, prop=.sa-icon.sa-success, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13855 and loc.getEndColumn() >= 13855
        ) or 
        (   // id=87, type=DOM-API, prop=.sa-tip, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13988 and loc.getEndColumn() >= 13988
        ) or 
        (   // id=88, type=DOM-API, prop=.sa-tip, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13988 and loc.getEndColumn() >= 13988
        ) or 
        (   // id=89, type=DOM-API, prop=.sa-long, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 14047 and loc.getEndColumn() >= 14047
        ) or 
        (   // id=90, type=DOM-API, prop=.sa-long, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 14047 and loc.getEndColumn() >= 14047
        ) or 
        (   // id=105, type=DOM-API, prop=.sweet-overlay, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10231 and loc.getEndColumn() >= 10231
        ) or 
        (   // id=106, type=DOM-API, prop=.sweet-overlay, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10231 and loc.getEndColumn() >= 10231
        ) or 
        (   // id=109, type=DOM-API, prop=button.confirm, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10532 and loc.getEndColumn() >= 10532
        ) or 
        (   // id=110, type=DOM-API, prop=button.confirm, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10532 and loc.getEndColumn() >= 10532
        ) or 
        (   // id=114, type=DOM-API, prop=button, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1674 and loc.getEndColumn() >= 1674
        ) or 
        (   // id=115, type=DOM-API, prop=button, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1674 and loc.getEndColumn() >= 1674
        ) or 
        (   // id=122, type=DOM-API, prop=button.confirm, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3976 and loc.getEndColumn() >= 3976
        ) or 
        (   // id=123, type=DOM-API, prop=button.confirm, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3976 and loc.getEndColumn() >= 3976
        ) or 
        (   // id=124, type=DOM-API, prop=button.cancel, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4012 and loc.getEndColumn() >= 4012
        ) or 
        (   // id=125, type=DOM-API, prop=button.cancel, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4012 and loc.getEndColumn() >= 4012
        ) or 
        (   // id=126, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=146, type=DOM-API, prop=.sa-icon.sa-success, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2453 and loc.getEndColumn() >= 2453
        ) or 
        (   // id=147, type=DOM-API, prop=.sa-icon.sa-success, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2453 and loc.getEndColumn() >= 2453
        ) or 
        (   // id=148, type=DOM-API, prop=.sa-tip, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2533 and loc.getEndColumn() >= 2533
        ) or 
        (   // id=149, type=DOM-API, prop=.sa-tip, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2533 and loc.getEndColumn() >= 2533
        ) or 
        (   // id=150, type=DOM-API, prop=.sa-long, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2595 and loc.getEndColumn() >= 2595
        ) or 
        (   // id=151, type=DOM-API, prop=.sa-long, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2595 and loc.getEndColumn() >= 2595
        ) or 
        (   // id=152, type=DOM-API, prop=.sa-icon.sa-error, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2651 and loc.getEndColumn() >= 2651
        ) or 
        (   // id=153, type=DOM-API, prop=.sa-icon.sa-error, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2651 and loc.getEndColumn() >= 2651
        ) or 
        (   // id=154, type=DOM-API, prop=.sa-x-mark, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2738 and loc.getEndColumn() >= 2738
        ) or 
        (   // id=155, type=DOM-API, prop=.sa-x-mark, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2738 and loc.getEndColumn() >= 2738
        ) or 
        (   // id=156, type=DOM-API, prop=.sa-icon.sa-warning, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2790 and loc.getEndColumn() >= 2790
        ) or 
        (   // id=157, type=DOM-API, prop=.sa-icon.sa-warning, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2790 and loc.getEndColumn() >= 2790
        ) or 
        (   // id=158, type=DOM-API, prop=.sa-body, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2882 and loc.getEndColumn() >= 2882
        ) or 
        (   // id=159, type=DOM-API, prop=.sa-body, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2882 and loc.getEndColumn() >= 2882
        ) or 
        (   // id=160, type=DOM-API, prop=.sa-dot, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2943 and loc.getEndColumn() >= 2943
        ) or 
        (   // id=161, type=DOM-API, prop=.sa-dot, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2943 and loc.getEndColumn() >= 2943
        ) or 
        (   // id=167, type=DOM-API, prop=out, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 173 and loc.getEndLine() = 173 and
            loc.getStartColumn() <= 19 and loc.getEndColumn() >= 19
        ) or 
        (   // id=172, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/codemirror/lib/codemirror.js") and
            loc.getStartLine() = 1317 and loc.getEndLine() = 1317 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=173, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/codemirror/lib/codemirror.js") and
            loc.getStartLine() = 1317 and loc.getEndLine() = 1317 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=212, type=DOM-API, prop=.sa-icon.sa-warning, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13855 and loc.getEndColumn() >= 13855
        ) or 
        (   // id=213, type=DOM-API, prop=.sa-icon.sa-warning, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13855 and loc.getEndColumn() >= 13855
        ) or 
        (   // id=218, type=DOM-API, prop=.sa-body, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 14265 and loc.getEndColumn() >= 14265
        ) or 
        (   // id=219, type=DOM-API, prop=.sa-body, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 14265 and loc.getEndColumn() >= 14265
        ) or 
        (   // id=220, type=DOM-API, prop=.sa-dot, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 14323 and loc.getEndColumn() >= 14323
        ) or 
        (   // id=221, type=DOM-API, prop=.sa-dot, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 14323 and loc.getEndColumn() >= 14323
        ) or 
        (   // id=238, type=DOM-API, prop=button.confirm, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5543 and loc.getEndColumn() >= 5543
        ) or 
        (   // id=239, type=DOM-API, prop=button.confirm, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5543 and loc.getEndColumn() >= 5543
        ) or 
        (   // id=240, type=DOM-API, prop=button.cancel, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5579 and loc.getEndColumn() >= 5579
        ) or 
        (   // id=241, type=DOM-API, prop=button.cancel, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5579 and loc.getEndColumn() >= 5579
        ) or 
        (   // id=288, type=DOM-API, prop=toplevel, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 288 and loc.getEndLine() = 288 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=290, type=DOM-API, prop=out, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 293 and loc.getEndLine() = 293 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=292, type=DOM-API, prop=in, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 294 and loc.getEndLine() = 294 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=1076, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10566 and loc.getEndColumn() >= 10566
        ) or 
        (   // id=1077, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10566 and loc.getEndColumn() >= 10566
        ) or 
        (   // id=1148, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 303 and loc.getEndLine() = 303 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=1149, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 303 and loc.getEndLine() = 303 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=1150, type=DOM-API, prop=7ZTdbptAEIWvy1PsXRI1VZdfg+VYsmSiRMV2VJxGrWWhxTs4G68BwTomivIqveqT9UkK2KmxaprUlaoqCnAxoNn5zjBn1yUBOFE0W8SoC/5ieoxuUlnCmRxoKsZYUw2dNtFoRGKGIv8GJmKM8FhC79CcxE30mKiQgGo6avVIPFKV8eHZwLE/e7Zj9+z+0D1qo9EpScVFEsWQCAZpWSHN2XzFFmTaRN1zt+M4gyvP7ZzazmDw4fKiSIuTSETiLoYNLtelTyhqDUpFhRR0UtUymVjtYilwmEMo0spKjA2QUeuUZUA7SULuRnicy9sWXMqDuQ+UQoICBpzmNZS1mnUPTxUtsjuco2gZVlahQ8gmfEFZOP0p76iJ7h92IPOm7iWUXxUQNnLQIqQQsBBo+xgRzqZ5hOKIhQKSJjoMGT/ae9mD5P5iiYQsvQTSBRevznh1Rv1hofmB9RxL+JiA9Q8toZm+VWeJXItBX5YldowQZ41AV5VA0yg28W/SZCuQMZZzU2D8B4fB6+Rf3ORRcU8h+P71G0LZe1XJlmUxlagy6JgGWNp+RS3vS1/3OQtnsvHJPBv2nC67tVfiZXOZkDhvzitG5LEwiDy73XyDs9UhhOVNiPNQxbpMGxZefy04VRzgPXBvZaNKxNuh4hsWgKLXEeV9iKpSEssKgWJWam/gWkXHFlHZImrP/aGP89gJw3UwtYTV96fi8zAVhPPLcBKFlAkWhYRvtqp90VduzcZ5GnEiwP74oe96st4d9K5WMq+ihFO778qe7kQTws+L0BzCPC7zbdu1vPyxZX3WESJh/kLAkPgcyp4Uv+HrpGFs91SYBFS91iTa/9rToxPLBjR/16g0w6wblb7lC3PdlcNS8RebDfRJ7X809gI+ud1MxferE5UkicxSen0zk4qrRRCjJwfZAbpOICiCNvoB, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/index.js") and
            loc.getStartLine() = 303 and loc.getEndLine() = 303 and
            loc.getStartColumn() <= 26 and loc.getEndColumn() >= 26
        ) or 
        (   // id=1303, type=DOM-API, prop=button.confirm, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 9026 and loc.getEndColumn() >= 9026
        ) or 
        (   // id=1304, type=DOM-API, prop=button.confirm, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 9026 and loc.getEndColumn() >= 9026
        ) or 
        (   // id=1305, type=DOM-API, prop=button.cancel, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 9062 and loc.getEndColumn() >= 9062
        ) or 
        (   // id=1306, type=DOM-API, prop=button.cancel, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 9062 and loc.getEndColumn() >= 9062
        ) or 
        (   // id=1307, type=DOM-API, prop=button[tabindex], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 9097 and loc.getEndColumn() >= 9097
        ) or 
        (   // id=1308, type=DOM-API, prop=button[tabindex], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-18/jbt.github.io/06c10ac122/source/jbt.github.io/markdown-editor/lib/sweetalert.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 9097 and loc.getEndColumn() >= 9097
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

DebuggingConfig() { this = "DOM-Clobbering-jbt.github.io-06c10ac122" }
    
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
