/**
* @name DOM-Clobbering-paste.quest-e52d015bcd
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
        (   // id=35, type=WIN-TYPE-1, prop=onfocusin 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=45, type=WIN-TYPE-1, prop=onfocusout 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=59, type=WIN-TYPE-1, prop=onshow 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=71, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25851 and loc.getEndColumn() >= 25851
        ) or 
        (   // id=72, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 32731 and loc.getEndColumn() >= 32731
        ) or 
        (   // id=73, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 32747 and loc.getEndColumn() >= 32747
        ) or 
        (   // id=74, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 32761 and loc.getEndColumn() >= 32761
        ) or 
        (   // id=86, type=WIN-TYPE-1, prop=onwebkitTransitionEnd 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=90, type=WIN-TYPE-1, prop=onshown 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=94, type=WIN-TYPE-1, prop=onhide 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=106, type=WIN-TYPE-1, prop=onhidden 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=1149, type=WIN-TYPE-1, prop=onajaxStart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=1150, type=WIN-TYPE-1, prop=onajaxSend 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=1175, type=WIN-TYPE-1, prop=onajaxSuccess 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=1176, type=WIN-TYPE-1, prop=onajaxComplete 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=1177, type=WIN-TYPE-1, prop=onajaxStop 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71677 and loc.getEndColumn() >= 71677
        ) or 
        (   // id=1182, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 44865 and loc.getEndColumn() >= 44865
        ) or 
        (   // id=1186, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/kjua-0.9.0.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=1187, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/kjua-0.9.0.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 80 and loc.getEndColumn() >= 80
        ) or 
        (   // id=1188, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/kjua-0.9.0.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 123 and loc.getEndColumn() >= 123
        ) or 
        (   // id=1189, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/kjua-0.9.0.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 467 and loc.getEndColumn() >= 467
        ) or 
        (   // id=1190, type=WIN-TYPE-1, prop=kjua 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/kjua-0.9.0.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 191 and loc.getEndColumn() >= 191
        ) or 
        (   // id=1203, type=WIN-TYPE-1, prop=module 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 29 and loc.getEndColumn() >= 29
        ) or 
        (   // id=1273, type=WIN-TYPE-1, prop=onfocusin 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 70606 and loc.getEndColumn() >= 70606
        ) or 
        (   // id=1277, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 89347 and loc.getEndColumn() >= 89347
        ) or 
        (   // id=1278, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 89426 and loc.getEndColumn() >= 89426
        ) or 
        (   // id=1279, type=WIN-TYPE-1, prop=$ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 89438 and loc.getEndColumn() >= 89438
        ) or 
        (   // id=1280, type=WIN-TYPE-1, prop=$ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 89567 and loc.getEndColumn() >= 89567
        ) or 
        (   // id=1281, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 89563 and loc.getEndColumn() >= 89563
        ) or 
        (   // id=1282, type=WIN-TYPE-1, prop=zlib 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/zlib-1.2.13.js") and
            loc.getStartLine() = 145 and loc.getEndLine() = 145 and
            loc.getStartColumn() <= 15 and loc.getEndColumn() >= 15
        ) or 
        (   // id=1283, type=WIN-TYPE-1, prop=baseX 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/base-x-4.0.0.js") and
            loc.getStartLine() = 8 and loc.getEndLine() = 8 and
            loc.getStartColumn() <= 12 and loc.getEndColumn() >= 12
        ) or 
        (   // id=1284, type=WIN-TYPE-1, prop=RawDeflate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/rawinflate-0.3.js") and
            loc.getStartLine() = 752 and loc.getEndLine() = 752 and
            loc.getStartColumn() <= 11 and loc.getEndColumn() >= 11
        ) or 
        (   // id=1285, type=WIN-TYPE-1, prop=RawDeflate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/rawinflate-0.3.js") and
            loc.getStartLine() = 752 and loc.getEndLine() = 752 and
            loc.getStartColumn() <= 38 and loc.getEndColumn() >= 38
        ) or 
        (   // id=1323, type=WIN-TYPE-1, prop=jQuery361043078488493572521 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 32861 and loc.getEndColumn() >= 32861
        ) or 
        (   // id=1327, type=WIN-TYPE-1, prop=nodeType 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 32901 and loc.getEndColumn() >= 32901
        ) or 
        (   // id=1358, type=WIN-TYPE-1, prop=PR_SHOULD_USE_CONTINUATION 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/prettify.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 76 and loc.getEndColumn() >= 76
        ) or 
        (   // id=1359, type=WIN-TYPE-1, prop=prettyPrintOne 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/prettify.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 404 and loc.getEndColumn() >= 404
        ) or 
        (   // id=1360, type=WIN-TYPE-1, prop=prettyPrint 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/prettify.js") and
            loc.getStartLine() = 27 and loc.getEndLine() = 27 and
            loc.getStartColumn() <= 123 and loc.getEndColumn() >= 123
        ) or 
        (   // id=1361, type=WIN-TYPE-1, prop=PR 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/prettify.js") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 82 and loc.getEndColumn() >= 82
        ) or 
        (   // id=1362, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/prettify.js") and
            loc.getStartLine() = 30 and loc.getEndLine() = 30 and
            loc.getStartColumn() <= 87 and loc.getEndColumn() >= 87
        ) or 
        (   // id=1363, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/showdown-2.1.0.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71878 and loc.getEndColumn() >= 71878
        ) or 
        (   // id=1364, type=WIN-TYPE-1, prop=module 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/showdown-2.1.0.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71916 and loc.getEndColumn() >= 71916
        ) or 
        (   // id=1365, type=WIN-TYPE-1, prop=showdown 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/showdown-2.1.0.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 72031 and loc.getEndColumn() >= 72031
        ) or 
        (   // id=1366, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/purify-2.4.6.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=1367, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/purify-2.4.6.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=1379, type=WIN-TYPE-1, prop=DOMPurify 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/purify-2.4.6.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 199 and loc.getEndColumn() >= 199
        ) or 
        (   // id=1383, type=WIN-TYPE-1, prop=Legacy 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/legacy.js") and
            loc.getStartLine() = 308 and loc.getEndLine() = 308 and
            loc.getStartColumn() <= 17 and loc.getEndColumn() >= 17
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
        (   // id=34, type=DOC-TYPE-1, prop=onfocusin 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71676 and loc.getEndColumn() >= 71676
        ) or 
        (   // id=1210, type=DOC-TYPE-1, prop=namespaceURI 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8399 and loc.getEndColumn() >= 8399
        ) or 
        (   // id=1287, type=DOC-TYPE-1, prop=jQuery361043078488493572521 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 32860 and loc.getEndColumn() >= 32860
        ) or 
        (   // id=1293, type=DOC-TYPE-1, prop=type 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 44145 and loc.getEndColumn() >= 44145
        ) or 
        (   // id=1304, type=DOC-TYPE-1, prop=document 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 72555 and loc.getEndColumn() >= 72555
        ) or 
        (   // id=1381, type=DOC-TYPE-1, prop=attachEvent 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/legacy.js") and
            loc.getStartLine() = 293 and loc.getEndLine() = 293 and
            loc.getStartColumn() <= 57 and loc.getEndColumn() >= 57
        ) or 
        (   // id=1549, type=DOC-TYPE-1, prop=onajaxStart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71676 and loc.getEndColumn() >= 71676
        ) or 
        (   // id=1551, type=DOC-TYPE-1, prop=ajaxStart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71857 and loc.getEndColumn() >= 71857
        ) or 
        (   // id=1557, type=DOC-TYPE-1, prop=onajaxSend 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71676 and loc.getEndColumn() >= 71676
        ) or 
        (   // id=1559, type=DOC-TYPE-1, prop=ajaxSend 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71857 and loc.getEndColumn() >= 71857
        ) or 
        (   // id=1600, type=DOC-TYPE-1, prop=onajaxSuccess 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71676 and loc.getEndColumn() >= 71676
        ) or 
        (   // id=1602, type=DOC-TYPE-1, prop=ajaxSuccess 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71857 and loc.getEndColumn() >= 71857
        ) or 
        (   // id=1608, type=DOC-TYPE-1, prop=onajaxComplete 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71676 and loc.getEndColumn() >= 71676
        ) or 
        (   // id=1610, type=DOC-TYPE-1, prop=ajaxComplete 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71857 and loc.getEndColumn() >= 71857
        ) or 
        (   // id=1616, type=DOC-TYPE-1, prop=onajaxStop 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71676 and loc.getEndColumn() >= 71676
        ) or 
        (   // id=1618, type=DOC-TYPE-1, prop=ajaxStop 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71857 and loc.getEndColumn() >= 71857
        ) or 
        (   // id=1623, type=DOC-TYPE-1, prop=onshow 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 71676 and loc.getEndColumn() >= 71676
        ))
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
        (   // id=4, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8438 and loc.getEndColumn() >= 8438
        ) or 
        (   // id=37, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/privatebin.js") and
            loc.getStartLine() = 3755 and loc.getEndLine() = 3755 and
            loc.getStartColumn() <= 21 and loc.getEndColumn() >= 21
        ) or 
        (   // id=41, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/privatebin.js") and
            loc.getStartLine() = 3759 and loc.getEndLine() = 3759 and
            loc.getStartColumn() <= 21 and loc.getEndColumn() >= 21
        ) or 
        (   // id=53, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 12036 and loc.getEndColumn() >= 12036
        ) or 
        (   // id=57, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/bootstrap-3.4.1.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 13907 and loc.getEndColumn() >= 13907
        ) or 
        (   // id=60, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/bootstrap-3.4.1.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 18717 and loc.getEndColumn() >= 18717
        ) or 
        (   // id=68, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/bootstrap-3.4.1.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 18901 and loc.getEndColumn() >= 18901
        ) or 
        (   // id=84, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/bootstrap-3.4.1.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 18265 and loc.getEndColumn() >= 18265
        ) or 
        (   // id=87, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 39664 and loc.getEndColumn() >= 39664
        ) or 
        (   // id=483, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/bootstrap-3.4.1.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 12331 and loc.getEndColumn() >= 12331
        ) or 
        (   // id=511, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/purify-2.4.6.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 15888 and loc.getEndColumn() >= 15888
        ) or 
        (   // id=512, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/purify-2.4.6.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16004 and loc.getEndColumn() >= 16004
        ) or 
        (   // id=1164, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/privatebin.js") and
            loc.getStartLine() = 403 and loc.getEndLine() = 403 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=1208, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8588 and loc.getEndColumn() >= 8588
        ) or 
        (   // id=1209, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8614 and loc.getEndColumn() >= 8614
        ) or 
        (   // id=1261, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 32142 and loc.getEndColumn() >= 32142
        ) or 
        (   // id=1262, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 36196 and loc.getEndColumn() >= 36196
        ) or 
        (   // id=1276, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 84595 and loc.getEndColumn() >= 84595
        ) or 
        (   // id=1370, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/purify-2.4.6.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 9884 and loc.getEndColumn() >= 9884
        ) or 
        (   // id=1371, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/purify-2.4.6.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 9901 and loc.getEndColumn() >= 9901
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
        (   // id=1, type=DOM-API, prop=dropdown-backdrop, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6649 and loc.getEndColumn() >= 6649
        ) or 
        (   // id=2, type=DOM-API, prop=[data-toggle="dropdown"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=3, type=DOM-API, prop=[data-toggle="dropdown"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=48, type=DOM-API, prop=qrcode-display, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=49, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 38493 and loc.getEndColumn() >= 38493
        ) or 
        (   // id=54, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 38493 and loc.getEndColumn() >= 38493
        ) or 
        (   // id=56, type=DOM-API, prop=qrcodemodal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6376 and loc.getEndColumn() >= 6376
        ) or 
        (   // id=58, type=DOM-API, prop=modal-dialog, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6649 and loc.getEndColumn() >= 6649
        ) or 
        (   // id=131, type=DOM-API, prop=*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=132, type=DOM-API, prop=*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=146, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6539 and loc.getEndColumn() >= 6539
        ) or 
        (   // id=150, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 40400 and loc.getEndColumn() >= 40400
        ) or 
        (   // id=151, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 40400 and loc.getEndColumn() >= 40400
        ) or 
        (   // id=152, type=DOM-API, prop=passworddecrypt, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 40400 and loc.getEndColumn() >= 40400
        ) or 
        (   // id=155, type=DOM-API, prop=input, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6539 and loc.getEndColumn() >= 6539
        ) or 
        (   // id=156, type=DOM-API, prop=pasteExpiration, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=157, type=DOM-API, prop=pasteExpiration, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=158, type=DOM-API, prop=#pasteExpiration>option, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=159, type=DOM-API, prop=#pasteExpiration>option, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=160, type=DOM-API, prop=pasteExpirationDisplay, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=166, type=DOM-API, prop=replytemplate, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6451 and loc.getEndColumn() >= 6451
        ) or 
        (   // id=167, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 48704 and loc.getEndColumn() >= 48704
        ) or 
        (   // id=172, type=DOM-API, prop=replymessage, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6451 and loc.getEndColumn() >= 6451
        ) or 
        (   // id=173, type=DOM-API, prop=#replymessage, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=174, type=DOM-API, prop=#replymessage, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=175, type=DOM-API, prop=nickname, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6451 and loc.getEndColumn() >= 6451
        ) or 
        (   // id=176, type=DOM-API, prop=#nickname, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=177, type=DOM-API, prop=#nickname, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=178, type=DOM-API, prop=replystatus, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6451 and loc.getEndColumn() >= 6451
        ) or 
        (   // id=179, type=DOM-API, prop=#replystatus, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=180, type=DOM-API, prop=#replystatus, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=181, type=DOM-API, prop=commenttailtemplate, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6451 and loc.getEndColumn() >= 6451
        ) or 
        (   // id=250, type=DOM-API, prop=messageedit, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=251, type=DOM-API, prop=messagepreview, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=489, type=DOM-API, prop=pasteFormatterDisplay, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=513, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/purify-2.4.6.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16111 and loc.getEndColumn() >= 16111
        ) or 
        (   // id=515, type=DOM-API, prop=table, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6539 and loc.getEndColumn() >= 6539
        ) or 
        (   // id=1141, type=DOM-API, prop=navbar, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1142, type=DOM-API, prop=file, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1152, type=DOM-API, prop=pastelink, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1157, type=DOM-API, prop=pasteurl, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1158, type=DOM-API, prop=deletelink, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1160, type=DOM-API, prop=deletelink, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1161, type=DOM-API, prop=#deletelink a, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1162, type=DOM-API, prop=#deletelink a, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1167, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/privatebin.js") and
            loc.getStartLine() = 4792 and loc.getEndLine() = 4792 and
            loc.getStartColumn() <= 21 and loc.getEndColumn() >= 21
        ) or 
        (   // id=1168, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/privatebin.js") and
            loc.getStartLine() = 4792 and loc.getEndLine() = 4792 and
            loc.getStartColumn() <= 21 and loc.getEndColumn() >= 21
        ) or 
        (   // id=1169, type=DOM-API, prop=passworddecrypt, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/privatebin.js") and
            loc.getStartLine() = 4792 and loc.getEndLine() = 4792 and
            loc.getStartColumn() <= 21 and loc.getEndColumn() >= 21
        ) or 
        (   // id=1215, type=DOM-API, prop=:scope fieldset div, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8901 and loc.getEndColumn() >= 8901
        ) or 
        (   // id=1216, type=DOM-API, prop=:scope fieldset div, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8901 and loc.getEndColumn() >= 8901
        ) or 
        (   // id=1220, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 9115 and loc.getEndColumn() >= 9115
        ) or 
        (   // id=1225, type=DOM-API, prop=sizzle1712343281255, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 9287 and loc.getEndColumn() >= 9287
        ) or 
        (   // id=1228, type=DOM-API, prop=[msallowcapture^=''], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10601 and loc.getEndColumn() >= 10601
        ) or 
        (   // id=1229, type=DOM-API, prop=[msallowcapture^=''], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10601 and loc.getEndColumn() >= 10601
        ) or 
        (   // id=1230, type=DOM-API, prop=[selected], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10686 and loc.getEndColumn() >= 10686
        ) or 
        (   // id=1231, type=DOM-API, prop=[selected], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10686 and loc.getEndColumn() >= 10686
        ) or 
        (   // id=1232, type=DOM-API, prop=[id~=sizzle1712343281255-], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10762 and loc.getEndColumn() >= 10762
        ) or 
        (   // id=1233, type=DOM-API, prop=[id~=sizzle1712343281255-], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10762 and loc.getEndColumn() >= 10762
        ) or 
        (   // id=1235, type=DOM-API, prop=[name=''], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10888 and loc.getEndColumn() >= 10888
        ) or 
        (   // id=1236, type=DOM-API, prop=[name=''], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10888 and loc.getEndColumn() >= 10888
        ) or 
        (   // id=1237, type=DOM-API, prop=:checked, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10976 and loc.getEndColumn() >= 10976
        ) or 
        (   // id=1238, type=DOM-API, prop=:checked, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10976 and loc.getEndColumn() >= 10976
        ) or 
        (   // id=1239, type=DOM-API, prop=sizzle1712343281255, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11034 and loc.getEndColumn() >= 11034
        ) or 
        (   // id=1240, type=DOM-API, prop=a#sizzle1712343281255+*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11034 and loc.getEndColumn() >= 11034
        ) or 
        (   // id=1241, type=DOM-API, prop=a#sizzle1712343281255+*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11034 and loc.getEndColumn() >= 11034
        ) or 
        (   // id=1242, type=DOM-API, prop=\, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11093 and loc.getEndColumn() >= 11093
        ) or 
        (   // id=1245, type=DOM-API, prop=[name=d], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11360 and loc.getEndColumn() >= 11360
        ) or 
        (   // id=1246, type=DOM-API, prop=[name=d], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11360 and loc.getEndColumn() >= 11360
        ) or 
        (   // id=1247, type=DOM-API, prop=:enabled, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11434 and loc.getEndColumn() >= 11434
        ) or 
        (   // id=1248, type=DOM-API, prop=:enabled, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11434 and loc.getEndColumn() >= 11434
        ) or 
        (   // id=1249, type=DOM-API, prop=:disabled, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11537 and loc.getEndColumn() >= 11537
        ) or 
        (   // id=1250, type=DOM-API, prop=:disabled, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11537 and loc.getEndColumn() >= 11537
        ) or 
        (   // id=1251, type=DOM-API, prop=*,:x, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11608 and loc.getEndColumn() >= 11608
        ) or 
        (   // id=1413, type=DOM-API, prop=[data-ride="carousel"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1414, type=DOM-API, prop=[data-ride="carousel"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1418, type=DOM-API, prop=[data-spy="scroll"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1419, type=DOM-API, prop=[data-spy="scroll"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1423, type=DOM-API, prop=[data-spy="affix"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1424, type=DOM-API, prop=[data-spy="affix"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1434, type=DOM-API, prop=modal, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6649 and loc.getEndColumn() >= 6649
        ) or 
        (   // id=1435, type=DOM-API, prop=noscript, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1436, type=DOM-API, prop=errormessage, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1437, type=DOM-API, prop=loadingindicator, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1438, type=DOM-API, prop=status, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1439, type=DOM-API, prop=remainingtime, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1440, type=DOM-API, prop=templates, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1441, type=DOM-API, prop=attachment, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1442, type=DOM-API, prop=dragAndDropFileName, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1443, type=DOM-API, prop=dropzone, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1447, type=DOM-API, prop=attachment, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1448, type=DOM-API, prop=#attachment a, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1449, type=DOM-API, prop=#attachment a, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1450, type=DOM-API, prop=attachmentPreview, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1457, type=DOM-API, prop=button, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6539 and loc.getEndColumn() >= 6539
        ) or 
        (   // id=1459, type=DOM-API, prop=replytemplate, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1461, type=DOM-API, prop=commentcontainer, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1462, type=DOM-API, prop=discussion, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1463, type=DOM-API, prop=editorTabs, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1464, type=DOM-API, prop=message, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1467, type=DOM-API, prop=pastesuccess, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1469, type=DOM-API, prop=shortenbutton, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1470, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1471, type=DOM-API, prop=plaintext, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1472, type=DOM-API, prop=prettymessage, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1473, type=DOM-API, prop=prettyprint, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1474, type=DOM-API, prop=pasteFormatter, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1475, type=DOM-API, prop=passworddecrypt, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1476, type=DOM-API, prop=passwordform, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1477, type=DOM-API, prop=passwordmodal, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1478, type=DOM-API, prop=attach, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1479, type=DOM-API, prop=burnafterreading, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1480, type=DOM-API, prop=burnafterreadingoption, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1481, type=DOM-API, prop=clonebutton, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1482, type=DOM-API, prop=customattachment, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1483, type=DOM-API, prop=expiration, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1484, type=DOM-API, prop=fileremovebutton, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1485, type=DOM-API, prop=filewrap, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1486, type=DOM-API, prop=formatter, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1487, type=DOM-API, prop=newbutton, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1488, type=DOM-API, prop=opendiscussion, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1489, type=DOM-API, prop=opendiscussionoption, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1490, type=DOM-API, prop=password, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1491, type=DOM-API, prop=passwordinput, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1492, type=DOM-API, prop=rawtextbutton, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1493, type=DOM-API, prop=downloadtextbutton, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1494, type=DOM-API, prop=retrybutton, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1495, type=DOM-API, prop=sendbutton, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1496, type=DOM-API, prop=qrcodelink, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1497, type=DOM-API, prop=emaillink, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25788 and loc.getEndColumn() >= 25788
        ) or 
        (   // id=1501, type=DOM-API, prop=language, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1502, type=DOM-API, prop=#language ul.dropdown-menu li a, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1503, type=DOM-API, prop=#language ul.dropdown-menu li a, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1508, type=DOM-API, prop=#language select option, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1509, type=DOM-API, prop=#language select option, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1511, type=DOM-API, prop=:scope ul.dropdown-menu li a, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1512, type=DOM-API, prop=:scope ul.dropdown-menu li a, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) or 
        (   // id=1517, type=DOM-API, prop=reloadlink, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 6649 and loc.getEndColumn() >= 6649
        ) or 
        (   // id=1524, type=DOM-API, prop=:first, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-14-52/paste.quest/e52d015bcd/source/paste.quest/js/jquery-3.6.1.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7028 and loc.getEndColumn() >= 7028
        ) )
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

DebuggingConfig() { this = "DOM-Clobbering-paste.quest-e52d015bcd" }
    
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
