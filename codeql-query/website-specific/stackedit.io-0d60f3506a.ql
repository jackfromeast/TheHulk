/**
* @name DOM-Clobbering-stackedit.io-0d60f3506a
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
        (   // id=1, type=WIN-TYPE-1, prop=webpackJsonp 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/manifest.9841283e03f435423068.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 161 and loc.getEndColumn() >= 161
        ) or 
        (   // id=2, type=WIN-TYPE-1, prop=webpackJsonp 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/manifest.9841283e03f435423068.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 193 and loc.getEndColumn() >= 193
        ) or 
        (   // id=3, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 960661 and loc.getEndColumn() >= 960661
        ) or 
        (   // id=4, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 960793 and loc.getEndColumn() >= 960793
        ) or 
        (   // id=5, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 20270 and loc.getEndColumn() >= 20270
        ) or 
        (   // id=6, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 12323 and loc.getEndColumn() >= 12323
        ) or 
        (   // id=7, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 13355 and loc.getEndColumn() >= 13355
        ) or 
        (   // id=8, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 13403 and loc.getEndColumn() >= 13403
        ) or 
        (   // id=9, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 178973 and loc.getEndColumn() >= 178973
        ) or 
        (   // id=10, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 178973 and loc.getEndColumn() >= 178973
        ) or 
        (   // id=11, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 178973 and loc.getEndColumn() >= 178973
        ) or 
        (   // id=12, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 178973 and loc.getEndColumn() >= 178973
        ) or 
        (   // id=15, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 83543 and loc.getEndColumn() >= 83543
        ) or 
        (   // id=16, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 83555 and loc.getEndColumn() >= 83555
        ) or 
        (   // id=17, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 83572 and loc.getEndColumn() >= 83572
        ) or 
        (   // id=18, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 83610 and loc.getEndColumn() >= 83610
        ) or 
        (   // id=19, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 980869 and loc.getEndColumn() >= 980869
        ) or 
        (   // id=21, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 985446 and loc.getEndColumn() >= 985446
        ) or 
        (   // id=22, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 691226 and loc.getEndColumn() >= 691226
        ) or 
        (   // id=23, type=WIN-TYPE-1, prop=setTimeout 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 691330 and loc.getEndColumn() >= 691330
        ) or 
        (   // id=24, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 691385 and loc.getEndColumn() >= 691385
        ) or 
        (   // id=25, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 691484 and loc.getEndColumn() >= 691484
        ) or 
        (   // id=26, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 692317 and loc.getEndColumn() >= 692317
        ) or 
        (   // id=27, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 692336 and loc.getEndColumn() >= 692336
        ) or 
        (   // id=28, type=WIN-TYPE-1, prop=WXEnvironment 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 1117 and loc.getEndColumn() >= 1117
        ) or 
        (   // id=29, type=WIN-TYPE-1, prop=__VUE_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 1753 and loc.getEndColumn() >= 1753
        ) or 
        (   // id=30, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 8888 and loc.getEndColumn() >= 8888
        ) or 
        (   // id=31, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 42573 and loc.getEndColumn() >= 42573
        ) or 
        (   // id=32, type=WIN-TYPE-1, prop=core 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1182 and loc.getEndColumn() >= 1182
        ) or 
        (   // id=33, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1019726 and loc.getEndColumn() >= 1019726
        ) or 
        (   // id=36, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 19118 and loc.getEndColumn() >= 19118
        ) or 
        (   // id=37, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 19185 and loc.getEndColumn() >= 19185
        ) or 
        (   // id=38, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 17002 and loc.getEndColumn() >= 17002
        ) or 
        (   // id=40, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1007308 and loc.getEndColumn() >= 1007308
        ) or 
        (   // id=41, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1042 and loc.getEndColumn() >= 1042
        ) or 
        (   // id=42, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 23649 and loc.getEndColumn() >= 23649
        ) or 
        (   // id=43, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 23720 and loc.getEndColumn() >= 23720
        ) or 
        (   // id=44, type=WIN-TYPE-1, prop=System 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 913 and loc.getEndColumn() >= 913
        ) or 
        (   // id=45, type=WIN-TYPE-1, prop=System 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 923 and loc.getEndColumn() >= 923
        ) or 
        (   // id=47, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1024953 and loc.getEndColumn() >= 1024953
        ) or 
        (   // id=48, type=WIN-TYPE-1, prop=asap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1042 and loc.getEndColumn() >= 1042
        ) or 
        (   // id=49, type=WIN-TYPE-1, prop=asap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 23649 and loc.getEndColumn() >= 23649
        ) or 
        (   // id=50, type=WIN-TYPE-1, prop=asap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 23678 and loc.getEndColumn() >= 23678
        ) or 
        (   // id=51, type=WIN-TYPE-1, prop=asap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 23720 and loc.getEndColumn() >= 23720
        ) or 
        (   // id=53, type=WIN-TYPE-1, prop=Observable 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1042 and loc.getEndColumn() >= 1042
        ) or 
        (   // id=54, type=WIN-TYPE-1, prop=Observable 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 23649 and loc.getEndColumn() >= 23649
        ) or 
        (   // id=55, type=WIN-TYPE-1, prop=Observable 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 23678 and loc.getEndColumn() >= 23678
        ) or 
        (   // id=56, type=WIN-TYPE-1, prop=Observable 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 23720 and loc.getEndColumn() >= 23720
        ) or 
        (   // id=57, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1034571 and loc.getEndColumn() >= 1034571
        ) or 
        (   // id=58, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1034571 and loc.getEndColumn() >= 1034571
        ) or 
        (   // id=59, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1034571 and loc.getEndColumn() >= 1034571
        ) or 
        (   // id=60, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1034571 and loc.getEndColumn() >= 1034571
        ) or 
        (   // id=61, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 686698 and loc.getEndColumn() >= 686698
        ) or 
        (   // id=62, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 686774 and loc.getEndColumn() >= 686774
        ) or 
        (   // id=63, type=WIN-TYPE-1, prop=_babelPolyfill 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 207956 and loc.getEndColumn() >= 207956
        ) or 
        (   // id=64, type=WIN-TYPE-1, prop=_babelPolyfill 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 208053 and loc.getEndColumn() >= 208053
        ) or 
        (   // id=65, type=WIN-TYPE-1, prop=openDatabase 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 355283 and loc.getEndColumn() >= 355283
        ) or 
        (   // id=66, type=WIN-TYPE-1, prop=shimIndexedDB 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 355366 and loc.getEndColumn() >= 355366
        ) or 
        (   // id=67, type=WIN-TYPE-1, prop=shimIndexedDB 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 357895 and loc.getEndColumn() >= 357895
        ) or 
        (   // id=69, type=WIN-TYPE-1, prop=Prism 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 192235 and loc.getEndColumn() >= 192235
        ) or 
        (   // id=70, type=WIN-TYPE-1, prop=Prism 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 192287 and loc.getEndColumn() >= 192287
        ) or 
        (   // id=71, type=WIN-TYPE-1, prop=Prism 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 192224 and loc.getEndColumn() >= 192224
        ) or 
        (   // id=75, type=WIN-TYPE-1, prop=TYPED_ARRAY_SUPPORT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 117 and loc.getEndColumn() >= 117
        ) or 
        (   // id=76, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 989037 and loc.getEndColumn() >= 989037
        ) or 
        (   // id=77, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 514126 and loc.getEndColumn() >= 514126
        ) or 
        (   // id=78, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 514220 and loc.getEndColumn() >= 514220
        ) or 
        (   // id=79, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 514259 and loc.getEndColumn() >= 514259
        ) or 
        (   // id=81, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 191106 and loc.getEndColumn() >= 191106
        ) or 
        (   // id=82, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 67278 and loc.getEndColumn() >= 67278
        ) or 
        (   // id=83, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 225159 and loc.getEndColumn() >= 225159
        ) or 
        (   // id=84, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 461169 and loc.getEndColumn() >= 461169
        ) or 
        (   // id=85, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 57996 and loc.getEndColumn() >= 57996
        ) or 
        (   // id=86, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 176571 and loc.getEndColumn() >= 176571
        ) or 
        (   // id=87, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 22966 and loc.getEndColumn() >= 22966
        ) or 
        (   // id=88, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 20961 and loc.getEndColumn() >= 20961
        ) or 
        (   // id=89, type=WIN-TYPE-1, prop=mermaid 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 514367 and loc.getEndColumn() >= 514367
        ) or 
        (   // id=99, type=WIN-TYPE-1, prop=Mousetrap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 679076 and loc.getEndColumn() >= 679076
        ) or 
        (   // id=100, type=WIN-TYPE-1, prop=__VUE_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 406 and loc.getEndColumn() >= 406
        ) or 
        (   // id=110, type=WIN-TYPE-1, prop=safari 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 461624 and loc.getEndColumn() >= 461624
        ) or 
        (   // id=1198, type=WIN-TYPE-1, prop=txt 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 914610 and loc.getEndColumn() >= 914610
        ) or 
        (   // id=1508, type=WIN-TYPE-1, prop=gapi 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 367 and loc.getEndColumn() >= 367
        ) or 
        (   // id=1509, type=WIN-TYPE-1, prop=gapi 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 359 and loc.getEndColumn() >= 359
        ) or 
        (   // id=1510, type=WIN-TYPE-1, prop=___jsl 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 107 and loc.getEndColumn() >= 107
        ) or 
        (   // id=1511, type=WIN-TYPE-1, prop=___jsl 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 105 and loc.getEndColumn() >= 105
        ) or 
        (   // id=1512, type=WIN-TYPE-1, prop=gapi_onload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 1168 and loc.getEndColumn() >= 1168
        ) or 
        (   // id=1576, type=WIN-TYPE-1, prop=gapi_onload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 1168 and loc.getEndColumn() >= 1168
        ) or 
        (   // id=1764, type=WIN-TYPE-1, prop=gapi_onload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 1168 and loc.getEndColumn() >= 1168
        ) or 
        (   // id=2520, type=WIN-TYPE-1, prop=gapi_onload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 1168 and loc.getEndColumn() >= 1168
        ) or 
        (   // id=2940, type=WIN-TYPE-1, prop=gapi_onload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 1168 and loc.getEndColumn() >= 1168
        ) or 
        (   // id=2948, type=WIN-TYPE-1, prop=gapi_onload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 1168 and loc.getEndColumn() >= 1168
        ) or 
        (   // id=2950, type=WIN-TYPE-1, prop=gapi_onload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 1168 and loc.getEndColumn() >= 1168
        ) or 
        (   // id=2952, type=WIN-TYPE-1, prop=gapi_onload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 1168 and loc.getEndColumn() >= 1168
        ) or 
        (   // id=2954, type=WIN-TYPE-1, prop=gapi_onload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/apis.google.com/js/api.js") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 1168 and loc.getEndColumn() >= 1168
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
        (   // id=13, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 80472 and loc.getEndColumn() >= 80472
        ) or 
        (   // id=34, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 15242 and loc.getEndColumn() >= 15242
        ) or 
        (   // id=72, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 197770 and loc.getEndColumn() >= 197770
        ) or 
        (   // id=80, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 45614 and loc.getEndColumn() >= 45614
        ) or 
        (   // id=92, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305563 and loc.getEndColumn() >= 305563
        ) or 
        (   // id=103, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 339651 and loc.getEndColumn() >= 339651
        ) or 
        (   // id=104, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 339712 and loc.getEndColumn() >= 339712
        ) or 
        (   // id=105, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 339766 and loc.getEndColumn() >= 339766
        ) or 
        (   // id=112, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 113118 and loc.getEndColumn() >= 113118
        ) or 
        (   // id=144, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 422170 and loc.getEndColumn() >= 422170
        ) or 
        (   // id=145, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 422209 and loc.getEndColumn() >= 422209
        ) or 
        (   // id=178, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 62580 and loc.getEndColumn() >= 62580
        ) or 
        (   // id=199, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 325566 and loc.getEndColumn() >= 325566
        ) or 
        (   // id=1194, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 11 and loc.getEndLine() = 11 and
            loc.getStartColumn() <= 450031 and loc.getEndColumn() >= 450031
        ) or 
        (   // id=1203, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127636 and loc.getEndColumn() >= 127636
        ) or 
        (   // id=1273, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1162377 and loc.getEndColumn() >= 1162377
        ) or 
        (   // id=1462, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 333212 and loc.getEndColumn() >= 333212
        ) or 
        (   // id=1507, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 50707 and loc.getEndColumn() >= 50707
        ) or 
        (   // id=1513, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 50881 and loc.getEndColumn() >= 50881
        ) or 
        (   // id=1522, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 405895 and loc.getEndColumn() >= 405895
        ) or 
        (   // id=2924, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 325692 and loc.getEndColumn() >= 325692
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
        (   // id=114, type=DOM-API, prop=app, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 57857 and loc.getEndColumn() >= 57857
        ) or 
        (   // id=115, type=DOM-API, prop=#app, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 57857 and loc.getEndColumn() >= 57857
        ) or 
        (   // id=135, type=DOM-API, prop=.mermaid, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 907785 and loc.getEndColumn() >= 907785
        ) or 
        (   // id=136, type=DOM-API, prop=.mermaid, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 907785 and loc.getEndColumn() >= 907785
        ) or 
        (   // id=179, type=DOM-API, prop=.navigation-bar__title--fake, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 194569 and loc.getEndColumn() >= 194569
        ) or 
        (   // id=181, type=DOM-API, prop=.navigation-bar__title--input, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 194643 and loc.getEndColumn() >= 194643
        ) or 
        (   // id=183, type=DOM-API, prop=.editor__inner, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 174839 and loc.getEndColumn() >= 174839
        ) or 
        (   // id=185, type=DOM-API, prop=.preview__inner-2, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 195488 and loc.getEndColumn() >= 195488
        ) or 
        (   // id=187, type=DOM-API, prop=.toc__inner, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 199459 and loc.getEndColumn() >= 199459
        ) or 
        (   // id=190, type=DOM-API, prop=[tour-step-anchor], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 200420 and loc.getEndColumn() >= 200420
        ) or 
        (   // id=191, type=DOM-API, prop=[tour-step-anchor], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 200420 and loc.getEndColumn() >= 200420
        ) or 
        (   // id=192, type=DOM-API, prop=.editor__inner, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 187308 and loc.getEndColumn() >= 187308
        ) or 
        (   // id=194, type=DOM-API, prop=.preview__inner-2, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 187351 and loc.getEndColumn() >= 187351
        ) or 
        (   // id=196, type=DOM-API, prop=.toc__inner, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 187397 and loc.getEndColumn() >= 187397
        ) or 
        (   // id=202, type=DOM-API, prop=token img, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 20357 and loc.getEndColumn() >= 20357
        ) or 
        (   // id=313, type=DOM-API, prop=.prism.language-abc, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 299306 and loc.getEndColumn() >= 299306
        ) or 
        (   // id=314, type=DOM-API, prop=.prism.language-abc, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 299306 and loc.getEndColumn() >= 299306
        ) or 
        (   // id=315, type=DOM-API, prop=.katex--inline, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 300291 and loc.getEndColumn() >= 300291
        ) or 
        (   // id=316, type=DOM-API, prop=.katex--inline, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 300291 and loc.getEndColumn() >= 300291
        ) or 
        (   // id=317, type=DOM-API, prop=.katex--display, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 300343 and loc.getEndColumn() >= 300343
        ) or 
        (   // id=318, type=DOM-API, prop=.katex--display, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 300343 and loc.getEndColumn() >= 300343
        ) or 
        (   // id=319, type=DOM-API, prop=.prism, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 304509 and loc.getEndColumn() >= 304509
        ) or 
        (   // id=320, type=DOM-API, prop=.prism, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 304509 and loc.getEndColumn() >= 304509
        ) or 
        (   // id=321, type=DOM-API, prop=span.task-list-item-checkbox, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 304638 and loc.getEndColumn() >= 304638
        ) or 
        (   // id=322, type=DOM-API, prop=span.task-list-item-checkbox, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 304638 and loc.getEndColumn() >= 304638
        ) or 
        (   // id=323, type=DOM-API, prop=.prism.language-mermaid, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305982 and loc.getEndColumn() >= 305982
        ) or 
        (   // id=324, type=DOM-API, prop=.prism.language-mermaid, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305982 and loc.getEndColumn() >= 305982
        ) or 
        (   // id=325, type=DOM-API, prop=img, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 15647 and loc.getEndColumn() >= 15647
        ) or 
        (   // id=1200, type=DOM-API, prop=dmermaid-svg-tHRYeyuNinCABMVY, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1201, type=DOM-API, prop=#dmermaid-svg-tHRYeyuNinCABMVY, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1206, type=DOM-API, prop=mermaid-svg-tHRYeyuNinCABMVY, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1207, type=DOM-API, prop=[id="mermaid-svg-tHRYeyuNinCABMVY"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1211, type=DOM-API, prop=body, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1267, type=DOM-API, prop=arrowhead, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 832664 and loc.getEndColumn() >= 832664
        ) or 
        (   // id=1268, type=DOM-API, prop=crosshead, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 832664 and loc.getEndColumn() >= 832664
        ) or 
        (   // id=1270, type=DOM-API, prop=mermaid-svg-tHRYeyuNinCABMVY, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1162347 and loc.getEndColumn() >= 1162347
        ) or 
        (   // id=1271, type=DOM-API, prop=#mermaid-svg-tHRYeyuNinCABMVY .actor-line, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1162347 and loc.getEndColumn() >= 1162347
        ) or 
        (   // id=1272, type=DOM-API, prop=#mermaid-svg-tHRYeyuNinCABMVY .actor-line, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1162347 and loc.getEndColumn() >= 1162347
        ) or 
        (   // id=1277, type=DOM-API, prop=foreignobject > *, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1278, type=DOM-API, prop=foreignobject > *, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1282, type=DOM-API, prop=mermaid-svg-tHRYeyuNinCABMVY, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305821 and loc.getEndColumn() >= 305821
        ) or 
        (   // id=1283, type=DOM-API, prop=#mermaid-svg-tHRYeyuNinCABMVY, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305821 and loc.getEndColumn() >= 305821
        ) or 
        (   // id=1285, type=DOM-API, prop=arrowhead, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=1286, type=DOM-API, prop=crosshead, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=1325, type=DOM-API, prop=dmermaid-svg-CIKIfZOihrYcSBKP, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1326, type=DOM-API, prop=#dmermaid-svg-CIKIfZOihrYcSBKP, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1329, type=DOM-API, prop=mermaid-svg-CIKIfZOihrYcSBKP, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1330, type=DOM-API, prop=[id="mermaid-svg-CIKIfZOihrYcSBKP"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1336, type=DOM-API, prop=#mermaid-svg-CIKIfZOihrYcSBKP g, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=1338, type=DOM-API, prop=g.output, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 46078 and loc.getEndColumn() >= 46078
        ) or 
        (   // id=1340, type=DOM-API, prop=g.clusters, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 46078 and loc.getEndColumn() >= 46078
        ) or 
        (   // id=1342, type=DOM-API, prop=g.edgePaths, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 46078 and loc.getEndColumn() >= 46078
        ) or 
        (   // id=1344, type=DOM-API, prop=g.edgeLabels, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 46078 and loc.getEndColumn() >= 46078
        ) or 
        (   // id=1346, type=DOM-API, prop=g.edgeLabel, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1347, type=DOM-API, prop=g.edgeLabel, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1350, type=DOM-API, prop=.label, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 46078 and loc.getEndColumn() >= 46078
        ) or 
        (   // id=1358, type=DOM-API, prop=g.nodes, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 46078 and loc.getEndColumn() >= 46078
        ) or 
        (   // id=1360, type=DOM-API, prop=g.node, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1361, type=DOM-API, prop=g.node, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1364, type=DOM-API, prop=g.label, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 46078 and loc.getEndColumn() >= 46078
        ) or 
        (   // id=1366, type=DOM-API, prop=.label-container, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 46078 and loc.getEndColumn() >= 46078
        ) or 
        (   // id=1368, type=DOM-API, prop=:first-child, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 46078 and loc.getEndColumn() >= 46078
        ) or 
        (   // id=1388, type=DOM-API, prop=g.edgePath, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1389, type=DOM-API, prop=g.edgePath, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1390, type=DOM-API, prop=path.path, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1391, type=DOM-API, prop=path.path, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1398, type=DOM-API, prop=defs *, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1399, type=DOM-API, prop=defs *, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1406, type=DOM-API, prop=defs, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1407, type=DOM-API, prop=defs, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1414, type=DOM-API, prop=g.cluster, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1415, type=DOM-API, prop=g.cluster, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 128977 and loc.getEndColumn() >= 128977
        ) or 
        (   // id=1420, type=DOM-API, prop=arrowhead1, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666210 and loc.getEndColumn() >= 666210
        ) or 
        (   // id=1421, type=DOM-API, prop=arrowhead2, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666210 and loc.getEndColumn() >= 666210
        ) or 
        (   // id=1422, type=DOM-API, prop=arrowhead3, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666210 and loc.getEndColumn() >= 666210
        ) or 
        (   // id=1423, type=DOM-API, prop=arrowhead4, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666210 and loc.getEndColumn() >= 666210
        ) or 
        (   // id=1425, type=DOM-API, prop=mermaid-svg-CIKIfZOihrYcSBKP, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666990 and loc.getEndColumn() >= 666990
        ) or 
        (   // id=1426, type=DOM-API, prop=[id="mermaid-svg-CIKIfZOihrYcSBKP"] .edgeLabel .label, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666990 and loc.getEndColumn() >= 666990
        ) or 
        (   // id=1427, type=DOM-API, prop=[id="mermaid-svg-CIKIfZOihrYcSBKP"] .edgeLabel .label, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666990 and loc.getEndColumn() >= 666990
        ) or 
        (   // id=1440, type=DOM-API, prop=mermaid-svg-CIKIfZOihrYcSBKP, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305821 and loc.getEndColumn() >= 305821
        ) or 
        (   // id=1441, type=DOM-API, prop=#mermaid-svg-CIKIfZOihrYcSBKP, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305821 and loc.getEndColumn() >= 305821
        ) or 
        (   // id=1443, type=DOM-API, prop=arrowhead1, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=1444, type=DOM-API, prop=arrowhead2, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=1445, type=DOM-API, prop=arrowhead3, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=1446, type=DOM-API, prop=arrowhead4, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=1460, type=DOM-API, prop=.cl-toc-section *, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 15969 and loc.getEndColumn() >= 15969
        ) or 
        (   // id=1584, type=DOM-API, prop=input,select, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 259078 and loc.getEndColumn() >= 259078
        ) or 
        (   // id=1592, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 191083 and loc.getEndColumn() >= 191083
        ) or 
        (   // id=1593, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 191083 and loc.getEndColumn() >= 191083
        ) or 
        (   // id=1594, type=DOM-API, prop=6ZqQIxPPoV3SZaKU, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 191083 and loc.getEndColumn() >= 191083
        ) or 
        (   // id=1595, type=DOM-API, prop=EfLnupYloH6BUDJf, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 191083 and loc.getEndColumn() >= 191083
        ) or 
        (   // id=1596, type=DOM-API, prop=jM0ZDQ16JIhIydPn, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 191083 and loc.getEndColumn() >= 191083
        ) or 
        (   // id=1830, type=DOM-API, prop=.form-entry[error=repoUrl], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11549 and loc.getEndColumn() >= 11549
        ) or 
        (   // id=1888, type=DOM-API, prop=hd-lf, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 325993 and loc.getEndColumn() >= 325993
        ) or 
        (   // id=1889, type=DOM-API, prop=br, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 326088 and loc.getEndColumn() >= 326088
        ) or 
        (   // id=2327, type=DOM-API, prop=arrowhead, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 15279 and loc.getEndColumn() >= 15279
        ) or 
        (   // id=2328, type=DOM-API, prop=crosshead, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 15279 and loc.getEndColumn() >= 15279
        ) or 
        (   // id=2346, type=DOM-API, prop=dmermaid-svg-VvCP6pmTFKly16hC, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2347, type=DOM-API, prop=#dmermaid-svg-VvCP6pmTFKly16hC, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2350, type=DOM-API, prop=mermaid-svg-VvCP6pmTFKly16hC, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2351, type=DOM-API, prop=[id="mermaid-svg-VvCP6pmTFKly16hC"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2377, type=DOM-API, prop=arrowhead, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1162806 and loc.getEndColumn() >= 1162806
        ) or 
        (   // id=2381, type=DOM-API, prop=crosshead, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1162806 and loc.getEndColumn() >= 1162806
        ) or 
        (   // id=2425, type=DOM-API, prop=mermaid-svg-VvCP6pmTFKly16hC, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1162347 and loc.getEndColumn() >= 1162347
        ) or 
        (   // id=2426, type=DOM-API, prop=#mermaid-svg-VvCP6pmTFKly16hC .actor-line, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1162347 and loc.getEndColumn() >= 1162347
        ) or 
        (   // id=2427, type=DOM-API, prop=#mermaid-svg-VvCP6pmTFKly16hC .actor-line, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 1162347 and loc.getEndColumn() >= 1162347
        ) or 
        (   // id=2437, type=DOM-API, prop=mermaid-svg-VvCP6pmTFKly16hC, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305821 and loc.getEndColumn() >= 305821
        ) or 
        (   // id=2438, type=DOM-API, prop=#mermaid-svg-VvCP6pmTFKly16hC, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305821 and loc.getEndColumn() >= 305821
        ) or 
        (   // id=2497, type=DOM-API, prop=dmermaid-svg-SkjuJgiHVRvWOQRP, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2498, type=DOM-API, prop=#dmermaid-svg-SkjuJgiHVRvWOQRP, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2501, type=DOM-API, prop=mermaid-svg-SkjuJgiHVRvWOQRP, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2502, type=DOM-API, prop=#mermaid-svg-SkjuJgiHVRvWOQRP, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2587, type=DOM-API, prop=dmermaid-svg-orCN6Sz8jI7NlF9h, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2588, type=DOM-API, prop=#dmermaid-svg-orCN6Sz8jI7NlF9h, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2591, type=DOM-API, prop=mermaid-svg-orCN6Sz8jI7NlF9h, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2592, type=DOM-API, prop=[id="mermaid-svg-orCN6Sz8jI7NlF9h"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2606, type=DOM-API, prop=#mermaid-svg-orCN6Sz8jI7NlF9h g, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 127608 and loc.getEndColumn() >= 127608
        ) or 
        (   // id=2747, type=DOM-API, prop=arrowhead5, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666210 and loc.getEndColumn() >= 666210
        ) or 
        (   // id=2748, type=DOM-API, prop=arrowhead6, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666210 and loc.getEndColumn() >= 666210
        ) or 
        (   // id=2749, type=DOM-API, prop=arrowhead7, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666210 and loc.getEndColumn() >= 666210
        ) or 
        (   // id=2750, type=DOM-API, prop=arrowhead8, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666210 and loc.getEndColumn() >= 666210
        ) or 
        (   // id=2752, type=DOM-API, prop=mermaid-svg-orCN6Sz8jI7NlF9h, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666990 and loc.getEndColumn() >= 666990
        ) or 
        (   // id=2753, type=DOM-API, prop=[id="mermaid-svg-orCN6Sz8jI7NlF9h"] .edgeLabel .label, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666990 and loc.getEndColumn() >= 666990
        ) or 
        (   // id=2754, type=DOM-API, prop=[id="mermaid-svg-orCN6Sz8jI7NlF9h"] .edgeLabel .label, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js") and
            loc.getStartLine() = 17 and loc.getEndLine() = 17 and
            loc.getStartColumn() <= 666990 and loc.getEndColumn() >= 666990
        ) or 
        (   // id=2767, type=DOM-API, prop=mermaid-svg-orCN6Sz8jI7NlF9h, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305821 and loc.getEndColumn() >= 305821
        ) or 
        (   // id=2768, type=DOM-API, prop=#mermaid-svg-orCN6Sz8jI7NlF9h, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305821 and loc.getEndColumn() >= 305821
        ) or 
        (   // id=2770, type=DOM-API, prop=arrowhead5, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=2771, type=DOM-API, prop=arrowhead6, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=2772, type=DOM-API, prop=arrowhead7, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=2773, type=DOM-API, prop=arrowhead8, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 305807 and loc.getEndColumn() >= 305807
        ) or 
        (   // id=2856, type=DOM-API, prop=z0732zB7ZlBXYpN1, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-21-21/stackedit.io/0d60f3506a/source/stackedit.io/static/js/app.4a860d498cf8c210e5e8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 191083 and loc.getEndColumn() >= 191083
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

DebuggingConfig() { this = "DOM-Clobbering-stackedit.io-0d60f3506a" }
    
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
