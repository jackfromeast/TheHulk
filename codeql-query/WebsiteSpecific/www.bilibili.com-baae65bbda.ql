/**
* @name DOM-Clobbering-www.bilibili.com-baae65bbda
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
        (   // id=4, type=WIN-TYPE-1, prop=classList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 925299 and loc.getEndColumn() >= 925299
        ) or 
        (   // id=38, type=WIN-TYPE-1, prop=bsource 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 4353 and loc.getEndColumn() >= 4353
        ) or 
        (   // id=94, type=WIN-TYPE-1, prop=__BMG_AF__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 543013 and loc.getEndColumn() >= 543013
        ) or 
        (   // id=152, type=WIN-TYPE-1, prop=headerLoginToggleOptions 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 185299 and loc.getEndColumn() >= 185299
        ) or 
        (   // id=164, type=WIN-TYPE-1, prop= 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 127966 and loc.getEndColumn() >= 127966
        ) or 
        (   // id=248, type=WIN-TYPE-1, prop=__BMG_AF__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 1189 and loc.getEndColumn() >= 1189
        ) or 
        (   // id=249, type=WIN-TYPE-1, prop=BmgAutoFallback 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 1204 and loc.getEndColumn() >= 1204
        ) or 
        (   // id=264, type=WIN-TYPE-1, prop=bsource 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 123178 and loc.getEndColumn() >= 123178
        ) or 
        (   // id=316, type=WIN-TYPE-1, prop=XDomainRequest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 528 and loc.getEndColumn() >= 528
        ) or 
        (   // id=399, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=400, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 82 and loc.getEndColumn() >= 82
        ) or 
        (   // id=401, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=402, type=WIN-TYPE-1, prop=webpackJsonpminiLogin 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 2313 and loc.getEndColumn() >= 2313
        ) or 
        (   // id=403, type=WIN-TYPE-1, prop=webpackJsonpminiLogin 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 2275 and loc.getEndColumn() >= 2275
        ) or 
        (   // id=407, type=WIN-TYPE-1, prop=__VUE_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 4189 and loc.getEndColumn() >= 4189
        ) or 
        (   // id=409, type=WIN-TYPE-1, prop=SuppressedError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 77427 and loc.getEndColumn() >= 77427
        ) or 
        (   // id=421, type=WIN-TYPE-1, prop=_android 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 157458 and loc.getEndColumn() >= 157458
        ) or 
        (   // id=422, type=WIN-TYPE-1, prop=DEBUG 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 70217 and loc.getEndColumn() >= 70217
        ) or 
        (   // id=461, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 17759 and loc.getEndColumn() >= 17759
        ) or 
        (   // id=462, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 17759 and loc.getEndColumn() >= 17759
        ) or 
        (   // id=463, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 17759 and loc.getEndColumn() >= 17759
        ) or 
        (   // id=464, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 17759 and loc.getEndColumn() >= 17759
        ) or 
        (   // id=465, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 16871 and loc.getEndColumn() >= 16871
        ) or 
        (   // id=466, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 27378 and loc.getEndColumn() >= 27378
        ) or 
        (   // id=469, type=WIN-TYPE-1, prop=Geetest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 4602 and loc.getEndColumn() >= 4602
        ) or 
        (   // id=471, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 10482 and loc.getEndColumn() >= 10482
        ) or 
        (   // id=472, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 10513 and loc.getEndColumn() >= 10513
        ) or 
        (   // id=473, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 43625 and loc.getEndColumn() >= 43625
        ) or 
        (   // id=474, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 20558 and loc.getEndColumn() >= 20558
        ) or 
        (   // id=475, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 52690 and loc.getEndColumn() >= 52690
        ) or 
        (   // id=516, type=WIN-TYPE-1, prop=MiniLogin 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 263177 and loc.getEndColumn() >= 263177
        ) or 
        (   // id=517, type=WIN-TYPE-1, prop=miniLogin 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 204 and loc.getEndColumn() >= 204
        ) or 
        (   // id=530, type=WIN-TYPE-1, prop= 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 103611 and loc.getEndColumn() >= 103611
        ) or 
        (   // id=645, type=WIN-TYPE-1, prop=msWriteProfilerMark 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/fingerPrint.chunk.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16836 and loc.getEndColumn() >= 16836
        ) or 
        (   // id=646, type=WIN-TYPE-1, prop=openDatabase 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/fingerPrint.chunk.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 19116 and loc.getEndColumn() >= 19116
        ) or 
        (   // id=655, type=WIN-TYPE-1, prop=ontouchstart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/fingerPrint.chunk.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 27474 and loc.getEndColumn() >= 27474
        ) or 
        (   // id=657, type=WIN-TYPE-1, prop=ontouchstart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/fingerPrint.chunk.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 29771 and loc.getEndColumn() >= 29771
        ) or 
        (   // id=1266, type=WIN-TYPE-1, prop=geetest_1712347373687 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 4250 and loc.getEndColumn() >= 4250
        ) or 
        (   // id=1611, type=WIN-TYPE-1, prop=module 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 57929 and loc.getEndColumn() >= 57929
        ) or 
        (   // id=1618, type=WIN-TYPE-1, prop=_phantom 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 216031 and loc.getEndColumn() >= 216031
        ) or 
        (   // id=1619, type=WIN-TYPE-1, prop=callPhantom 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 216093 and loc.getEndColumn() >= 216093
        ) or 
        (   // id=1620, type=WIN-TYPE-1, prop=__nightmare 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 216291 and loc.getEndColumn() >= 216291
        ) or 
        (   // id=1628, type=WIN-TYPE-1, prop=FAIL 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 236250 and loc.getEndColumn() >= 236250
        ) or 
        (   // id=1629, type=WIN-TYPE-1, prop=pure 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 269075 and loc.getEndColumn() >= 269075
        ) or 
        (   // id=1630, type=WIN-TYPE-1, prop=Geetest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 162071 and loc.getEndColumn() >= 162071
        ) or 
        (   // id=1631, type=WIN-TYPE-1, prop=Geetest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 162326 and loc.getEndColumn() >= 162326
        ) or 
        (   // id=1644, type=WIN-TYPE-1, prop=XDomainRequest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 116436 and loc.getEndColumn() >= 116436
        ) or 
        (   // id=1645, type=WIN-TYPE-1, prop=geetest_1712347368731 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 100725 and loc.getEndColumn() >= 100725
        ) or 
        (   // id=1741, type=WIN-TYPE-1, prop=_phantom 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 163378 and loc.getEndColumn() >= 163378
        ) or 
        (   // id=1742, type=WIN-TYPE-1, prop=callPhantom 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 163378 and loc.getEndColumn() >= 163378
        ) or 
        (   // id=1743, type=WIN-TYPE-1, prop=__nightmare 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 163378 and loc.getEndColumn() >= 163378
        ) or 
        (   // id=1745, type=WIN-TYPE-1, prop=geetest_1712347371305 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 100725 and loc.getEndColumn() >= 100725
        ) or 
        (   // id=1791, type=WIN-TYPE-1, prop=module 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/click.3.1.0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48652 and loc.getEndColumn() >= 48652
        ) or 
        (   // id=1803, type=WIN-TYPE-1, prop=XDomainRequest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/click.3.1.0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 74461 and loc.getEndColumn() >= 74461
        ) or 
        (   // id=1804, type=WIN-TYPE-1, prop=geetest_1712347374080 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/click.3.1.0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 59912 and loc.getEndColumn() >= 59912
        ) or 
        (   // id=1871, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/gct.b71a9027509bc6bcfef9fc6a196424f5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2899 and loc.getEndColumn() >= 2899
        ) or 
        (   // id=1872, type=WIN-TYPE-1, prop=UjhT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/gct.b71a9027509bc6bcfef9fc6a196424f5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2967 and loc.getEndColumn() >= 2967
        ) or 
        (   // id=1873, type=WIN-TYPE-1, prop=_gct 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/gct.b71a9027509bc6bcfef9fc6a196424f5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3090 and loc.getEndColumn() >= 3090
        ) or 
        (   // id=1973, type=WIN-TYPE-1, prop=resposition 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/gct.b71a9027509bc6bcfef9fc6a196424f5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19200 and loc.getEndColumn() >= 19200
        ) or 
        (   // id=1974, type=WIN-TYPE-1, prop=getJSError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/gct.b71a9027509bc6bcfef9fc6a196424f5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11599 and loc.getEndColumn() >= 11599
        ) or 
        (   // id=1992, type=WIN-TYPE-1, prop=geetest_1712347374798 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/click.3.1.0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 59912 and loc.getEndColumn() >= 59912
        ) or 
        (   // id=1997, type=WIN-TYPE-1, prop=geetest_1712347386241 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/click.3.1.0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 59912 and loc.getEndColumn() >= 59912
        ) or 
        (   // id=2110, type=WIN-TYPE-1, prop=geetest_1712347387588 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/click.3.1.0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 59912 and loc.getEndColumn() >= 59912
        ) or 
        (   // id=2152, type=WIN-TYPE-1, prop=JSEncrypt 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.1.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 54847 and loc.getEndColumn() >= 54847
        ) or 
        (   // id=2153, type=WIN-TYPE-1, prop=count 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.1.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 30466 and loc.getEndColumn() >= 30466
        ) or 
        (   // id=2154, type=WIN-TYPE-1, prop=count 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.1.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 30460 and loc.getEndColumn() >= 30460
        ) or 
        (   // id=2956, type=WIN-TYPE-1, prop= 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 10157 and loc.getEndColumn() >= 10157
        ) or 
        (   // id=2964, type=WIN-TYPE-1, prop=SINA_QRCODE_LOGIN 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/qrcode_login.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11071 and loc.getEndColumn() >= 11071
        ) or 
        (   // id=2965, type=WIN-TYPE-1, prop=$Import 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1072 and loc.getEndColumn() >= 1072
        ) or 
        (   // id=2983, type=WIN-TYPE-1, prop=sinaSSOConfig 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 35464 and loc.getEndColumn() >= 35464
        ) or 
        (   // id=3040, type=WIN-TYPE-1, prop=cssArr 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 51819 and loc.getEndColumn() >= 51819
        ) or 
        (   // id=3097, type=WIN-TYPE-1, prop=$CONFIG 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 59426 and loc.getEndColumn() >= 59426
        ) or 
        (   // id=3100, type=WIN-TYPE-1, prop=text 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 42235 and loc.getEndColumn() >= 42235
        ) or 
        (   // id=3136, type=WIN-TYPE-1, prop=webAbTest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 50 and loc.getEndColumn() >= 50
        ) or 
        (   // id=3137, type=WIN-TYPE-1, prop=_BiliGreyResult 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 2986 and loc.getEndColumn() >= 2986
        ) or 
        (   // id=3138, type=WIN-TYPE-1, prop=spmReportData 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 3654 and loc.getEndColumn() >= 3654
        ) or 
        (   // id=3139, type=WIN-TYPE-1, prop=reportConfig 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 3677 and loc.getEndColumn() >= 3677
        ) or 
        (   // id=3140, type=WIN-TYPE-1, prop=__playinfo__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 4018 and loc.getEndColumn() >= 4018
        ) or 
        (   // id=3141, type=WIN-TYPE-1, prop=__INITIAL_STATE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 21368 and loc.getEndColumn() >= 21368
        ) or 
        (   // id=3143, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=3144, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 93 and loc.getEndColumn() >= 93
        ) or 
        (   // id=3146, type=WIN-TYPE-1, prop=nanoWidgetsJsonp 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 190 and loc.getEndLine() = 190 and
            loc.getStartColumn() <= 1809 and loc.getEndColumn() >= 1809
        ) or 
        (   // id=3147, type=WIN-TYPE-1, prop=nanoWidgetsJsonp 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 190 and loc.getEndLine() = 190 and
            loc.getStartColumn() <= 1803 and loc.getEndColumn() >= 1803
        ) or 
        (   // id=3148, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 20 and loc.getEndLine() = 20 and
            loc.getStartColumn() <= 1451 and loc.getEndColumn() >= 1451
        ) or 
        (   // id=3150, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 7322 and loc.getEndColumn() >= 7322
        ) or 
        (   // id=3152, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 7377 and loc.getEndColumn() >= 7377
        ) or 
        (   // id=3153, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 7377 and loc.getEndColumn() >= 7377
        ) or 
        (   // id=3154, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 7377 and loc.getEndColumn() >= 7377
        ) or 
        (   // id=3155, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 7377 and loc.getEndColumn() >= 7377
        ) or 
        (   // id=3156, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 6021 and loc.getEndColumn() >= 6021
        ) or 
        (   // id=3157, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 6051 and loc.getEndColumn() >= 6051
        ) or 
        (   // id=3158, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 1931 and loc.getEndColumn() >= 1931
        ) or 
        (   // id=3159, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 8031 and loc.getEndColumn() >= 8031
        ) or 
        (   // id=3160, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 8048 and loc.getEndColumn() >= 8048
        ) or 
        (   // id=3161, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 8067 and loc.getEndColumn() >= 8067
        ) or 
        (   // id=3162, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 8098 and loc.getEndColumn() >= 8098
        ) or 
        (   // id=3163, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 1247 and loc.getEndColumn() >= 1247
        ) or 
        (   // id=3164, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 7610 and loc.getEndColumn() >= 7610
        ) or 
        (   // id=3165, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 7141 and loc.getEndColumn() >= 7141
        ) or 
        (   // id=3166, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 7141 and loc.getEndColumn() >= 7141
        ) or 
        (   // id=3167, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 7141 and loc.getEndColumn() >= 7141
        ) or 
        (   // id=3168, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 7141 and loc.getEndColumn() >= 7141
        ) or 
        (   // id=3169, type=WIN-TYPE-1, prop=dashjs 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 72 and loc.getEndLine() = 72 and
            loc.getStartColumn() <= 3363 and loc.getEndColumn() >= 3363
        ) or 
        (   // id=3170, type=WIN-TYPE-1, prop=dashjs 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 72 and loc.getEndLine() = 72 and
            loc.getStartColumn() <= 3384 and loc.getEndColumn() >= 3384
        ) or 
        (   // id=3171, type=WIN-TYPE-1, prop=WorkerGlobalScope 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 184 and loc.getEndLine() = 184 and
            loc.getStartColumn() <= 274 and loc.getEndColumn() >= 274
        ) or 
        (   // id=3173, type=WIN-TYPE-1, prop=SharedArrayBuffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 5127 and loc.getEndColumn() >= 5127
        ) or 
        (   // id=3174, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 2406 and loc.getEndColumn() >= 2406
        ) or 
        (   // id=3175, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 187 and loc.getEndLine() = 187 and
            loc.getStartColumn() <= 6205 and loc.getEndColumn() >= 6205
        ) or 
        (   // id=3176, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 189 and loc.getEndLine() = 189 and
            loc.getStartColumn() <= 113 and loc.getEndColumn() >= 113
        ) or 
        (   // id=3177, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 4851 and loc.getEndColumn() >= 4851
        ) or 
        (   // id=3183, type=WIN-TYPE-1, prop=__mobxInstanceCount 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 14 and loc.getEndLine() = 14 and
            loc.getStartColumn() <= 3583 and loc.getEndColumn() >= 3583
        ) or 
        (   // id=3184, type=WIN-TYPE-1, prop=__mobxGlobals 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 14 and loc.getEndLine() = 14 and
            loc.getStartColumn() <= 3634 and loc.getEndColumn() >= 3634
        ) or 
        (   // id=3185, type=WIN-TYPE-1, prop=__mobxGlobals 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 14 and loc.getEndLine() = 14 and
            loc.getStartColumn() <= 3706 and loc.getEndColumn() >= 3706
        ) or 
        (   // id=3186, type=WIN-TYPE-1, prop=__mobxInstanceCount 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 14 and loc.getEndLine() = 14 and
            loc.getStartColumn() <= 3843 and loc.getEndColumn() >= 3843
        ) or 
        (   // id=3187, type=WIN-TYPE-1, prop=__mobxGlobals 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 14 and loc.getEndLine() = 14 and
            loc.getStartColumn() <= 3861 and loc.getEndColumn() >= 3861
        ) or 
        (   // id=3188, type=WIN-TYPE-1, prop=__MOBX_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 18 and loc.getEndLine() = 18 and
            loc.getStartColumn() <= 4815 and loc.getEndColumn() >= 4815
        ) or 
        (   // id=3189, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 27 and loc.getEndLine() = 27 and
            loc.getStartColumn() <= 1235 and loc.getEndColumn() >= 1235
        ) or 
        (   // id=3191, type=WIN-TYPE-1, prop=dcodeIO 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 27 and loc.getEndLine() = 27 and
            loc.getStartColumn() <= 2090 and loc.getEndColumn() >= 2090
        ) or 
        (   // id=3192, type=WIN-TYPE-1, prop=Long 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 27 and loc.getEndLine() = 27 and
            loc.getStartColumn() <= 2131 and loc.getEndColumn() >= 2131
        ) or 
        (   // id=3196, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 94 and loc.getEndLine() = 94 and
            loc.getStartColumn() <= 3750 and loc.getEndColumn() >= 3750
        ) or 
        (   // id=3199, type=WIN-TYPE-1, prop=BwpElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 109 and loc.getEndLine() = 109 and
            loc.getStartColumn() <= 2179 and loc.getEndColumn() >= 2179
        ) or 
        (   // id=3200, type=WIN-TYPE-1, prop=BwpMediaSource 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 109 and loc.getEndLine() = 109 and
            loc.getStartColumn() <= 2204 and loc.getEndColumn() >= 2204
        ) or 
        (   // id=3208, type=WIN-TYPE-1, prop=nano 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 157 and loc.getEndLine() = 157 and
            loc.getStartColumn() <= 1408 and loc.getEndColumn() >= 1408
        ) or 
        (   // id=3209, type=WIN-TYPE-1, prop=nano 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 157 and loc.getEndLine() = 157 and
            loc.getStartColumn() <= 1530 and loc.getEndColumn() >= 1530
        ) or 
        (   // id=3213, type=WIN-TYPE-1, prop=hasBlackSide 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 55453 and loc.getEndColumn() >= 55453
        ) or 
        (   // id=3214, type=WIN-TYPE-1, prop=isWide 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 55845 and loc.getEndColumn() >= 55845
        ) or 
        (   // id=3216, type=WIN-TYPE-1, prop=isWide 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 56094 and loc.getEndColumn() >= 56094
        ) or 
        (   // id=3217, type=WIN-TYPE-1, prop=PlayerAgent 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 56917 and loc.getEndColumn() >= 56917
        ) or 
        (   // id=3218, type=WIN-TYPE-1, prop=__MIRROR_CONFIG__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=3219, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=3220, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 69 and loc.getEndColumn() >= 69
        ) or 
        (   // id=3221, type=WIN-TYPE-1, prop=biliMirror 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 206 and loc.getEndColumn() >= 206
        ) or 
        (   // id=3222, type=WIN-TYPE-1, prop=SuppressedError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 536 and loc.getEndColumn() >= 536
        ) or 
        (   // id=3225, type=WIN-TYPE-1, prop=__biliMirror__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 752 and loc.getEndColumn() >= 752
        ) or 
        (   // id=3226, type=WIN-TYPE-1, prop=__biliMirror__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 749 and loc.getEndColumn() >= 749
        ) or 
        (   // id=3229, type=WIN-TYPE-1, prop=selfBrowser 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 1792 and loc.getEndColumn() >= 1792
        ) or 
        (   // id=3230, type=WIN-TYPE-1, prop=selfBrowser 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 1820 and loc.getEndColumn() >= 1820
        ) or 
        (   // id=3231, type=WIN-TYPE-1, prop=BiliJsBridge 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 2770 and loc.getEndColumn() >= 2770
        ) or 
        (   // id=3232, type=WIN-TYPE-1, prop=BiliJsBridge 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 2800 and loc.getEndColumn() >= 2800
        ) or 
        (   // id=3239, type=WIN-TYPE-1, prop=__INITIAL_MIRROR__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 26612 and loc.getEndColumn() >= 26612
        ) or 
        (   // id=3240, type=WIN-TYPE-1, prop=__MIRROR_REPORT__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 26640 and loc.getEndColumn() >= 26640
        ) or 
        (   // id=3241, type=WIN-TYPE-1, prop=KvSDK 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4183 and loc.getEndColumn() >= 4183
        ) or 
        (   // id=3242, type=WIN-TYPE-1, prop=__BILI_X_ENGINE_SCRIPT_CACHE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3304 and loc.getEndColumn() >= 3304
        ) or 
        (   // id=3245, type=WIN-TYPE-1, prop=__BILI_X_ENGINE_SCRIPT_CACHE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3839 and loc.getEndColumn() >= 3839
        ) or 
        (   // id=3246, type=WIN-TYPE-1, prop=__BILI_X_ENGINE_SCRIPT_CACHE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3909 and loc.getEndColumn() >= 3909
        ) or 
        (   // id=3247, type=WIN-TYPE-1, prop=NanoInitStage 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 28 and loc.getEndLine() = 28 and
            loc.getStartColumn() <= 20 and loc.getEndColumn() >= 20
        ) or 
        (   // id=3248, type=WIN-TYPE-1, prop=NanoInitStage 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 29 and loc.getEndLine() = 29 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=3255, type=WIN-TYPE-1, prop=player 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 137 and loc.getEndLine() = 137 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=3259, type=WIN-TYPE-1, prop=abtest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 292 and loc.getEndLine() = 292 and
            loc.getStartColumn() <= 1266 and loc.getEndColumn() >= 1266
        ) or 
        (   // id=3260, type=WIN-TYPE-1, prop=webpackChunkwebpackLogReporter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 120956 and loc.getEndColumn() >= 120956
        ) or 
        (   // id=3261, type=WIN-TYPE-1, prop=webpackChunkwebpackLogReporter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 120950 and loc.getEndColumn() >= 120950
        ) or 
        (   // id=3282, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 86566 and loc.getEndColumn() >= 86566
        ) or 
        (   // id=3283, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 86578 and loc.getEndColumn() >= 86578
        ) or 
        (   // id=3286, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 86324 and loc.getEndColumn() >= 86324
        ) or 
        (   // id=3287, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 105856 and loc.getEndColumn() >= 105856
        ) or 
        (   // id=3288, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 105873 and loc.getEndColumn() >= 105873
        ) or 
        (   // id=3289, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 105892 and loc.getEndColumn() >= 105892
        ) or 
        (   // id=3290, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 105904 and loc.getEndColumn() >= 105904
        ) or 
        (   // id=3291, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 97718 and loc.getEndColumn() >= 97718
        ) or 
        (   // id=3292, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 85974 and loc.getEndColumn() >= 85974
        ) or 
        (   // id=3293, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 112504 and loc.getEndColumn() >= 112504
        ) or 
        (   // id=3296, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 117070 and loc.getEndColumn() >= 117070
        ) or 
        (   // id=3297, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 117070 and loc.getEndColumn() >= 117070
        ) or 
        (   // id=3298, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 117070 and loc.getEndColumn() >= 117070
        ) or 
        (   // id=3299, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 117070 and loc.getEndColumn() >= 117070
        ) or 
        (   // id=3302, type=WIN-TYPE-1, prop=reportObserver 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 128134 and loc.getEndColumn() >= 128134
        ) or 
        (   // id=3303, type=WIN-TYPE-1, prop=bsourceFrom 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 17107 and loc.getEndColumn() >= 17107
        ) or 
        (   // id=3305, type=WIN-TYPE-1, prop=uaSource 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 125257 and loc.getEndColumn() >= 125257
        ) or 
        (   // id=3306, type=WIN-TYPE-1, prop=bsource 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 124458 and loc.getEndColumn() >= 124458
        ) or 
        (   // id=3324, type=WIN-TYPE-1, prop=reportObserver 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 128309 and loc.getEndColumn() >= 128309
        ) or 
        (   // id=3325, type=WIN-TYPE-1, prop=webpackLogReporter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 128407 and loc.getEndColumn() >= 128407
        ) or 
        (   // id=3328, type=WIN-TYPE-1, prop=loginInfoCallbacks 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 292 and loc.getEndLine() = 292 and
            loc.getStartColumn() <= 2204 and loc.getEndColumn() >= 2204
        ) or 
        (   // id=3329, type=WIN-TYPE-1, prop=onLoginInfoLoaded 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 292 and loc.getEndLine() = 292 and
            loc.getStartColumn() <= 2232 and loc.getEndColumn() >= 2232
        ) or 
        (   // id=3335, type=WIN-TYPE-1, prop=__USER_FP_CONFIG__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 292 and loc.getEndLine() = 292 and
            loc.getStartColumn() <= 4568 and loc.getEndColumn() >= 4568
        ) or 
        (   // id=3336, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=3337, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 80 and loc.getEndColumn() >= 80
        ) or 
        (   // id=3338, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 123 and loc.getEndColumn() >= 123
        ) or 
        (   // id=3340, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6799 and loc.getEndColumn() >= 6799
        ) or 
        (   // id=3341, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6811 and loc.getEndColumn() >= 6811
        ) or 
        (   // id=3343, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6584 and loc.getEndColumn() >= 6584
        ) or 
        (   // id=3345, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 27792 and loc.getEndColumn() >= 27792
        ) or 
        (   // id=3346, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 27809 and loc.getEndColumn() >= 27809
        ) or 
        (   // id=3347, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 27828 and loc.getEndColumn() >= 27828
        ) or 
        (   // id=3348, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 27840 and loc.getEndColumn() >= 27840
        ) or 
        (   // id=3349, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16556 and loc.getEndColumn() >= 16556
        ) or 
        (   // id=3350, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6250 and loc.getEndColumn() >= 6250
        ) or 
        (   // id=3351, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 35312 and loc.getEndColumn() >= 35312
        ) or 
        (   // id=3353, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 41808 and loc.getEndColumn() >= 41808
        ) or 
        (   // id=3355, type=WIN-TYPE-1, prop=_loadConfigPromise_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 61000 and loc.getEndColumn() >= 61000
        ) or 
        (   // id=3356, type=WIN-TYPE-1, prop=_loadConfigPromise_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 60992 and loc.getEndColumn() >= 60992
        ) or 
        (   // id=3357, type=WIN-TYPE-1, prop=_loadLogicPromise_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 61059 and loc.getEndColumn() >= 61059
        ) or 
        (   // id=3358, type=WIN-TYPE-1, prop=_loadLogicPromise_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 61051 and loc.getEndColumn() >= 61051
        ) or 
        (   // id=3359, type=WIN-TYPE-1, prop=CaptchaLoader 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 202 and loc.getEndColumn() >= 202
        ) or 
        (   // id=3360, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/user-fingerprint/bili-user-fingerprint.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6101 and loc.getEndColumn() >= 6101
        ) or 
        (   // id=3361, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/user-fingerprint/bili-user-fingerprint.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6191 and loc.getEndColumn() >= 6191
        ) or 
        (   // id=3362, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/user-fingerprint/bili-user-fingerprint.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6277 and loc.getEndColumn() >= 6277
        ) or 
        (   // id=3367, type=WIN-TYPE-1, prop=__biliUserFp__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/user-fingerprint/bili-user-fingerprint.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6375 and loc.getEndColumn() >= 6375
        ) or 
        (   // id=3369, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/kv-sdk/index.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1564 and loc.getEndColumn() >= 1564
        ) or 
        (   // id=3370, type=WIN-TYPE-1, prop=_KV_CORE_CACHE_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/kv-sdk/index.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2057 and loc.getEndColumn() >= 2057
        ) or 
        (   // id=3371, type=WIN-TYPE-1, prop=_KV_CORE_CACHE_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/kv-sdk/index.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2097 and loc.getEndColumn() >= 2097
        ) or 
        (   // id=3373, type=WIN-TYPE-1, prop=_KV_CORE_REQUEST_QUEUE_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/kv-sdk/index.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4040 and loc.getEndColumn() >= 4040
        ) or 
        (   // id=3374, type=WIN-TYPE-1, prop=_KV_CORE_REQUEST_QUEUE_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/kv-sdk/index.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4037 and loc.getEndColumn() >= 4037
        ) or 
        (   // id=3375, type=WIN-TYPE-1, prop=ReporterPb 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/kv-sdk/index.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5230 and loc.getEndColumn() >= 5230
        ) or 
        (   // id=3382, type=WIN-TYPE-1, prop=onScrollTrackerLoaded 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 125539 and loc.getEndColumn() >= 125539
        ) or 
        (   // id=3383, type=WIN-TYPE-1, prop=msWriteProfilerMark 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 53237 and loc.getEndColumn() >= 53237
        ) or 
        (   // id=3384, type=WIN-TYPE-1, prop=openDatabase 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 55331 and loc.getEndColumn() >= 55331
        ) or 
        (   // id=3393, type=WIN-TYPE-1, prop=ontouchstart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 50885 and loc.getEndColumn() >= 50885
        ) or 
        (   // id=3395, type=WIN-TYPE-1, prop=ontouchstart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 44362 and loc.getEndColumn() >= 44362
        ) or 
        (   // id=3413, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16 and loc.getEndColumn() >= 16
        ) or 
        (   // id=3414, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 80 and loc.getEndColumn() >= 80
        ) or 
        (   // id=3415, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 123 and loc.getEndColumn() >= 123
        ) or 
        (   // id=3416, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 158209 and loc.getEndColumn() >= 158209
        ) or 
        (   // id=3419, type=WIN-TYPE-1, prop=loadReportPbChunk 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 159480 and loc.getEndColumn() >= 159480
        ) or 
        (   // id=3420, type=WIN-TYPE-1, prop=loadReportPbChunk 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 159474 and loc.getEndColumn() >= 159474
        ) or 
        (   // id=3422, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 98717 and loc.getEndColumn() >= 98717
        ) or 
        (   // id=3423, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 98729 and loc.getEndColumn() >= 98729
        ) or 
        (   // id=3426, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 98437 and loc.getEndColumn() >= 98437
        ) or 
        (   // id=3427, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 124767 and loc.getEndColumn() >= 124767
        ) or 
        (   // id=3428, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 124784 and loc.getEndColumn() >= 124784
        ) or 
        (   // id=3429, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 124803 and loc.getEndColumn() >= 124803
        ) or 
        (   // id=3430, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 124815 and loc.getEndColumn() >= 124815
        ) or 
        (   // id=3431, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 111587 and loc.getEndColumn() >= 111587
        ) or 
        (   // id=3432, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 98139 and loc.getEndColumn() >= 98139
        ) or 
        (   // id=3433, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 140478 and loc.getEndColumn() >= 140478
        ) or 
        (   // id=3436, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 155204 and loc.getEndColumn() >= 155204
        ) or 
        (   // id=3437, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 155204 and loc.getEndColumn() >= 155204
        ) or 
        (   // id=3438, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 155204 and loc.getEndColumn() >= 155204
        ) or 
        (   // id=3439, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 155204 and loc.getEndColumn() >= 155204
        ) or 
        (   // id=3440, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153515 and loc.getEndColumn() >= 153515
        ) or 
        (   // id=3441, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153545 and loc.getEndColumn() >= 153545
        ) or 
        (   // id=3442, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 149472 and loc.getEndColumn() >= 149472
        ) or 
        (   // id=3443, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 86446 and loc.getEndColumn() >= 86446
        ) or 
        (   // id=3444, type=WIN-TYPE-1, prop=Zepto 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 86456 and loc.getEndColumn() >= 86456
        ) or 
        (   // id=3445, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 64754 and loc.getEndColumn() >= 64754
        ) or 
        (   // id=3447, type=WIN-TYPE-1, prop=dcodeIO 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 65793 and loc.getEndColumn() >= 65793
        ) or 
        (   // id=3448, type=WIN-TYPE-1, prop=Long 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 65834 and loc.getEndColumn() >= 65834
        ) or 
        (   // id=3450, type=WIN-TYPE-1, prop=ReporterPb 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 196 and loc.getEndColumn() >= 196
        ) or 
        (   // id=3460, type=WIN-TYPE-1, prop=__biliMirrorPbInstance__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 10291 and loc.getEndColumn() >= 10291
        ) or 
        (   // id=3465, type=WIN-TYPE-1, prop=__ReporterPbGlobalState 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 249871 and loc.getEndColumn() >= 249871
        ) or 
        (   // id=3468, type=WIN-TYPE-1, prop=__ReporterPbGlobalState 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 249970 and loc.getEndColumn() >= 249970
        ) or 
        (   // id=3469, type=WIN-TYPE-1, prop=__biliMirrorPbInstance__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 10439 and loc.getEndColumn() >= 10439
        ) or 
        (   // id=3504, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 543 and loc.getEndColumn() >= 543
        ) or 
        (   // id=3505, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 730 and loc.getEndColumn() >= 730
        ) or 
        (   // id=3506, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 12863 and loc.getEndColumn() >= 12863
        ) or 
        (   // id=3507, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 12863 and loc.getEndColumn() >= 12863
        ) or 
        (   // id=3508, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 12863 and loc.getEndColumn() >= 12863
        ) or 
        (   // id=3509, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 12863 and loc.getEndColumn() >= 12863
        ) or 
        (   // id=3510, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13955 and loc.getEndColumn() >= 13955
        ) or 
        (   // id=3512, type=WIN-TYPE-1, prop=BiliCm 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19065 and loc.getEndColumn() >= 19065
        ) or 
        (   // id=3513, type=WIN-TYPE-1, prop=bilicm 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19116 and loc.getEndColumn() >= 19116
        ) or 
        (   // id=3514, type=WIN-TYPE-1, prop=BiliCm 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19102 and loc.getEndColumn() >= 19102
        ) or 
        (   // id=3515, type=WIN-TYPE-1, prop=ad_rp 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/cm/cm-sdk/static/js/bili-collect.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19133 and loc.getEndColumn() >= 19133
        ) or 
        (   // id=3516, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1020 and loc.getEndColumn() >= 1020
        ) or 
        (   // id=3517, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1052 and loc.getEndColumn() >= 1052
        ) or 
        (   // id=3518, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 100654 and loc.getEndColumn() >= 100654
        ) or 
        (   // id=3519, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 161151 and loc.getEndColumn() >= 161151
        ) or 
        (   // id=3520, type=WIN-TYPE-1, prop=core 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7059 and loc.getEndColumn() >= 7059
        ) or 
        (   // id=3521, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 75954 and loc.getEndColumn() >= 75954
        ) or 
        (   // id=3523, type=WIN-TYPE-1, prop=[object Object] 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6807 and loc.getEndColumn() >= 6807
        ) or 
        (   // id=3525, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 8291 and loc.getEndColumn() >= 8291
        ) or 
        (   // id=3526, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 8303 and loc.getEndColumn() >= 8303
        ) or 
        (   // id=3527, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 8320 and loc.getEndColumn() >= 8320
        ) or 
        (   // id=3528, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 8358 and loc.getEndColumn() >= 8358
        ) or 
        (   // id=3529, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 9265 and loc.getEndColumn() >= 9265
        ) or 
        (   // id=3531, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 100744 and loc.getEndColumn() >= 100744
        ) or 
        (   // id=3532, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 481638 and loc.getEndColumn() >= 481638
        ) or 
        (   // id=3533, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 481668 and loc.getEndColumn() >= 481668
        ) or 
        (   // id=3534, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6923 and loc.getEndColumn() >= 6923
        ) or 
        (   // id=3535, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156921 and loc.getEndColumn() >= 156921
        ) or 
        (   // id=3536, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156992 and loc.getEndColumn() >= 156992
        ) or 
        (   // id=3537, type=WIN-TYPE-1, prop=System 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6790 and loc.getEndColumn() >= 6790
        ) or 
        (   // id=3538, type=WIN-TYPE-1, prop=System 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6800 and loc.getEndColumn() >= 6800
        ) or 
        (   // id=3540, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 115922 and loc.getEndColumn() >= 115922
        ) or 
        (   // id=3541, type=WIN-TYPE-1, prop=asap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6923 and loc.getEndColumn() >= 6923
        ) or 
        (   // id=3542, type=WIN-TYPE-1, prop=asap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156921 and loc.getEndColumn() >= 156921
        ) or 
        (   // id=3543, type=WIN-TYPE-1, prop=asap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156950 and loc.getEndColumn() >= 156950
        ) or 
        (   // id=3544, type=WIN-TYPE-1, prop=asap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156992 and loc.getEndColumn() >= 156992
        ) or 
        (   // id=3546, type=WIN-TYPE-1, prop=Observable 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6923 and loc.getEndColumn() >= 6923
        ) or 
        (   // id=3547, type=WIN-TYPE-1, prop=Observable 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156921 and loc.getEndColumn() >= 156921
        ) or 
        (   // id=3548, type=WIN-TYPE-1, prop=Observable 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156950 and loc.getEndColumn() >= 156950
        ) or 
        (   // id=3549, type=WIN-TYPE-1, prop=Observable 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156992 and loc.getEndColumn() >= 156992
        ) or 
        (   // id=3550, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6923 and loc.getEndColumn() >= 6923
        ) or 
        (   // id=3551, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156921 and loc.getEndColumn() >= 156921
        ) or 
        (   // id=3552, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156950 and loc.getEndColumn() >= 156950
        ) or 
        (   // id=3553, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156992 and loc.getEndColumn() >= 156992
        ) or 
        (   // id=3554, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6923 and loc.getEndColumn() >= 6923
        ) or 
        (   // id=3555, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156921 and loc.getEndColumn() >= 156921
        ) or 
        (   // id=3556, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156950 and loc.getEndColumn() >= 156950
        ) or 
        (   // id=3557, type=WIN-TYPE-1, prop=clearImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 156992 and loc.getEndColumn() >= 156992
        ) or 
        (   // id=3558, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 119271 and loc.getEndColumn() >= 119271
        ) or 
        (   // id=3559, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 119271 and loc.getEndColumn() >= 119271
        ) or 
        (   // id=3560, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 119271 and loc.getEndColumn() >= 119271
        ) or 
        (   // id=3561, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 119271 and loc.getEndColumn() >= 119271
        ) or 
        (   // id=3562, type=WIN-TYPE-1, prop=_babelPolyfill 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 73282 and loc.getEndColumn() >= 73282
        ) or 
        (   // id=3563, type=WIN-TYPE-1, prop=_babelPolyfill 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 73379 and loc.getEndColumn() >= 73379
        ) or 
        (   // id=3564, type=WIN-TYPE-1, prop=WXEnvironment 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 3432 and loc.getEndColumn() >= 3432
        ) or 
        (   // id=3565, type=WIN-TYPE-1, prop=__VUE_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 4098 and loc.getEndColumn() >= 4098
        ) or 
        (   // id=3569, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 134064 and loc.getEndColumn() >= 134064
        ) or 
        (   // id=3573, type=WIN-TYPE-1, prop=SuppressedError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 104333 and loc.getEndColumn() >= 104333
        ) or 
        (   // id=3586, type=WIN-TYPE-1, prop=TYPED_ARRAY_SUPPORT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 184 and loc.getEndLine() = 184 and
            loc.getStartColumn() <= 6171 and loc.getEndColumn() >= 6171
        ) or 
        (   // id=3587, type=WIN-TYPE-1, prop=WXEnvironment 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 98 and loc.getEndLine() = 98 and
            loc.getStartColumn() <= 3493 and loc.getEndColumn() >= 3493
        ) or 
        (   // id=3588, type=WIN-TYPE-1, prop=__VUE_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 98 and loc.getEndLine() = 98 and
            loc.getStartColumn() <= 4195 and loc.getEndColumn() >= 4195
        ) or 
        (   // id=3590, type=WIN-TYPE-1, prop=Vue 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 98 and loc.getEndLine() = 98 and
            loc.getStartColumn() <= 75528 and loc.getEndColumn() >= 75528
        ) or 
        (   // id=3592, type=WIN-TYPE-1, prop=SharedArrayBuffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 98 and loc.getEndLine() = 98 and
            loc.getStartColumn() <= 99841 and loc.getEndColumn() >= 99841
        ) or 
        (   // id=3608, type=WIN-TYPE-1, prop=Geetest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 5297 and loc.getEndColumn() >= 5297
        ) or 
        (   // id=3609, type=WIN-TYPE-1, prop=initGeetest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 5948 and loc.getEndColumn() >= 5948
        ) or 
        (   // id=3626, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 33469 and loc.getEndColumn() >= 33469
        ) or 
        (   // id=3628, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 63977 and loc.getEndColumn() >= 63977
        ) or 
        (   // id=3629, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 32503 and loc.getEndColumn() >= 32503
        ) or 
        (   // id=3630, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 32534 and loc.getEndColumn() >= 32534
        ) or 
        (   // id=3631, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 361113 and loc.getEndColumn() >= 361113
        ) or 
        (   // id=3632, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 383850 and loc.getEndColumn() >= 383850
        ) or 
        (   // id=3634, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 26655 and loc.getEndColumn() >= 26655
        ) or 
        (   // id=3635, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 26655 and loc.getEndColumn() >= 26655
        ) or 
        (   // id=3636, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 26655 and loc.getEndColumn() >= 26655
        ) or 
        (   // id=3637, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 26655 and loc.getEndColumn() >= 26655
        ) or 
        (   // id=3640, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 228375 and loc.getEndColumn() >= 228375
        ) or 
        (   // id=3642, type=WIN-TYPE-1, prop=dcodeIO 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 229435 and loc.getEndColumn() >= 229435
        ) or 
        (   // id=3643, type=WIN-TYPE-1, prop=Long 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 229476 and loc.getEndColumn() >= 229476
        ) or 
        (   // id=3654, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 9403 and loc.getEndColumn() >= 9403
        ) or 
        (   // id=3659, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 58634 and loc.getEndColumn() >= 58634
        ) or 
        (   // id=3660, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 139078 and loc.getEndColumn() >= 139078
        ) or 
        (   // id=3661, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 139078 and loc.getEndColumn() >= 139078
        ) or 
        (   // id=3662, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 139078 and loc.getEndColumn() >= 139078
        ) or 
        (   // id=3663, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 139078 and loc.getEndColumn() >= 139078
        ) or 
        (   // id=3665, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 352182 and loc.getEndColumn() >= 352182
        ) or 
        (   // id=3666, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 377436 and loc.getEndColumn() >= 377436
        ) or 
        (   // id=3667, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 377436 and loc.getEndColumn() >= 377436
        ) or 
        (   // id=3668, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 377436 and loc.getEndColumn() >= 377436
        ) or 
        (   // id=3669, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 377436 and loc.getEndColumn() >= 377436
        ) or 
        (   // id=3672, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 18413 and loc.getEndColumn() >= 18413
        ) or 
        (   // id=3673, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 18466 and loc.getEndColumn() >= 18466
        ) or 
        (   // id=3674, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 32348 and loc.getEndColumn() >= 32348
        ) or 
        (   // id=3675, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 32348 and loc.getEndColumn() >= 32348
        ) or 
        (   // id=3676, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 32348 and loc.getEndColumn() >= 32348
        ) or 
        (   // id=3677, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 32348 and loc.getEndColumn() >= 32348
        ) or 
        (   // id=3679, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 39583 and loc.getEndColumn() >= 39583
        ) or 
        (   // id=3680, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 39614 and loc.getEndColumn() >= 39614
        ) or 
        (   // id=3681, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 36252 and loc.getEndColumn() >= 36252
        ) or 
        (   // id=3682, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 20994 and loc.getEndColumn() >= 20994
        ) or 
        (   // id=3684, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 9411 and loc.getEndColumn() >= 9411
        ) or 
        (   // id=3685, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 28683 and loc.getEndColumn() >= 28683
        ) or 
        (   // id=3686, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 28683 and loc.getEndColumn() >= 28683
        ) or 
        (   // id=3687, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 28683 and loc.getEndColumn() >= 28683
        ) or 
        (   // id=3688, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 28683 and loc.getEndColumn() >= 28683
        ) or 
        (   // id=3689, type=WIN-TYPE-1, prop=@bplus-common/icon-font@2.1.2 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 38549 and loc.getEndColumn() >= 38549
        ) or 
        (   // id=3692, type=WIN-TYPE-1, prop=@bplus-common/icon-font@2.1.2 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 38676 and loc.getEndColumn() >= 38676
        ) or 
        (   // id=3693, type=WIN-TYPE-1, prop=DEBUG 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 14493 and loc.getEndColumn() >= 14493
        ) or 
        (   // id=3706, type=WIN-TYPE-1, prop=__BiliUser__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 215866 and loc.getEndColumn() >= 215866
        ) or 
        (   // id=3708, type=WIN-TYPE-1, prop=__BiliUser__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 216046 and loc.getEndColumn() >= 216046
        ) or 
        (   // id=3709, type=WIN-TYPE-1, prop=__BiliUserWatch__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 212158 and loc.getEndColumn() >= 212158
        ) or 
        (   // id=3710, type=WIN-TYPE-1, prop=__BiliUser__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 216110 and loc.getEndColumn() >= 216110
        ) or 
        (   // id=3715, type=WIN-TYPE-1, prop=SharedArrayBuffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 31328 and loc.getEndColumn() >= 31328
        ) or 
        (   // id=3721, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 36240 and loc.getEndColumn() >= 36240
        ) or 
        (   // id=3722, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 22536 and loc.getEndColumn() >= 22536
        ) or 
        (   // id=3723, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 10408 and loc.getEndColumn() >= 10408
        ) or 
        (   // id=3724, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 10439 and loc.getEndColumn() >= 10439
        ) or 
        (   // id=3725, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 66 and loc.getEndLine() = 66 and
            loc.getStartColumn() <= 4310 and loc.getEndColumn() >= 4310
        ) or 
        (   // id=3726, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 19150 and loc.getEndColumn() >= 19150
        ) or 
        (   // id=3728, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 5418 and loc.getEndColumn() >= 5418
        ) or 
        (   // id=3729, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 5418 and loc.getEndColumn() >= 5418
        ) or 
        (   // id=3730, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 5418 and loc.getEndColumn() >= 5418
        ) or 
        (   // id=3731, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 59 and loc.getEndLine() = 59 and
            loc.getStartColumn() <= 5418 and loc.getEndColumn() >= 5418
        ) or 
        (   // id=3733, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 2383 and loc.getEndColumn() >= 2383
        ) or 
        (   // id=3735, type=WIN-TYPE-1, prop=BiliAjax 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 15756 and loc.getEndColumn() >= 15756
        ) or 
        (   // id=3741, type=WIN-TYPE-1, prop=ontouchstart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 3477 and loc.getEndColumn() >= 3477
        ) or 
        (   // id=3742, type=WIN-TYPE-1, prop=DocumentTouch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 3567 and loc.getEndColumn() >= 3567
        ) or 
        (   // id=3759, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 43644 and loc.getEndColumn() >= 43644
        ) or 
        (   // id=3760, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 44637 and loc.getEndColumn() >= 44637
        ) or 
        (   // id=3761, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 45719 and loc.getEndColumn() >= 45719
        ) or 
        (   // id=3762, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 45943 and loc.getEndColumn() >= 45943
        ) or 
        (   // id=3763, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 47486 and loc.getEndColumn() >= 47486
        ) or 
        (   // id=3764, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 49699 and loc.getEndColumn() >= 49699
        ) or 
        (   // id=3765, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 50690 and loc.getEndColumn() >= 50690
        ) or 
        (   // id=3767, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 9126 and loc.getEndColumn() >= 9126
        ) or 
        (   // id=3768, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 9138 and loc.getEndColumn() >= 9138
        ) or 
        (   // id=3770, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 33426 and loc.getEndColumn() >= 33426
        ) or 
        (   // id=3771, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 34417 and loc.getEndColumn() >= 34417
        ) or 
        (   // id=3772, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 42332 and loc.getEndColumn() >= 42332
        ) or 
        (   // id=3773, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 43323 and loc.getEndColumn() >= 43323
        ) or 
        (   // id=3774, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 44406 and loc.getEndColumn() >= 44406
        ) or 
        (   // id=3775, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 44633 and loc.getEndColumn() >= 44633
        ) or 
        (   // id=3776, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 46187 and loc.getEndColumn() >= 46187
        ) or 
        (   // id=3777, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 48367 and loc.getEndColumn() >= 48367
        ) or 
        (   // id=3778, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 49363 and loc.getEndColumn() >= 49363
        ) or 
        (   // id=3779, type=WIN-TYPE-1, prop=__BMG_TRACKER_COLLECT_EXTS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 35550 and loc.getEndColumn() >= 35550
        ) or 
        (   // id=3780, type=WIN-TYPE-1, prop=__BMG_TRACKER_COLLECT_EXTS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 35687 and loc.getEndColumn() >= 35687
        ) or 
        (   // id=3781, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 60923 and loc.getEndColumn() >= 60923
        ) or 
        (   // id=3782, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 61914 and loc.getEndColumn() >= 61914
        ) or 
        (   // id=3783, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 155820 and loc.getEndColumn() >= 155820
        ) or 
        (   // id=3784, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 155633 and loc.getEndColumn() >= 155633
        ) or 
        (   // id=3785, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 6580 and loc.getEndColumn() >= 6580
        ) or 
        (   // id=3786, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 6580 and loc.getEndColumn() >= 6580
        ) or 
        (   // id=3787, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 6580 and loc.getEndColumn() >= 6580
        ) or 
        (   // id=3788, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 6580 and loc.getEndColumn() >= 6580
        ) or 
        (   // id=3791, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 7188 and loc.getEndColumn() >= 7188
        ) or 
        (   // id=3792, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 7255 and loc.getEndColumn() >= 7255
        ) or 
        (   // id=3793, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 186 and loc.getEndLine() = 186 and
            loc.getStartColumn() <= 8413 and loc.getEndColumn() >= 8413
        ) or 
        (   // id=3795, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 186 and loc.getEndLine() = 186 and
            loc.getStartColumn() <= 3937 and loc.getEndColumn() >= 3937
        ) or 
        (   // id=3797, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 186 and loc.getEndLine() = 186 and
            loc.getStartColumn() <= 11251 and loc.getEndColumn() >= 11251
        ) or 
        (   // id=3804, type=WIN-TYPE-1, prop=Vue 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 11341 and loc.getEndColumn() >= 11341
        ) or 
        (   // id=3805, type=WIN-TYPE-1, prop=__VUE_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 46 and loc.getEndColumn() >= 46
        ) or 
        (   // id=3806, type=WIN-TYPE-1, prop=SharedArrayBuffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 74373 and loc.getEndColumn() >= 74373
        ) or 
        (   // id=3807, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 34806 and loc.getEndColumn() >= 34806
        ) or 
        (   // id=3809, type=WIN-TYPE-1, prop=dcodeIO 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 35671 and loc.getEndColumn() >= 35671
        ) or 
        (   // id=3810, type=WIN-TYPE-1, prop=Long 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 35712 and loc.getEndColumn() >= 35712
        ) or 
        (   // id=3819, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 73117 and loc.getEndColumn() >= 73117
        ) or 
        (   // id=3820, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 73278 and loc.getEndColumn() >= 73278
        ) or 
        (   // id=3821, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 84401 and loc.getEndColumn() >= 84401
        ) or 
        (   // id=3822, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 84401 and loc.getEndColumn() >= 84401
        ) or 
        (   // id=3823, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 84401 and loc.getEndColumn() >= 84401
        ) or 
        (   // id=3824, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 84401 and loc.getEndColumn() >= 84401
        ) or 
        (   // id=3825, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 86824 and loc.getEndColumn() >= 86824
        ) or 
        (   // id=3829, type=WIN-TYPE-1, prop=SuppressedError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 203353 and loc.getEndColumn() >= 203353
        ) or 
        (   // id=3846, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 204997 and loc.getEndColumn() >= 204997
        ) or 
        (   // id=3847, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 205009 and loc.getEndColumn() >= 205009
        ) or 
        (   // id=3852, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 173825 and loc.getEndColumn() >= 173825
        ) or 
        (   // id=3853, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 177552 and loc.getEndColumn() >= 177552
        ) or 
        (   // id=3854, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 177552 and loc.getEndColumn() >= 177552
        ) or 
        (   // id=3855, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 177552 and loc.getEndColumn() >= 177552
        ) or 
        (   // id=3856, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 177552 and loc.getEndColumn() >= 177552
        ) or 
        (   // id=3857, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 254469 and loc.getEndColumn() >= 254469
        ) or 
        (   // id=3858, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 204055 and loc.getEndColumn() >= 204055
        ) or 
        (   // id=3859, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 204067 and loc.getEndColumn() >= 204067
        ) or 
        (   // id=3860, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 220 and loc.getEndLine() = 220 and
            loc.getStartColumn() <= 91055 and loc.getEndColumn() >= 91055
        ) or 
        (   // id=3861, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 264947 and loc.getEndColumn() >= 264947
        ) or 
        (   // id=3862, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 251586 and loc.getEndColumn() >= 251586
        ) or 
        (   // id=3864, type=WIN-TYPE-1, prop=DEBUG 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 57932 and loc.getEndColumn() >= 57932
        ) or 
        (   // id=3872, type=WIN-TYPE-1, prop=SharedArrayBuffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 3507 and loc.getEndColumn() >= 3507
        ) or 
        (   // id=3874, type=WIN-TYPE-1, prop=Bjax 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 146256 and loc.getEndColumn() >= 146256
        ) or 
        (   // id=3875, type=WIN-TYPE-1, prop=TYPED_ARRAY_SUPPORT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 6198 and loc.getEndColumn() >= 6198
        ) or 
        (   // id=3878, type=WIN-TYPE-1, prop=SharedArrayBuffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 150532 and loc.getEndColumn() >= 150532
        ) or 
        (   // id=3879, type=WIN-TYPE-1, prop=SharedArrayBuffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 150621 and loc.getEndColumn() >= 150621
        ) or 
        (   // id=3884, type=WIN-TYPE-1, prop=hljs 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 209687 and loc.getEndColumn() >= 209687
        ) or 
        (   // id=3885, type=WIN-TYPE-1, prop=opera 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 187207 and loc.getEndColumn() >= 187207
        ) or 
        (   // id=3886, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 176067 and loc.getEndColumn() >= 176067
        ) or 
        (   // id=3887, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 177058 and loc.getEndColumn() >= 177058
        ) or 
        (   // id=3888, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 184816 and loc.getEndColumn() >= 184816
        ) or 
        (   // id=3889, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 185807 and loc.getEndColumn() >= 185807
        ) or 
        (   // id=3890, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 186889 and loc.getEndColumn() >= 186889
        ) or 
        (   // id=3891, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 187115 and loc.getEndColumn() >= 187115
        ) or 
        (   // id=3892, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 188669 and loc.getEndColumn() >= 188669
        ) or 
        (   // id=3893, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 190849 and loc.getEndColumn() >= 190849
        ) or 
        (   // id=3894, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 191845 and loc.getEndColumn() >= 191845
        ) or 
        (   // id=3901, type=WIN-TYPE-1, prop=__BMG_TRACKER__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 175842 and loc.getEndColumn() >= 175842
        ) or 
        (   // id=3902, type=WIN-TYPE-1, prop=__BMG_TRACKER_COLLECT_QUEUE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 197950 and loc.getEndColumn() >= 197950
        ) or 
        (   // id=3906, type=WIN-TYPE-1, prop=bmgOnLoad 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 179075 and loc.getEndColumn() >= 179075
        ) or 
        (   // id=3907, type=WIN-TYPE-1, prop=__BMG_TRACKER_COLLECT_MODE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 180739 and loc.getEndColumn() >= 180739
        ) or 
        (   // id=3908, type=WIN-TYPE-1, prop=bmgOnLoad 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 180768 and loc.getEndColumn() >= 180768
        ) or 
        (   // id=3909, type=WIN-TYPE-1, prop=bmgOnError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 180960 and loc.getEndColumn() >= 180960
        ) or 
        (   // id=3910, type=WIN-TYPE-1, prop=__BMG_TRACKER__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 197847 and loc.getEndColumn() >= 197847
        ) or 
        (   // id=3912, type=WIN-TYPE-1, prop=SharedArrayBuffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 38803 and loc.getEndColumn() >= 38803
        ) or 
        (   // id=3913, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 220 and loc.getEndLine() = 220 and
            loc.getStartColumn() <= 5901 and loc.getEndColumn() >= 5901
        ) or 
        (   // id=3915, type=WIN-TYPE-1, prop=dcodeIO 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 220 and loc.getEndLine() = 220 and
            loc.getStartColumn() <= 6766 and loc.getEndColumn() >= 6766
        ) or 
        (   // id=3916, type=WIN-TYPE-1, prop=Long 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 220 and loc.getEndLine() = 220 and
            loc.getStartColumn() <= 6807 and loc.getEndColumn() >= 6807
        ) or 
        (   // id=3920, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 4903 and loc.getEndColumn() >= 4903
        ) or 
        (   // id=3921, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 5894 and loc.getEndColumn() >= 5894
        ) or 
        (   // id=3922, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 6976 and loc.getEndColumn() >= 6976
        ) or 
        (   // id=3923, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 7200 and loc.getEndColumn() >= 7200
        ) or 
        (   // id=3924, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 8743 and loc.getEndColumn() >= 8743
        ) or 
        (   // id=3925, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 10962 and loc.getEndColumn() >= 10962
        ) or 
        (   // id=3926, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 11953 and loc.getEndColumn() >= 11953
        ) or 
        (   // id=3928, type=WIN-TYPE-1, prop=lazyload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 19324 and loc.getEndColumn() >= 19324
        ) or 
        (   // id=3929, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 19360 and loc.getEndColumn() >= 19360
        ) or 
        (   // id=3930, type=WIN-TYPE-1, prop=LazyLoad 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 206 and loc.getEndLine() = 206 and
            loc.getStartColumn() <= 17611 and loc.getEndColumn() >= 17611
        ) or 
        (   // id=3978, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 4974 and loc.getEndColumn() >= 4974
        ) or 
        (   // id=3979, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 5965 and loc.getEndColumn() >= 5965
        ) or 
        (   // id=3980, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 7047 and loc.getEndColumn() >= 7047
        ) or 
        (   // id=3981, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 7271 and loc.getEndColumn() >= 7271
        ) or 
        (   // id=3982, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 8814 and loc.getEndColumn() >= 8814
        ) or 
        (   // id=3983, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 11015 and loc.getEndColumn() >= 11015
        ) or 
        (   // id=3984, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 12006 and loc.getEndColumn() >= 12006
        ) or 
        (   // id=3986, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 19377 and loc.getEndColumn() >= 19377
        ) or 
        (   // id=3989, type=WIN-TYPE-1, prop=gsapVersions 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 12896 and loc.getEndColumn() >= 12896
        ) or 
        (   // id=3990, type=WIN-TYPE-1, prop=gsapVersions 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 12925 and loc.getEndColumn() >= 12925
        ) or 
        (   // id=3996, type=WIN-TYPE-1, prop=gsap 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 106 and loc.getEndColumn() >= 106
        ) or 
        (   // id=4000, type=WIN-TYPE-1, prop=Vue 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 239 and loc.getEndLine() = 239 and
            loc.getStartColumn() <= 24245 and loc.getEndColumn() >= 24245
        ) or 
        (   // id=4018, type=WIN-TYPE-1, prop=tid 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1081257 and loc.getEndColumn() >= 1081257
        ) or 
        (   // id=4019, type=WIN-TYPE-1, prop=channel 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1081289 and loc.getEndColumn() >= 1081289
        ) or 
        (   // id=4066, type=WIN-TYPE-1, prop=__spm_prefix 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 447617 and loc.getEndColumn() >= 447617
        ) or 
        (   // id=4070, type=WIN-TYPE-1, prop=__spm_prefix 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 447651 and loc.getEndColumn() >= 447651
        ) or 
        (   // id=4071, type=WIN-TYPE-1, prop=BiliMusic 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 478841 and loc.getEndColumn() >= 478841
        ) or 
        (   // id=4074, type=WIN-TYPE-1, prop=__BMG_AF__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 14569 and loc.getEndColumn() >= 14569
        ) or 
        (   // id=4102, type=WIN-TYPE-1, prop=UNIFY_HTTP_WBI_CONFIG 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 281638 and loc.getEndColumn() >= 281638
        ) or 
        (   // id=4120, type=WIN-TYPE-1, prop=__BMG_AF__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 51946 and loc.getEndColumn() >= 51946
        ) or 
        (   // id=4127, type=WIN-TYPE-1, prop=bmgCmptOnload 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 1348 and loc.getEndColumn() >= 1348
        ) or 
        (   // id=4128, type=WIN-TYPE-1, prop=bmgCmptOnerror 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 1739 and loc.getEndColumn() >= 1739
        ) or 
        (   // id=4334, type=WIN-TYPE-1, prop=commentAgent 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1048888 and loc.getEndColumn() >= 1048888
        ) or 
        (   // id=4335, type=WIN-TYPE-1, prop=SPACount 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1046871 and loc.getEndColumn() >= 1046871
        ) or 
        (   // id=4336, type=WIN-TYPE-1, prop=SPACount 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1046913 and loc.getEndColumn() >= 1046913
        ) or 
        (   // id=4493, type=WIN-TYPE-1, prop=bsource 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/512.65972.function.chunk.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3574 and loc.getEndColumn() >= 3574
        ) or 
        (   // id=4614, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 135351 and loc.getEndColumn() >= 135351
        ) or 
        (   // id=4615, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 135404 and loc.getEndColumn() >= 135404
        ) or 
        (   // id=4616, type=WIN-TYPE-1, prop=CommentVue 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 135548 and loc.getEndColumn() >= 135548
        ) or 
        (   // id=4617, type=WIN-TYPE-1, prop=__VUE_INSTANCE_SETTERS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 209242 and loc.getEndColumn() >= 209242
        ) or 
        (   // id=4618, type=WIN-TYPE-1, prop=__VUE_INSTANCE_SETTERS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 209314 and loc.getEndColumn() >= 209314
        ) or 
        (   // id=4620, type=WIN-TYPE-1, prop=SuppressedError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 33 and loc.getEndLine() = 33 and
            loc.getStartColumn() <= 30872 and loc.getEndColumn() >= 30872
        ) or 
        (   // id=4631, type=WIN-TYPE-1, prop=__spreadArray 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 42 and loc.getEndLine() = 42 and
            loc.getStartColumn() <= 30157 and loc.getEndColumn() >= 30157
        ) or 
        (   // id=4632, type=WIN-TYPE-1, prop=__vueuse_ssr_handlers__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 66 and loc.getEndLine() = 66 and
            loc.getStartColumn() <= 19889 and loc.getEndColumn() >= 19889
        ) or 
        (   // id=4633, type=WIN-TYPE-1, prop=__vueuse_ssr_handlers__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 66 and loc.getEndLine() = 66 and
            loc.getStartColumn() <= 19881 and loc.getEndColumn() >= 19881
        ) or 
        (   // id=4634, type=WIN-TYPE-1, prop=__assign 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 66 and loc.getEndLine() = 66 and
            loc.getStartColumn() <= 24412 and loc.getEndColumn() >= 24412
        ) or 
        (   // id=4635, type=WIN-TYPE-1, prop=__awaiter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 6382 and loc.getEndColumn() >= 6382
        ) or 
        (   // id=4636, type=WIN-TYPE-1, prop=__generator 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 6779 and loc.getEndColumn() >= 6779
        ) or 
        (   // id=4637, type=WIN-TYPE-1, prop=__values 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 7996 and loc.getEndColumn() >= 7996
        ) or 
        (   // id=4638, type=WIN-TYPE-1, prop=__read 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 8355 and loc.getEndColumn() >= 8355
        ) or 
        (   // id=4639, type=WIN-TYPE-1, prop=__SVG_ICON_NEXT_CACHE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 14323 and loc.getEndColumn() >= 14323
        ) or 
        (   // id=4640, type=WIN-TYPE-1, prop=__SVG_ICON_NEXT_PRELOAD_PACKS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 14397 and loc.getEndColumn() >= 14397
        ) or 
        (   // id=4641, type=WIN-TYPE-1, prop=__SVG_ICON_NEXT_PRELOAD_PACKS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 14469 and loc.getEndColumn() >= 14469
        ) or 
        (   // id=4642, type=WIN-TYPE-1, prop=__awaiter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 15119 and loc.getEndColumn() >= 15119
        ) or 
        (   // id=4643, type=WIN-TYPE-1, prop=__generator 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 15516 and loc.getEndColumn() >= 15516
        ) or 
        (   // id=4644, type=WIN-TYPE-1, prop=__awaiter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 18814 and loc.getEndColumn() >= 18814
        ) or 
        (   // id=4645, type=WIN-TYPE-1, prop=__generator 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 19211 and loc.getEndColumn() >= 19211
        ) or 
        (   // id=4646, type=WIN-TYPE-1, prop=__assign 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 26475 and loc.getEndColumn() >= 26475
        ) or 
        (   // id=4647, type=WIN-TYPE-1, prop=__assign 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 28387 and loc.getEndColumn() >= 28387
        ) or 
        (   // id=4648, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 31125 and loc.getEndColumn() >= 31125
        ) or 
        (   // id=4649, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 32165 and loc.getEndColumn() >= 32165
        ) or 
        (   // id=4650, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 35438 and loc.getEndColumn() >= 35438
        ) or 
        (   // id=4651, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 36554 and loc.getEndColumn() >= 36554
        ) or 
        (   // id=4652, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 37808 and loc.getEndColumn() >= 37808
        ) or 
        (   // id=4653, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 38148 and loc.getEndColumn() >= 38148
        ) or 
        (   // id=4654, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 40011 and loc.getEndColumn() >= 40011
        ) or 
        (   // id=4655, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 42484 and loc.getEndColumn() >= 42484
        ) or 
        (   // id=4656, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 43518 and loc.getEndColumn() >= 43518
        ) or 
        (   // id=4660, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 81 and loc.getEndLine() = 81 and
            loc.getStartColumn() <= 3941 and loc.getEndColumn() >= 3941
        ) or 
        (   // id=4663, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 84 and loc.getEndLine() = 84 and
            loc.getStartColumn() <= 24446 and loc.getEndColumn() >= 24446
        ) or 
        (   // id=4673, type=WIN-TYPE-1, prop=WXEnvironment 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 883 and loc.getEndLine() = 883 and
            loc.getStartColumn() <= 4733 and loc.getEndColumn() >= 4733
        ) or 
        (   // id=4674, type=WIN-TYPE-1, prop=__VUE_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 883 and loc.getEndLine() = 883 and
            loc.getStartColumn() <= 5383 and loc.getEndColumn() >= 5383
        ) or 
        (   // id=4678, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 889 and loc.getEndLine() = 889 and
            loc.getStartColumn() <= 1040 and loc.getEndColumn() >= 1040
        ) or 
        (   // id=4679, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 889 and loc.getEndLine() = 889 and
            loc.getStartColumn() <= 2071 and loc.getEndColumn() >= 2071
        ) or 
        (   // id=4681, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 895 and loc.getEndLine() = 895 and
            loc.getStartColumn() <= 1914 and loc.getEndColumn() >= 1914
        ) or 
        (   // id=4684, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 909 and loc.getEndLine() = 909 and
            loc.getStartColumn() <= 6856 and loc.getEndColumn() >= 6856
        ) or 
        (   // id=4685, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 909 and loc.getEndLine() = 909 and
            loc.getStartColumn() <= 7892 and loc.getEndColumn() >= 7892
        ) or 
        (   // id=4686, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 922 and loc.getEndLine() = 922 and
            loc.getStartColumn() <= 6901 and loc.getEndColumn() >= 6901
        ) or 
        (   // id=4687, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 922 and loc.getEndLine() = 922 and
            loc.getStartColumn() <= 7927 and loc.getEndColumn() >= 7927
        ) or 
        (   // id=4688, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 33165 and loc.getEndColumn() >= 33165
        ) or 
        (   // id=4689, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 34236 and loc.getEndColumn() >= 34236
        ) or 
        (   // id=4690, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 35418 and loc.getEndColumn() >= 35418
        ) or 
        (   // id=4691, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 35658 and loc.getEndColumn() >= 35658
        ) or 
        (   // id=4692, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 37331 and loc.getEndColumn() >= 37331
        ) or 
        (   // id=4693, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 39746 and loc.getEndColumn() >= 39746
        ) or 
        (   // id=4694, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 40777 and loc.getEndColumn() >= 40777
        ) or 
        (   // id=4695, type=WIN-TYPE-1, prop=initComment 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 558522 and loc.getEndColumn() >= 558522
        ) or 
        (   // id=4696, type=WIN-TYPE-1, prop=initNotePreview 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 558557 and loc.getEndColumn() >= 558557
        ) or 
        (   // id=4708, type=WIN-TYPE-1, prop=__VUE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 187434 and loc.getEndColumn() >= 187434
        ) or 
        (   // id=4718, type=WIN-TYPE-1, prop=UNIFY_HTTP_WBI_CONFIG 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 33 and loc.getEndLine() = 33 and
            loc.getStartColumn() <= 17980 and loc.getEndColumn() >= 17980
        ) or 
        (   // id=4748, type=WIN-TYPE-1, prop=commentContainer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 488099 and loc.getEndColumn() >= 488099
        ) or 
        (   // id=4749, type=WIN-TYPE-1, prop=__v_isRef 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 153662 and loc.getEndColumn() >= 153662
        ) or 
        (   // id=4750, type=WIN-TYPE-1, prop=$el 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 66 and loc.getEndLine() = 66 and
            loc.getStartColumn() <= 17820 and loc.getEndColumn() >= 17820
        ) or 
        (   // id=4834, type=WIN-TYPE-1, prop=commentCanvas 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 6695 and loc.getEndColumn() >= 6695
        ) or 
        (   // id=4836, type=WIN-TYPE-1, prop=commentCanvas 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 6890 and loc.getEndColumn() >= 6890
        ) or 
        (   // id=4887, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 12309 and loc.getEndColumn() >= 12309
        ) or 
        (   // id=4888, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 12422 and loc.getEndColumn() >= 12422
        ) or 
        (   // id=4890, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16304 and loc.getEndColumn() >= 16304
        ) or 
        (   // id=4891, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16328 and loc.getEndColumn() >= 16328
        ) or 
        (   // id=4894, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 41730 and loc.getEndColumn() >= 41730
        ) or 
        (   // id=4895, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 85511 and loc.getEndColumn() >= 85511
        ) or 
        (   // id=4896, type=WIN-TYPE-1, prop=opera 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 105665 and loc.getEndColumn() >= 105665
        ) or 
        (   // id=4897, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 151518 and loc.getEndColumn() >= 151518
        ) or 
        (   // id=4898, type=WIN-TYPE-1, prop=Dispatch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 151544 and loc.getEndColumn() >= 151544
        ) or 
        (   // id=4899, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 154166 and loc.getEndColumn() >= 154166
        ) or 
        (   // id=4900, type=WIN-TYPE-1, prop=Deno 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 155394 and loc.getEndColumn() >= 155394
        ) or 
        (   // id=4901, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 158457 and loc.getEndColumn() >= 158457
        ) or 
        (   // id=4903, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 238772 and loc.getEndColumn() >= 238772
        ) or 
        (   // id=4904, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 238802 and loc.getEndColumn() >= 238802
        ) or 
        (   // id=4906, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 245708 and loc.getEndColumn() >= 245708
        ) or 
        (   // id=4907, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 245708 and loc.getEndColumn() >= 245708
        ) or 
        (   // id=4908, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 245708 and loc.getEndColumn() >= 245708
        ) or 
        (   // id=4909, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 245708 and loc.getEndColumn() >= 245708
        ) or 
        (   // id=4910, type=WIN-TYPE-1, prop=Bun 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 253781 and loc.getEndColumn() >= 253781
        ) or 
        (   // id=4911, type=WIN-TYPE-1, prop=__VUE_SSR_SETTERS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 43244 and loc.getEndColumn() >= 43244
        ) or 
        (   // id=4912, type=WIN-TYPE-1, prop=__VUE_SSR_SETTERS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 43258 and loc.getEndColumn() >= 43258
        ) or 
        (   // id=4914, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 74936 and loc.getEndColumn() >= 74936
        ) or 
        (   // id=4915, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 75941 and loc.getEndColumn() >= 75941
        ) or 
        (   // id=4916, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 79028 and loc.getEndColumn() >= 79028
        ) or 
        (   // id=4917, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 80069 and loc.getEndColumn() >= 80069
        ) or 
        (   // id=4918, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 81231 and loc.getEndColumn() >= 81231
        ) or 
        (   // id=4919, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 81559 and loc.getEndColumn() >= 81559
        ) or 
        (   // id=4920, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 83306 and loc.getEndColumn() >= 83306
        ) or 
        (   // id=4921, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 85596 and loc.getEndColumn() >= 85596
        ) or 
        (   // id=4922, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 86597 and loc.getEndColumn() >= 86597
        ) or 
        (   // id=4925, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 163598 and loc.getEndColumn() >= 163598
        ) or 
        (   // id=4926, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 165649 and loc.getEndColumn() >= 165649
        ) or 
        (   // id=4931, type=WIN-TYPE-1, prop=__SVG_ICON_NEXT_CACHE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 512620 and loc.getEndColumn() >= 512620
        ) or 
        (   // id=4932, type=WIN-TYPE-1, prop=__SVG_ICON_NEXT_CACHE__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 512676 and loc.getEndColumn() >= 512676
        ) or 
        (   // id=4933, type=WIN-TYPE-1, prop=__SVG_ICON_NEXT_PROMISE_MAP__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 512694 and loc.getEndColumn() >= 512694
        ) or 
        (   // id=4934, type=WIN-TYPE-1, prop=__SVG_ICON_NEXT_PROMISE_MAP__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 512762 and loc.getEndColumn() >= 512762
        ) or 
        (   // id=4935, type=WIN-TYPE-1, prop=SuppressedError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 569945 and loc.getEndColumn() >= 569945
        ) or 
        (   // id=4946, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 760129 and loc.getEndColumn() >= 760129
        ) or 
        (   // id=4948, type=WIN-TYPE-1, prop=dcodeIO 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 760996 and loc.getEndColumn() >= 760996
        ) or 
        (   // id=4949, type=WIN-TYPE-1, prop=Long 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 761037 and loc.getEndColumn() >= 761037
        ) or 
        (   // id=4953, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 1179223 and loc.getEndColumn() >= 1179223
        ) or 
        (   // id=4954, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 1180216 and loc.getEndColumn() >= 1180216
        ) or 
        (   // id=4955, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 4935 and loc.getEndColumn() >= 4935
        ) or 
        (   // id=4956, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 5926 and loc.getEndColumn() >= 5926
        ) or 
        (   // id=4957, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 7008 and loc.getEndColumn() >= 7008
        ) or 
        (   // id=4958, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 7232 and loc.getEndColumn() >= 7232
        ) or 
        (   // id=4959, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 8764 and loc.getEndColumn() >= 8764
        ) or 
        (   // id=4960, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 10963 and loc.getEndColumn() >= 10963
        ) or 
        (   // id=4961, type=WIN-TYPE-1, prop=__importDefault 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 11954 and loc.getEndColumn() >= 11954
        ) or 
        (   // id=4963, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 19366 and loc.getEndColumn() >= 19366
        ) or 
        (   // id=4966, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 343100 and loc.getEndColumn() >= 343100
        ) or 
        (   // id=4967, type=WIN-TYPE-1, prop=Zepto 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 343110 and loc.getEndColumn() >= 343110
        ) or 
        (   // id=4968, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 314824 and loc.getEndColumn() >= 314824
        ) or 
        (   // id=4969, type=WIN-TYPE-1, prop=BiliHeader 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 12539 and loc.getEndColumn() >= 12539
        ) or 
        (   // id=4973, type=WIN-TYPE-1, prop=__VUE_PROD_HYDRATION_MISMATCH_DETAILS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 20372 and loc.getEndColumn() >= 20372
        ) or 
        (   // id=4974, type=WIN-TYPE-1, prop=__VUE_PROD_HYDRATION_MISMATCH_DETAILS__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 20487 and loc.getEndColumn() >= 20487
        ) or 
        (   // id=5028, type=WIN-TYPE-1, prop=serverdate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/interface.bilibili.com/serverdate.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19 and loc.getEndColumn() >= 19
        ) or 
        (   // id=5040, type=WIN-TYPE-1, prop=UserStatus 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 828122 and loc.getEndColumn() >= 828122
        ) or 
        (   // id=5041, type=WIN-TYPE-1, prop=UserStatus 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 284599 and loc.getEndColumn() >= 284599
        ) or 
        (   // id=5110, type=WIN-TYPE-1, prop=__v_isRef 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 336170 and loc.getEndColumn() >= 336170
        ) or 
        (   // id=5111, type=WIN-TYPE-1, prop=$el 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 63685 and loc.getEndColumn() >= 63685
        ) or 
        (   // id=5119, type=WIN-TYPE-1, prop=headerLoginToggleCtrl 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 184709 and loc.getEndColumn() >= 184709
        ) or 
        (   // id=5507, type=WIN-TYPE-1, prop=biliBridgePc 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 42 and loc.getEndLine() = 42 and
            loc.getStartColumn() <= 30516 and loc.getEndColumn() >= 30516
        ) or 
        (   // id=5508, type=WIN-TYPE-1, prop=biliBridgePc 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 42 and loc.getEndLine() = 42 and
            loc.getStartColumn() <= 30638 and loc.getEndColumn() >= 30638
        ) or 
        (   // id=6105, type=WIN-TYPE-1, prop=imgOnLoad 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 91457 and loc.getEndColumn() >= 91457
        ) or 
        (   // id=6106, type=WIN-TYPE-1, prop=imgOnError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 15 and loc.getEndColumn() >= 15
        ) or 
        (   // id=6110, type=WIN-TYPE-1, prop=__statisObserverConfig 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 1046881 and loc.getEndColumn() >= 1046881
        ) or 
        (   // id=6111, type=WIN-TYPE-1, prop=__statisObserver 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 1046932 and loc.getEndColumn() >= 1046932
        ) or 
        (   // id=6121, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 619 and loc.getEndColumn() >= 619
        ) or 
        (   // id=6122, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1061 and loc.getEndColumn() >= 1061
        ) or 
        (   // id=6123, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13643 and loc.getEndColumn() >= 13643
        ) or 
        (   // id=6124, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13643 and loc.getEndColumn() >= 13643
        ) or 
        (   // id=6125, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13643 and loc.getEndColumn() >= 13643
        ) or 
        (   // id=6126, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13643 and loc.getEndColumn() >= 13643
        ) or 
        (   // id=6127, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16936 and loc.getEndColumn() >= 16936
        ) or 
        (   // id=6128, type=WIN-TYPE-1, prop=__statisObserver 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 23585 and loc.getEndColumn() >= 23585
        ) or 
        (   // id=6129, type=WIN-TYPE-1, prop=reportMsgObj 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 23674 and loc.getEndColumn() >= 23674
        ) or 
        (   // id=6130, type=WIN-TYPE-1, prop=reportMsgObj 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 23735 and loc.getEndColumn() >= 23735
        ) or 
        (   // id=6152, type=WIN-TYPE-1, prop=__statisObserver 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 27848 and loc.getEndColumn() >= 27848
        ) or 
        (   // id=6202, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/special-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1062 and loc.getEndColumn() >= 1062
        ) or 
        (   // id=6203, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/special-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 620 and loc.getEndColumn() >= 620
        ) or 
        (   // id=6204, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/special-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6205, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/special-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6206, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/special-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6207, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/special-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6208, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/special-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16937 and loc.getEndColumn() >= 16937
        ) or 
        (   // id=6215, type=WIN-TYPE-1, prop=__tempSpecialTracker 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/special-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 24802 and loc.getEndColumn() >= 24802
        ) or 
        (   // id=6216, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/perform-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1062 and loc.getEndColumn() >= 1062
        ) or 
        (   // id=6217, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/perform-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 620 and loc.getEndColumn() >= 620
        ) or 
        (   // id=6218, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/perform-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6219, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/perform-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6220, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/perform-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6221, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/perform-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6222, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/perform-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16937 and loc.getEndColumn() >= 16937
        ) or 
        (   // id=6229, type=WIN-TYPE-1, prop=__tempPerformTracker 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/perform-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 25341 and loc.getEndColumn() >= 25341
        ) or 
        (   // id=6233, type=WIN-TYPE-1, prop=XDomainRequest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/perform-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5331 and loc.getEndColumn() >= 5331
        ) or 
        (   // id=6234, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/pv-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1062 and loc.getEndColumn() >= 1062
        ) or 
        (   // id=6235, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/pv-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 620 and loc.getEndColumn() >= 620
        ) or 
        (   // id=6236, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/pv-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6237, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/pv-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6238, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/pv-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6239, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/pv-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6240, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/pv-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16937 and loc.getEndColumn() >= 16937
        ) or 
        (   // id=6247, type=WIN-TYPE-1, prop=__tempPvTracker 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/pv-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 25123 and loc.getEndColumn() >= 25123
        ) or 
        (   // id=6250, type=WIN-TYPE-1, prop=XDomainRequest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/pv-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5331 and loc.getEndColumn() >= 5331
        ) or 
        (   // id=6251, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 620 and loc.getEndColumn() >= 620
        ) or 
        (   // id=6252, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1062 and loc.getEndColumn() >= 1062
        ) or 
        (   // id=6253, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6254, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6255, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6256, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6257, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16937 and loc.getEndColumn() >= 16937
        ) or 
        (   // id=6265, type=WIN-TYPE-1, prop=__tempEventTracker 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 29840 and loc.getEndColumn() >= 29840
        ) or 
        (   // id=6266, type=WIN-TYPE-1, prop=defaultMsgObj 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 28007 and loc.getEndColumn() >= 28007
        ) or 
        (   // id=6267, type=WIN-TYPE-1, prop=defaultMsgObj 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 28044 and loc.getEndColumn() >= 28044
        ) or 
        (   // id=6268, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/error-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 620 and loc.getEndColumn() >= 620
        ) or 
        (   // id=6269, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/error-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1062 and loc.getEndColumn() >= 1062
        ) or 
        (   // id=6270, type=WIN-TYPE-1, prop=CSSValueList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/error-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6271, type=WIN-TYPE-1, prop=ClientRectList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/error-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6272, type=WIN-TYPE-1, prop=PaintRequestList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/error-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6273, type=WIN-TYPE-1, prop=SVGPathSegList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/error-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13644 and loc.getEndColumn() >= 13644
        ) or 
        (   // id=6274, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/error-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16937 and loc.getEndColumn() >= 16937
        ) or 
        (   // id=6281, type=WIN-TYPE-1, prop=__tempErrorTracker 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/error-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 26646 and loc.getEndColumn() >= 26646
        ) or 
        (   // id=6284, type=WIN-TYPE-1, prop=XDomainRequest 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5331 and loc.getEndColumn() >= 5331
        ) or 
        (   // id=6545, type=WIN-TYPE-1, prop=[object Object] 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 1264 and loc.getEndColumn() >= 1264
        ) or 
        (   // id=6546, type=WIN-TYPE-1, prop=MReporter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 1410 and loc.getEndColumn() >= 1410
        ) or 
        (   // id=6566, type=WIN-TYPE-1, prop=blInlinePlayers 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 239 and loc.getEndLine() = 239 and
            loc.getStartColumn() <= 35341 and loc.getEndColumn() >= 35341
        ) or 
        (   // id=6567, type=WIN-TYPE-1, prop=blInlinePlayers 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 239 and loc.getEndLine() = 239 and
            loc.getStartColumn() <= 35418 and loc.getEndColumn() >= 35418
        ) or 
        (   // id=6568, type=WIN-TYPE-1, prop=blActiveInlinePlayer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 239 and loc.getEndLine() = 239 and
            loc.getStartColumn() <= 36181 and loc.getEndColumn() >= 36181
        ) or 
        (   // id=6570, type=WIN-TYPE-1, prop=UNIFY_HTTP_WBI_CONFIG 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 175 and loc.getEndLine() = 175 and
            loc.getStartColumn() <= 2217 and loc.getEndColumn() >= 2217
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
        (   // id=56, type=DOC-TYPE-1, prop=tagName 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 492335 and loc.getEndColumn() >= 492335
        ) or 
        (   // id=1621, type=DOC-TYPE-1, prop=$_BFGf 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 216484 and loc.getEndColumn() >= 216484
        ) or 
        (   // id=3798, type=DOC-TYPE-1, prop=documentMode 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 23532 and loc.getEndColumn() >= 23532
        ) or 
        (   // id=3826, type=DOC-TYPE-1, prop=documentMode 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 23409 and loc.getEndColumn() >= 23409
        ) or 
        (   // id=3840, type=DOC-TYPE-1, prop=documentMode 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 22 and loc.getEndLine() = 22 and
            loc.getStartColumn() <= 76098 and loc.getEndColumn() >= 76098
        ) or 
        (   // id=4975, type=DOC-TYPE-1, prop=documentMode 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 349449 and loc.getEndColumn() >= 349449
        ) or 
        (   // id=6352, type=DOC-TYPE-1, prop=classList 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 925298 and loc.getEndColumn() >= 925298
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
        (   // id=100, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 53279 and loc.getEndColumn() >= 53279
        ) or 
        (   // id=150, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 51241 and loc.getEndColumn() >= 51241
        ) or 
        (   // id=151, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 6093 and loc.getEndColumn() >= 6093
        ) or 
        (   // id=213, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/user-fingerprint/bili-user-fingerprint.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 34851 and loc.getEndColumn() >= 34851
        ) or 
        (   // id=214, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/user-fingerprint/bili-user-fingerprint.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 34970 and loc.getEndColumn() >= 34970
        ) or 
        (   // id=215, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/user-fingerprint/bili-user-fingerprint.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 35016 and loc.getEndColumn() >= 35016
        ) or 
        (   // id=384, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 211548 and loc.getEndColumn() >= 211548
        ) or 
        (   // id=406, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 174970 and loc.getEndColumn() >= 174970
        ) or 
        (   // id=420, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 157249 and loc.getEndColumn() >= 157249
        ) or 
        (   // id=423, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 70452 and loc.getEndColumn() >= 70452
        ) or 
        (   // id=457, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 59201 and loc.getEndColumn() >= 59201
        ) or 
        (   // id=460, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 39539 and loc.getEndColumn() >= 39539
        ) or 
        (   // id=470, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 48344 and loc.getEndColumn() >= 48344
        ) or 
        (   // id=534, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 157869 and loc.getEndColumn() >= 157869
        ) or 
        (   // id=571, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 56478 and loc.getEndColumn() >= 56478
        ) or 
        (   // id=1612, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 123083 and loc.getEndColumn() >= 123083
        ) or 
        (   // id=1613, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 123132 and loc.getEndColumn() >= 123132
        ) or 
        (   // id=1614, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 123181 and loc.getEndColumn() >= 123181
        ) or 
        (   // id=1667, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 219991 and loc.getEndColumn() >= 219991
        ) or 
        (   // id=1668, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 220007 and loc.getEndColumn() >= 220007
        ) or 
        (   // id=1792, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/click.3.1.0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 81105 and loc.getEndColumn() >= 81105
        ) or 
        (   // id=1793, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/click.3.1.0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 81154 and loc.getEndColumn() >= 81154
        ) or 
        (   // id=1794, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/click.3.1.0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 81204 and loc.getEndColumn() >= 81204
        ) or 
        (   // id=2145, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 1370 and loc.getEndColumn() >= 1370
        ) or 
        (   // id=2966, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 14151 and loc.getEndColumn() >= 14151
        ) or 
        (   // id=2967, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 14517 and loc.getEndColumn() >= 14517
        ) or 
        (   // id=2969, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 15821 and loc.getEndColumn() >= 15821
        ) or 
        (   // id=2987, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 59974 and loc.getEndColumn() >= 59974
        ) or 
        (   // id=2994, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19098 and loc.getEndColumn() >= 19098
        ) or 
        (   // id=3046, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 44314 and loc.getEndColumn() >= 44314
        ) or 
        (   // id=3096, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 45804 and loc.getEndColumn() >= 45804
        ) or 
        (   // id=3098, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37157 and loc.getEndColumn() >= 37157
        ) or 
        (   // id=3102, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 24077 and loc.getEndColumn() >= 24077
        ) or 
        (   // id=3103, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 20788 and loc.getEndColumn() >= 20788
        ) or 
        (   // id=3104, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 20821 and loc.getEndColumn() >= 20821
        ) or 
        (   // id=3105, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 23075 and loc.getEndColumn() >= 23075
        ) or 
        (   // id=3106, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 23105 and loc.getEndColumn() >= 23105
        ) or 
        (   // id=3107, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 43113 and loc.getEndColumn() >= 43113
        ) or 
        (   // id=3108, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 59743 and loc.getEndColumn() >= 59743
        ) or 
        (   // id=3142, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 33149 and loc.getEndColumn() >= 33149
        ) or 
        (   // id=3151, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 3640 and loc.getEndColumn() >= 3640
        ) or 
        (   // id=3198, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 109 and loc.getEndLine() = 109 and
            loc.getStartColumn() <= 2041 and loc.getEndColumn() >= 2041
        ) or 
        (   // id=3207, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 113 and loc.getEndLine() = 113 and
            loc.getStartColumn() <= 1728 and loc.getEndColumn() >= 1728
        ) or 
        (   // id=3244, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3758 and loc.getEndColumn() >= 3758
        ) or 
        (   // id=3281, type=DOC-TYPE-2, prop=all 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 84942 and loc.getEndColumn() >= 84942
        ) or 
        (   // id=3285, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 89440 and loc.getEndColumn() >= 89440
        ) or 
        (   // id=3315, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 120071 and loc.getEndColumn() >= 120071
        ) or 
        (   // id=3331, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 280 and loc.getEndColumn() >= 280
        ) or 
        (   // id=3333, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 375 and loc.getEndColumn() >= 375
        ) or 
        (   // id=3334, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 532 and loc.getEndColumn() >= 532
        ) or 
        (   // id=3339, type=DOC-TYPE-2, prop=all 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5119 and loc.getEndColumn() >= 5119
        ) or 
        (   // id=3344, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/risk-captcha-sdk/CaptchaLoader.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10028 and loc.getEndColumn() >= 10028
        ) or 
        (   // id=3377, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/kv-sdk/index.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5930 and loc.getEndColumn() >= 5930
        ) or 
        (   // id=3381, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/512.65972.function.chunk.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1342 and loc.getEndColumn() >= 1342
        ) or 
        (   // id=3417, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 158311 and loc.getEndColumn() >= 158311
        ) or 
        (   // id=3418, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 158331 and loc.getEndColumn() >= 158331
        ) or 
        (   // id=3421, type=DOC-TYPE-2, prop=all 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 97007 and loc.getEndColumn() >= 97007
        ) or 
        (   // id=3425, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 102263 and loc.getEndColumn() >= 102263
        ) or 
        (   // id=3497, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 533 and loc.getEndColumn() >= 533
        ) or 
        (   // id=3501, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 318 and loc.getEndColumn() >= 318
        ) or 
        (   // id=3522, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 4125 and loc.getEndColumn() >= 4125
        ) or 
        (   // id=3570, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 134313 and loc.getEndColumn() >= 134313
        ) or 
        (   // id=3571, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 134339 and loc.getEndColumn() >= 134339
        ) or 
        (   // id=3572, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 134371 and loc.getEndColumn() >= 134371
        ) or 
        (   // id=3601, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 98 and loc.getEndLine() = 98 and
            loc.getStartColumn() <= 309859 and loc.getEndColumn() >= 309859
        ) or 
        (   // id=3622, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 391530 and loc.getEndColumn() >= 391530
        ) or 
        (   // id=3623, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 340040 and loc.getEndColumn() >= 340040
        ) or 
        (   // id=3624, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 340070 and loc.getEndColumn() >= 340070
        ) or 
        (   // id=3627, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 369426 and loc.getEndColumn() >= 369426
        ) or 
        (   // id=3650, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 148737 and loc.getEndColumn() >= 148737
        ) or 
        (   // id=3651, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 52288 and loc.getEndColumn() >= 52288
        ) or 
        (   // id=3652, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 52318 and loc.getEndColumn() >= 52318
        ) or 
        (   // id=3655, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 86 and loc.getEndLine() = 86 and
            loc.getStartColumn() <= 131392 and loc.getEndColumn() >= 131392
        ) or 
        (   // id=3678, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 39 and loc.getEndLine() = 39 and
            loc.getStartColumn() <= 33079 and loc.getEndColumn() >= 33079
        ) or 
        (   // id=3691, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 38646 and loc.getEndColumn() >= 38646
        ) or 
        (   // id=3694, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 14727 and loc.getEndColumn() >= 14727
        ) or 
        (   // id=3711, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 2056 and loc.getEndColumn() >= 2056
        ) or 
        (   // id=3712, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 1215 and loc.getEndColumn() >= 1215
        ) or 
        (   // id=3713, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 1245 and loc.getEndColumn() >= 1245
        ) or 
        (   // id=3718, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 25100 and loc.getEndColumn() >= 25100
        ) or 
        (   // id=3720, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 10706 and loc.getEndColumn() >= 10706
        ) or 
        (   // id=3740, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 79 and loc.getEndLine() = 79 and
            loc.getStartColumn() <= 3397 and loc.getEndColumn() >= 3397
        ) or 
        (   // id=3766, type=DOC-TYPE-2, prop=all 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 8782 and loc.getEndColumn() >= 8782
        ) or 
        (   // id=3789, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 93 and loc.getEndLine() = 93 and
            loc.getStartColumn() <= 5996 and loc.getEndColumn() >= 5996
        ) or 
        (   // id=3843, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 198905 and loc.getEndColumn() >= 198905
        ) or 
        (   // id=3844, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 289493 and loc.getEndColumn() >= 289493
        ) or 
        (   // id=3845, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 289523 and loc.getEndColumn() >= 289523
        ) or 
        (   // id=3848, type=DOC-TYPE-2, prop=all 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 149740 and loc.getEndColumn() >= 149740
        ) or 
        (   // id=3851, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 42017 and loc.getEndColumn() >= 42017
        ) or 
        (   // id=3865, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 58166 and loc.getEndColumn() >= 58166
        ) or 
        (   // id=3871, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 55686 and loc.getEndColumn() >= 55686
        ) or 
        (   // id=3900, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 195162 and loc.getEndColumn() >= 195162
        ) or 
        (   // id=3937, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 93815 and loc.getEndColumn() >= 93815
        ) or 
        (   // id=3938, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 93834 and loc.getEndColumn() >= 93834
        ) or 
        (   // id=3991, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 15 and loc.getEndLine() = 15 and
            loc.getStartColumn() <= 53064 and loc.getEndColumn() >= 53064
        ) or 
        (   // id=3997, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 1235 and loc.getEndColumn() >= 1235
        ) or 
        (   // id=3998, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 1262 and loc.getEndColumn() >= 1262
        ) or 
        (   // id=3999, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 32 and loc.getEndLine() = 32 and
            loc.getStartColumn() <= 1278 and loc.getEndColumn() >= 1278
        ) or 
        (   // id=4001, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 177 and loc.getEndLine() = 177 and
            loc.getStartColumn() <= 71297 and loc.getEndColumn() >= 71297
        ) or 
        (   // id=4003, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 239 and loc.getEndLine() = 239 and
            loc.getStartColumn() <= 42443 and loc.getEndColumn() >= 42443
        ) or 
        (   // id=4062, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 31003 and loc.getEndColumn() >= 31003
        ) or 
        (   // id=4065, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 367313 and loc.getEndColumn() >= 367313
        ) or 
        (   // id=4073, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 488262 and loc.getEndColumn() >= 488262
        ) or 
        (   // id=4088, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 425341 and loc.getEndColumn() >= 425341
        ) or 
        (   // id=4126, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 52680 and loc.getEndColumn() >= 52680
        ) or 
        (   // id=4236, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 476490 and loc.getEndColumn() >= 476490
        ) or 
        (   // id=4324, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 68110 and loc.getEndColumn() >= 68110
        ) or 
        (   // id=4325, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 68184 and loc.getEndColumn() >= 68184
        ) or 
        (   // id=4326, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 68258 and loc.getEndColumn() >= 68258
        ) or 
        (   // id=4476, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 433186 and loc.getEndColumn() >= 433186
        ) or 
        (   // id=4484, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 52912 and loc.getEndColumn() >= 52912
        ) or 
        (   // id=4485, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 52986 and loc.getEndColumn() >= 52986
        ) or 
        (   // id=4486, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 53060 and loc.getEndColumn() >= 53060
        ) or 
        (   // id=4574, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 10924 and loc.getEndColumn() >= 10924
        ) or 
        (   // id=4575, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 10943 and loc.getEndColumn() >= 10943
        ) or 
        (   // id=4613, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 135232 and loc.getEndColumn() >= 135232
        ) or 
        (   // id=4657, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 84 and loc.getEndLine() = 84 and
            loc.getStartColumn() <= 11181 and loc.getEndColumn() >= 11181
        ) or 
        (   // id=4658, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 152349 and loc.getEndColumn() >= 152349
        ) or 
        (   // id=4659, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 80 and loc.getEndLine() = 80 and
            loc.getStartColumn() <= 152379 and loc.getEndColumn() >= 152379
        ) or 
        (   // id=4806, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 45421 and loc.getEndColumn() >= 45421
        ) or 
        (   // id=4840, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 26982 and loc.getEndColumn() >= 26982
        ) or 
        (   // id=4841, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 27048 and loc.getEndColumn() >= 27048
        ) or 
        (   // id=4842, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 27114 and loc.getEndColumn() >= 27114
        ) or 
        (   // id=4843, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 27180 and loc.getEndColumn() >= 27180
        ) or 
        (   // id=4856, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 224823 and loc.getEndColumn() >= 224823
        ) or 
        (   // id=4866, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 922 and loc.getEndLine() = 922 and
            loc.getStartColumn() <= 18247 and loc.getEndColumn() >= 18247
        ) or 
        (   // id=4867, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 922 and loc.getEndLine() = 922 and
            loc.getStartColumn() <= 21856 and loc.getEndColumn() >= 21856
        ) or 
        (   // id=4889, type=DOC-TYPE-2, prop=all 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 15605 and loc.getEndColumn() >= 15605
        ) or 
        (   // id=4893, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16065 and loc.getEndColumn() >= 16065
        ) or 
        (   // id=4979, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 69174 and loc.getEndColumn() >= 69174
        ) or 
        (   // id=5014, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/user-fingerprint/bili-user-fingerprint.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 34897 and loc.getEndColumn() >= 34897
        ) or 
        (   // id=5017, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 28683 and loc.getEndColumn() >= 28683
        ) or 
        (   // id=5018, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 28719 and loc.getEndColumn() >= 28719
        ) or 
        (   // id=5087, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 649097 and loc.getEndColumn() >= 649097
        ) or 
        (   // id=5095, type=DOC-TYPE-2, prop=scrollingElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 285027 and loc.getEndColumn() >= 285027
        ) or 
        (   // id=5120, type=DOC-TYPE-2, prop=scrollingElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 184925 and loc.getEndColumn() >= 184925
        ) or 
        (   // id=6136, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6537 and loc.getEndColumn() >= 6537
        ) or 
        (   // id=6264, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s2.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/event-tracker.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 24246 and loc.getEndColumn() >= 24246
        ) or 
        (   // id=6452, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 20864 and loc.getEndColumn() >= 20864
        ) or 
        (   // id=6453, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 1886 and loc.getEndColumn() >= 1886
        ) or 
        (   // id=6454, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 5250 and loc.getEndColumn() >= 5250
        ) or 
        (   // id=6466, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 1907 and loc.getEndColumn() >= 1907
        ) or 
        (   // id=6471, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 7123 and loc.getEndColumn() >= 7123
        ) or 
        (   // id=6472, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 7146 and loc.getEndColumn() >= 7146
        ) or 
        (   // id=6473, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 7181 and loc.getEndColumn() >= 7181
        ) or 
        (   // id=6474, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 7284 and loc.getEndColumn() >= 7284
        ) or 
        (   // id=6475, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 7307 and loc.getEndColumn() >= 7307
        ) or 
        (   // id=6476, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 7343 and loc.getEndColumn() >= 7343
        ) or 
        (   // id=6477, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 7413 and loc.getEndColumn() >= 7413
        ) or 
        (   // id=6478, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 7470 and loc.getEndColumn() >= 7470
        ) or 
        (   // id=6481, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 6230 and loc.getEndColumn() >= 6230
        ) or 
        (   // id=6531, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 3002 and loc.getEndColumn() >= 3002
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
        (   // id=2, type=DOM-API, prop=.ql-container, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 31603 and loc.getEndColumn() >= 31603
        ) or 
        (   // id=3, type=DOM-API, prop=.ql-container, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 213 and loc.getEndLine() = 213 and
            loc.getStartColumn() <= 31603 and loc.getEndColumn() >= 31603
        ) or 
        (   // id=15, type=DOM-API, prop=.bilibili-player-video-btn-send, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1031469 and loc.getEndColumn() >= 1031469
        ) or 
        (   // id=16, type=DOM-API, prop=.bilibili-player-video-btn-send, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1031469 and loc.getEndColumn() >= 1031469
        ) or 
        (   // id=17, type=DOM-API, prop=text-field-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=18, type=DOM-API, prop=spin, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=33, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=35, type=DOM-API, prop=meta[name=spm_prefix], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 910312 and loc.getEndColumn() >= 910312
        ) or 
        (   // id=36, type=DOM-API, prop=meta[name=spm_prefix], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 910312 and loc.getEndColumn() >= 910312
        ) or 
        (   // id=37, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25971 and loc.getEndColumn() >= 25971
        ) or 
        (   // id=42, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=43, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=44, type=DOM-API, prop=check-timestamp, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=113, type=DOM-API, prop=image0_5993_203998, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=115, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 67147 and loc.getEndColumn() >= 67147
        ) or 
        (   // id=118, type=DOM-API, prop=pattern0, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=119, type=DOM-API, prop=alttext, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 56932 and loc.getEndColumn() >= 56932
        ) or 
        (   // id=125, type=DOM-API, prop=pattern0, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 47289 and loc.getEndColumn() >= 47289
        ) or 
        (   // id=146, type=DOM-API, prop=.report-scroll-module, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/512.65972.function.chunk.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1798 and loc.getEndColumn() >= 1798
        ) or 
        (   // id=147, type=DOM-API, prop=.report-scroll-module, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/512.65972.function.chunk.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1798 and loc.getEndColumn() >= 1798
        ) or 
        (   // id=149, type=DOM-API, prop=arc_toolbar_report, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 999084 and loc.getEndColumn() >= 999084
        ) or 
        (   // id=161, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 431134 and loc.getEndColumn() >= 431134
        ) or 
        (   // id=181, type=DOM-API, prop=filter0_f_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=182, type=DOM-API, prop=filter1_d_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=183, type=DOM-API, prop=filter2_ii_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=184, type=DOM-API, prop=paint0_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=185, type=DOM-API, prop=paint1_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=186, type=DOM-API, prop=paint2_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=187, type=DOM-API, prop=paint3_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=188, type=DOM-API, prop=clip0_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=189, type=DOM-API, prop=clip0_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=190, type=DOM-API, prop=filter0_f_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=191, type=DOM-API, prop=paint0_linear_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=192, type=DOM-API, prop=filter1_d_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=193, type=DOM-API, prop=paint1_linear_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=194, type=DOM-API, prop=paint2_linear_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=195, type=DOM-API, prop=filter2_ii_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=196, type=DOM-API, prop=paint3_linear_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=197, type=DOM-API, prop=filter0_f_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41181 and loc.getEndColumn() >= 41181
        ) or 
        (   // id=198, type=DOM-API, prop=filter1_d_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41181 and loc.getEndColumn() >= 41181
        ) or 
        (   // id=199, type=DOM-API, prop=filter2_ii_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41181 and loc.getEndColumn() >= 41181
        ) or 
        (   // id=200, type=DOM-API, prop=paint0_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41181 and loc.getEndColumn() >= 41181
        ) or 
        (   // id=201, type=DOM-API, prop=paint1_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41181 and loc.getEndColumn() >= 41181
        ) or 
        (   // id=202, type=DOM-API, prop=paint2_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41181 and loc.getEndColumn() >= 41181
        ) or 
        (   // id=203, type=DOM-API, prop=paint3_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41181 and loc.getEndColumn() >= 41181
        ) or 
        (   // id=204, type=DOM-API, prop=clip0_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41181 and loc.getEndColumn() >= 41181
        ) or 
        (   // id=205, type=DOM-API, prop=filter0_f_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=206, type=DOM-API, prop=filter1_d_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=207, type=DOM-API, prop=filter2_ii_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=208, type=DOM-API, prop=paint0_linear_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=209, type=DOM-API, prop=paint1_linear_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=210, type=DOM-API, prop=paint2_linear_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=211, type=DOM-API, prop=paint3_linear_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=212, type=DOM-API, prop=clip0_8665_5013, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 41228 and loc.getEndColumn() >= 41228
        ) or 
        (   // id=217, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 47894 and loc.getEndColumn() >= 47894
        ) or 
        (   // id=382, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 1118 and loc.getEndColumn() >= 1118
        ) or 
        (   // id=385, type=DOM-API, prop=[data-v-owner="17"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=386, type=DOM-API, prop=[data-v-owner="17"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=387, type=DOM-API, prop=[data-v-owner="18"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=388, type=DOM-API, prop=[data-v-owner="18"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=389, type=DOM-API, prop=[data-v-owner="19"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=390, type=DOM-API, prop=[data-v-owner="19"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=405, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 172821 and loc.getEndColumn() >= 172821
        ) or 
        (   // id=411, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 77704 and loc.getEndColumn() >= 77704
        ) or 
        (   // id=413, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 100832 and loc.getEndColumn() >= 100832
        ) or 
        (   // id=425, type=DOM-API, prop=style[data-vue-ssr-id~="53b85fba:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=426, type=DOM-API, prop=style[data-vue-ssr-id~="53b85fba:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=431, type=DOM-API, prop=style[data-vue-ssr-id~="665fc9fd:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=432, type=DOM-API, prop=style[data-vue-ssr-id~="665fc9fd:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=436, type=DOM-API, prop=style[data-vue-ssr-id~="ba0eb9be:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=437, type=DOM-API, prop=style[data-vue-ssr-id~="ba0eb9be:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=441, type=DOM-API, prop=style[data-vue-ssr-id~="6b924dcd:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=442, type=DOM-API, prop=style[data-vue-ssr-id~="6b924dcd:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=446, type=DOM-API, prop=style[data-vue-ssr-id~="65e66132:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=447, type=DOM-API, prop=style[data-vue-ssr-id~="65e66132:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=451, type=DOM-API, prop=style[data-vue-ssr-id~="080f722e:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=452, type=DOM-API, prop=style[data-vue-ssr-id~="080f722e:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=456, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 58370 and loc.getEndColumn() >= 58370
        ) or 
        (   // id=468, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 2183 and loc.getEndColumn() >= 2183
        ) or 
        (   // id=478, type=DOM-API, prop=style[data-vue-ssr-id~="83319d60:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=479, type=DOM-API, prop=style[data-vue-ssr-id~="83319d60:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=483, type=DOM-API, prop=style[data-vue-ssr-id~="6d00776e:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=484, type=DOM-API, prop=style[data-vue-ssr-id~="6d00776e:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=488, type=DOM-API, prop=style[data-vue-ssr-id~="49e82dba:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=489, type=DOM-API, prop=style[data-vue-ssr-id~="49e82dba:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=493, type=DOM-API, prop=style[data-vue-ssr-id~="0ed7b201:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=494, type=DOM-API, prop=style[data-vue-ssr-id~="0ed7b201:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=496, type=DOM-API, prop=style[data-vue-ssr-id~="a31533c6:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=497, type=DOM-API, prop=style[data-vue-ssr-id~="a31533c6:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=499, type=DOM-API, prop=style[data-vue-ssr-id~="65556f6c:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=500, type=DOM-API, prop=style[data-vue-ssr-id~="65556f6c:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=502, type=DOM-API, prop=style[data-vue-ssr-id~="6976997a:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=503, type=DOM-API, prop=style[data-vue-ssr-id~="6976997a:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=504, type=DOM-API, prop=style[data-vue-ssr-id~="7342f386:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=505, type=DOM-API, prop=style[data-vue-ssr-id~="7342f386:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=506, type=DOM-API, prop=style[data-vue-ssr-id~="78354263:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=507, type=DOM-API, prop=style[data-vue-ssr-id~="78354263:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=508, type=DOM-API, prop=style[data-vue-ssr-id~="72074103:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=509, type=DOM-API, prop=style[data-vue-ssr-id~="72074103:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 13 and loc.getEndLine() = 13 and
            loc.getStartColumn() <= 71402 and loc.getEndColumn() >= 71402
        ) or 
        (   // id=511, type=DOM-API, prop=body, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 260430 and loc.getEndColumn() >= 260430
        ) or 
        (   // id=512, type=DOM-API, prop=body, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 260430 and loc.getEndColumn() >= 260430
        ) or 
        (   // id=526, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 262373 and loc.getEndColumn() >= 262373
        ) or 
        (   // id=528, type=DOM-API, prop=.bili-mini-mask, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 258023 and loc.getEndColumn() >= 258023
        ) or 
        (   // id=529, type=DOM-API, prop=.bili-mini-mask, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 258023 and loc.getEndColumn() >= 258023
        ) or 
        (   // id=532, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/index.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 157147 and loc.getEndColumn() >= 157147
        ) or 
        (   // id=570, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 54476 and loc.getEndColumn() >= 54476
        ) or 
        (   // id=573, type=DOM-API, prop=spin, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 54476 and loc.getEndColumn() >= 54476
        ) or 
        (   // id=576, type=DOM-API, prop=text-field-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 54476 and loc.getEndColumn() >= 54476
        ) or 
        (   // id=584, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 50658 and loc.getEndColumn() >= 50658
        ) or 
        (   // id=591, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 191033 and loc.getEndColumn() >= 191033
        ) or 
        (   // id=603, type=DOM-API, prop=alttext-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=604, type=DOM-API, prop=alttext-image, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=632, type=DOM-API, prop=input, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=633, type=DOM-API, prop=button, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=634, type=DOM-API, prop=a, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=635, type=DOM-API, prop=div, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=636, type=DOM-API, prop=span, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=639, type=DOM-API, prop=input[type="password"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=659, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/reporter-pb/fingerPrint.chunk.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 37102 and loc.getEndColumn() >= 37102
        ) or 
        (   // id=899, type=DOM-API, prop=forget-tip, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 211500 and loc.getEndColumn() >= 211500
        ) or 
        (   // id=1401, type=DOM-API, prop=area-code-select, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 243277 and loc.getEndColumn() >= 243277
        ) or 
        (   // id=1732, type=DOM-API, prop=geetest_data_share_plugin, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/static.geetest.com/static/js/fullpage.9.1.9-r8k4eq.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 252321 and loc.getEndColumn() >= 252321
        ) or 
        (   // id=2327, type=DOM-API, prop=.bili-mini-mask, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 258826 and loc.getEndColumn() >= 258826
        ) or 
        (   // id=2328, type=DOM-API, prop=.bili-mini-mask, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 258826 and loc.getEndColumn() >= 258826
        ) or 
        (   // id=2957, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 254297 and loc.getEndColumn() >= 254297
        ) or 
        (   // id=2958, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 254297 and loc.getEndColumn() >= 254297
        ) or 
        (   // id=2959, type=DOM-API, prop=check-timestamp, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/mini-login-v2/miniLogin.umd.min.js") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 254297 and loc.getEndColumn() >= 254297
        ) or 
        (   // id=2971, type=DOM-API, prop=script1712347409485, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 15890 and loc.getEndColumn() >= 15890
        ) or 
        (   // id=2974, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16496 and loc.getEndColumn() >= 16496
        ) or 
        (   // id=2977, type=DOM-API, prop=.TEST, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 17150 and loc.getEndColumn() >= 17150
        ) or 
        (   // id=2978, type=DOM-API, prop=.TEST, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 17150 and loc.getEndColumn() >= 17150
        ) or 
        (   // id=2980, type=DOM-API, prop=e, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 17656 and loc.getEndColumn() >= 17656
        ) or 
        (   // id=2981, type=DOM-API, prop=e, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 17738 and loc.getEndColumn() >= 17738
        ) or 
        (   // id=2986, type=DOM-API, prop=language, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 601 and loc.getEndColumn() >= 601
        ) or 
        (   // id=2989, type=DOM-API, prop=action, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 601 and loc.getEndColumn() >= 601
        ) or 
        (   // id=2991, type=DOM-API, prop=display, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 601 and loc.getEndColumn() >= 601
        ) or 
        (   // id=2996, type=DOM-API, prop=input[name=appkey62], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 17348 and loc.getEndColumn() >= 17348
        ) or 
        (   // id=2997, type=DOM-API, prop=input[name=appkey62], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 17348 and loc.getEndColumn() >= 17348
        ) or 
        (   // id=2999, type=DOM-API, prop=*, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4962 and loc.getEndColumn() >= 4962
        ) or 
        (   // id=3043, type=DOM-API, prop=[tabindex], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 17348 and loc.getEndColumn() >= 17348
        ) or 
        (   // id=3044, type=DOM-API, prop=[tabindex], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 17348 and loc.getEndColumn() >= 17348
        ) or 
        (   // id=3109, type=DOM-API, prop=switchLogin, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 601 and loc.getEndColumn() >= 601
        ) or 
        (   // id=3112, type=DOM-API, prop=qrcode_login_a, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/authorize.html") and
            loc.getStartLine() = 142 and loc.getEndLine() = 142 and
            loc.getStartColumn() <= 14 and loc.getEndColumn() >= 14
        ) or 
        (   // id=3113, type=DOM-API, prop=INPUT, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 49284 and loc.getEndColumn() >= 49284
        ) or 
        (   // id=3114, type=DOM-API, prop=TEXTAREA, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 49284 and loc.getEndColumn() >= 49284
        ) or 
        (   // id=3115, type=DOM-API, prop=BUTTON, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 49284 and loc.getEndColumn() >= 49284
        ) or 
        (   // id=3116, type=DOM-API, prop=SELECT, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/js/oauth2Web.min.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 49284 and loc.getEndColumn() >= 49284
        ) or 
        (   // id=3118, type=DOM-API, prop=##, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/api.weibo.com/oauth2/authorize.html") and
            loc.getStartLine() = 142 and loc.getEndLine() = 142 and
            loc.getStartColumn() <= 47 and loc.getEndColumn() >= 47
        ) or 
        (   // id=3180, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 1073 and loc.getEndColumn() >= 1073
        ) or 
        (   // id=3181, type=DOM-API, prop=head, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/player/main/core.0c2eed7f.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 1073 and loc.getEndColumn() >= 1073
        ) or 
        (   // id=3211, type=DOM-API, prop=setSizeStyle, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 54868 and loc.getEndColumn() >= 54868
        ) or 
        (   // id=3212, type=DOM-API, prop=setSizeStyle, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 5 and loc.getEndLine() = 5 and
            loc.getStartColumn() <= 54858 and loc.getEndColumn() >= 54858
        ) or 
        (   // id=3224, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 821 and loc.getEndColumn() >= 821
        ) or 
        (   // id=3234, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/short/b-mirror/biliMirror.umd.mini.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 33802 and loc.getEndColumn() >= 33802
        ) or 
        (   // id=3250, type=DOM-API, prop=bilibili-player, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 113 and loc.getEndLine() = 113 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=3252, type=DOM-API, prop=.danmaku-wrap, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 114 and loc.getEndLine() = 114 and
            loc.getStartColumn() <= 38 and loc.getEndColumn() >= 38
        ) or 
        (   // id=3253, type=DOM-API, prop=.danmaku-wrap, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 114 and loc.getEndLine() = 114 and
            loc.getStartColumn() <= 38 and loc.getEndColumn() >= 38
        ) or 
        (   // id=3257, type=DOM-API, prop=.bpx-docker, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 166 and loc.getEndLine() = 166 and
            loc.getStartColumn() <= 22 and loc.getEndColumn() >= 22
        ) or 
        (   // id=3258, type=DOM-API, prop=.bpx-docker, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 166 and loc.getEndLine() = 166 and
            loc.getStartColumn() <= 22 and loc.getEndColumn() >= 22
        ) or 
        (   // id=3265, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 25794 and loc.getEndColumn() >= 25794
        ) or 
        (   // id=3313, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 119392 and loc.getEndColumn() >= 119392
        ) or 
        (   // id=3326, type=DOM-API, prop=arc_toolbar_report, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 292 and loc.getEndLine() = 292 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=3327, type=DOM-API, prop=#arc_toolbar_report>.video-toolbar-left>.video-toolbar-left-main>:nth-child(1)>div>svg, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 292 and loc.getEndLine() = 292 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=3397, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/log/report/log-reporter.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 63401 and loc.getEndColumn() >= 63401
        ) or 
        (   // id=3479, type=DOM-API, prop=___gatsby, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=3480, type=DOM-API, prop=react-root, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=3575, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 104610 and loc.getEndColumn() >= 104610
        ) or 
        (   // id=3577, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 125052 and loc.getEndColumn() >= 125052
        ) or 
        (   // id=3594, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 98 and loc.getEndLine() = 98 and
            loc.getStartColumn() <= 131563 and loc.getEndColumn() >= 131563
        ) or 
        (   // id=3607, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 111 and loc.getEndLine() = 111 and
            loc.getStartColumn() <= 3038 and loc.getEndColumn() >= 3038
        ) or 
        (   // id=3696, type=DOM-API, prop=style[data-vue-ssr-id~="5f188990:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3697, type=DOM-API, prop=style[data-vue-ssr-id~="5f188990:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3701, type=DOM-API, prop=style[data-vue-ssr-id~="2bf46854:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3702, type=DOM-API, prop=style[data-vue-ssr-id~="2bf46854:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3717, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 73 and loc.getEndLine() = 73 and
            loc.getStartColumn() <= 24284 and loc.getEndColumn() >= 24284
        ) or 
        (   // id=3744, type=DOM-API, prop=style[data-vue-ssr-id~="768cc903:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3745, type=DOM-API, prop=style[data-vue-ssr-id~="768cc903:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3749, type=DOM-API, prop=style[data-vue-ssr-id~="8d1f24e2:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3750, type=DOM-API, prop=style[data-vue-ssr-id~="8d1f24e2:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3754, type=DOM-API, prop=style[data-vue-ssr-id~="fd0cf880:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3755, type=DOM-API, prop=style[data-vue-ssr-id~="fd0cf880:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 45 and loc.getEndLine() = 45 and
            loc.getStartColumn() <= 15658 and loc.getEndColumn() >= 15658
        ) or 
        (   // id=3815, type=DOM-API, prop=[src$=".svga"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 152726 and loc.getEndColumn() >= 152726
        ) or 
        (   // id=3816, type=DOM-API, prop=[src$=".svga"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 152726 and loc.getEndColumn() >= 152726
        ) or 
        (   // id=3818, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 29510 and loc.getEndColumn() >= 29510
        ) or 
        (   // id=3831, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 203646 and loc.getEndColumn() >= 203646
        ) or 
        (   // id=3833, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 224093 and loc.getEndColumn() >= 224093
        ) or 
        (   // id=3867, type=DOM-API, prop=style[data-vue-ssr-id~="dd5680da:0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 59097 and loc.getEndColumn() >= 59097
        ) or 
        (   // id=3868, type=DOM-API, prop=style[data-vue-ssr-id~="dd5680da:0"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 59097 and loc.getEndColumn() >= 59097
        ) or 
        (   // id=3896, type=DOM-API, prop=bmgstyle-img-preview, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 194739 and loc.getEndColumn() >= 194739
        ) or 
        (   // id=3897, type=DOM-API, prop=#bmgstyle-img-preview, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 194739 and loc.getEndColumn() >= 194739
        ) or 
        (   // id=3898, type=DOM-API, prop=#bmgstyle-img-preview, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 194739 and loc.getEndColumn() >= 194739
        ) or 
        (   // id=3904, type=DOM-API, prop=meta[name=spm_prefix], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 179420 and loc.getEndColumn() >= 179420
        ) or 
        (   // id=3905, type=DOM-API, prop=meta[name=spm_prefix], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 199 and loc.getEndLine() = 199 and
            loc.getStartColumn() <= 179420 and loc.getEndColumn() >= 179420
        ) or 
        (   // id=3935, type=DOM-API, prop=body, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 309282 and loc.getEndColumn() >= 309282
        ) or 
        (   // id=3936, type=DOM-API, prop=body, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 309282 and loc.getEndColumn() >= 309282
        ) or 
        (   // id=4006, type=DOM-API, prop=base, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 239 and loc.getEndLine() = 239 and
            loc.getStartColumn() <= 14919 and loc.getEndColumn() >= 14919
        ) or 
        (   // id=4007, type=DOM-API, prop=base, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 239 and loc.getEndLine() = 239 and
            loc.getStartColumn() <= 14919 and loc.getEndColumn() >= 14919
        ) or 
        (   // id=4010, type=DOM-API, prop=__css-map__, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 227 and loc.getEndLine() = 227 and
            loc.getStartColumn() <= 435475 and loc.getEndColumn() >= 435475
        ) or 
        (   // id=4014, type=DOM-API, prop=app, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 24488 and loc.getEndColumn() >= 24488
        ) or 
        (   // id=4015, type=DOM-API, prop=app, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 40693 and loc.getEndColumn() >= 40693
        ) or 
        (   // id=4016, type=DOM-API, prop=#app, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 40693 and loc.getEndColumn() >= 40693
        ) or 
        (   // id=4017, type=DOM-API, prop=#app, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 40693 and loc.getEndColumn() >= 40693
        ) or 
        (   // id=4064, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 85015 and loc.getEndColumn() >= 85015
        ) or 
        (   // id=4068, type=DOM-API, prop=meta[name=spm_prefix], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 447671 and loc.getEndColumn() >= 447671
        ) or 
        (   // id=4069, type=DOM-API, prop=meta[name=spm_prefix], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 447671 and loc.getEndColumn() >= 447671
        ) or 
        (   // id=4076, type=DOM-API, prop=.bili-avatar-img, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 20231 and loc.getEndColumn() >= 20231
        ) or 
        (   // id=4077, type=DOM-API, prop=.bili-avatar-img, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 20231 and loc.getEndColumn() >= 20231
        ) or 
        (   // id=4079, type=DOM-API, prop=.bili-avatar-img, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 18163 and loc.getEndColumn() >= 18163
        ) or 
        (   // id=4080, type=DOM-API, prop=.bili-avatar-img, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 21 and loc.getEndLine() = 21 and
            loc.getStartColumn() <= 18163 and loc.getEndColumn() >= 18163
        ) or 
        (   // id=4082, type=DOM-API, prop=.up-info-container .b-gz, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 517716 and loc.getEndColumn() >= 517716
        ) or 
        (   // id=4083, type=DOM-API, prop=.up-info-container .b-gz, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 517716 and loc.getEndColumn() >= 517716
        ) or 
        (   // id=4084, type=DOM-API, prop=.up-name, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 518815 and loc.getEndColumn() >= 518815
        ) or 
        (   // id=4085, type=DOM-API, prop=.up-name, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 518815 and loc.getEndColumn() >= 518815
        ) or 
        (   // id=4100, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 284972 and loc.getEndColumn() >= 284972
        ) or 
        (   // id=4106, type=DOM-API, prop=.video-title, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 88298 and loc.getEndColumn() >= 88298
        ) or 
        (   // id=4107, type=DOM-API, prop=.video-title, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 88298 and loc.getEndColumn() >= 88298
        ) or 
        (   // id=4108, type=DOM-API, prop=.item, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 88637 and loc.getEndColumn() >= 88637
        ) or 
        (   // id=4109, type=DOM-API, prop=.item, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 88637 and loc.getEndColumn() >= 88637
        ) or 
        (   // id=4119, type=DOM-API, prop=alttext, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 6 and loc.getEndLine() = 6 and
            loc.getStartColumn() <= 44498 and loc.getEndColumn() >= 44498
        ) or 
        (   // id=4122, type=DOM-API, prop=bmgstyle-b-img__inner, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 52257 and loc.getEndColumn() >= 52257
        ) or 
        (   // id=4123, type=DOM-API, prop=#bmgstyle-b-img__inner, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 52257 and loc.getEndColumn() >= 52257
        ) or 
        (   // id=4124, type=DOM-API, prop=#bmgstyle-b-img__inner, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 112 and loc.getEndLine() = 112 and
            loc.getStartColumn() <= 52257 and loc.getEndColumn() >= 52257
        ) or 
        (   // id=4234, type=DOM-API, prop=.not-btn-tag, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 476391 and loc.getEndColumn() >= 476391
        ) or 
        (   // id=4235, type=DOM-API, prop=.not-btn-tag, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 476391 and loc.getEndColumn() >= 476391
        ) or 
        (   // id=4243, type=DOM-API, prop=html, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 7852 and loc.getEndColumn() >= 7852
        ) or 
        (   // id=4245, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8119 and loc.getEndColumn() >= 8119
        ) or 
        (   // id=4247, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8193 and loc.getEndColumn() >= 8193
        ) or 
        (   // id=4249, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8349 and loc.getEndColumn() >= 8349
        ) or 
        (   // id=4251, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8392 and loc.getEndColumn() >= 8392
        ) or 
        (   // id=4252, type=DOM-API, prop=meta[data-vue-meta], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4253, type=DOM-API, prop=meta[data-vue-meta], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4254, type=DOM-API, prop=meta[data-vue-meta][data-body="true"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4255, type=DOM-API, prop=meta[data-vue-meta][data-body="true"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4277, type=DOM-API, prop=base[data-vue-meta], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4278, type=DOM-API, prop=base[data-vue-meta], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4279, type=DOM-API, prop=base[data-vue-meta][data-body="true"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4280, type=DOM-API, prop=base[data-vue-meta][data-body="true"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4285, type=DOM-API, prop=link[data-vue-meta], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4286, type=DOM-API, prop=link[data-vue-meta], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4287, type=DOM-API, prop=link[data-vue-meta][data-body="true"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4288, type=DOM-API, prop=link[data-vue-meta][data-body="true"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4296, type=DOM-API, prop=style[data-vue-meta], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4297, type=DOM-API, prop=style[data-vue-meta], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4298, type=DOM-API, prop=style[data-vue-meta][data-body="true"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4299, type=DOM-API, prop=style[data-vue-meta][data-body="true"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4302, type=DOM-API, prop=script[data-vue-meta], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4303, type=DOM-API, prop=script[data-vue-meta], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4304, type=DOM-API, prop=script[data-vue-meta][data-body="true"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4305, type=DOM-API, prop=script[data-vue-meta][data-body="true"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4308, type=DOM-API, prop=noscript[data-vue-meta], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4309, type=DOM-API, prop=noscript[data-vue-meta], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4310, type=DOM-API, prop=noscript[data-vue-meta][data-body="true"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4311, type=DOM-API, prop=noscript[data-vue-meta][data-body="true"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4314, type=DOM-API, prop=__dangerouslyDisableSanitizersByTagID[data-vue-meta], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4315, type=DOM-API, prop=__dangerouslyDisableSanitizersByTagID[data-vue-meta], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8512 and loc.getEndColumn() >= 8512
        ) or 
        (   // id=4316, type=DOM-API, prop=__dangerouslyDisableSanitizersByTagID[data-vue-meta][data-body="true"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4317, type=DOM-API, prop=__dangerouslyDisableSanitizersByTagID[data-vue-meta][data-body="true"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 147 and loc.getEndLine() = 147 and
            loc.getStartColumn() <= 8549 and loc.getEndColumn() >= 8549
        ) or 
        (   // id=4321, type=DOM-API, prop=ai-summary-popup-draggable-area, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 69236 and loc.getEndColumn() >= 69236
        ) or 
        (   // id=4322, type=DOM-API, prop=.ai-summary-popup #ai-summary-popup-draggable-area, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 69236 and loc.getEndColumn() >= 69236
        ) or 
        (   // id=4323, type=DOM-API, prop=.ai-summary-popup #ai-summary-popup-draggable-area, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 153 and loc.getEndLine() = 153 and
            loc.getStartColumn() <= 69236 and loc.getEndColumn() >= 69236
        ) or 
        (   // id=4328, type=DOM-API, prop=.bpx-docker, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1058389 and loc.getEndColumn() >= 1058389
        ) or 
        (   // id=4329, type=DOM-API, prop=.bpx-docker, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1058389 and loc.getEndColumn() >= 1058389
        ) or 
        (   // id=4332, type=DOM-API, prop=.bpx-docker, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1084530 and loc.getEndColumn() >= 1084530
        ) or 
        (   // id=4333, type=DOM-API, prop=.bpx-docker, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1084530 and loc.getEndColumn() >= 1084530
        ) or 
        (   // id=4338, type=DOM-API, prop=wxwork-share-pic, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1067845 and loc.getEndColumn() >= 1067845
        ) or 
        (   // id=4340, type=DOM-API, prop=v_upinfo, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1031877 and loc.getEndColumn() >= 1031877
        ) or 
        (   // id=4341, type=DOM-API, prop=#v_upinfo .b-gz, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1031877 and loc.getEndColumn() >= 1031877
        ) or 
        (   // id=4342, type=DOM-API, prop=#v_upinfo .b-gz, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 1031877 and loc.getEndColumn() >= 1031877
        ) or 
        (   // id=4482, type=DOM-API, prop=.note-header, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 54038 and loc.getEndColumn() >= 54038
        ) or 
        (   // id=4483, type=DOM-API, prop=.note-header, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 188 and loc.getEndLine() = 188 and
            loc.getStartColumn() <= 54038 and loc.getEndColumn() >= 54038
        ) or 
        (   // id=4576, type=DOM-API, prop=alttext-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 4983 and loc.getEndColumn() >= 4983
        ) or 
        (   // id=4577, type=DOM-API, prop=alttext-image, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 4983 and loc.getEndColumn() >= 4983
        ) or 
        (   // id=4599, type=DOM-API, prop=alttext-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 6442 and loc.getEndColumn() >= 6442
        ) or 
        (   // id=4600, type=DOM-API, prop=alttext-image, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 244 and loc.getEndLine() = 244 and
            loc.getStartColumn() <= 6442 and loc.getEndColumn() >= 6442
        ) or 
        (   // id=4622, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 33 and loc.getEndLine() = 33 and
            loc.getStartColumn() <= 31175 and loc.getEndColumn() >= 31175
        ) or 
        (   // id=4624, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 34 and loc.getEndLine() = 34 and
            loc.getStartColumn() <= 20770 and loc.getEndColumn() >= 20770
        ) or 
        (   // id=4668, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 881 and loc.getEndLine() = 881 and
            loc.getStartColumn() <= 580 and loc.getEndColumn() >= 580
        ) or 
        (   // id=4669, type=DOM-API, prop=head, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 881 and loc.getEndLine() = 881 and
            loc.getStartColumn() <= 580 and loc.getEndColumn() >= 580
        ) or 
        (   // id=4702, type=DOM-API, prop=.comment, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 487455 and loc.getEndColumn() >= 487455
        ) or 
        (   // id=4703, type=DOM-API, prop=.comment, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 487455 and loc.getEndColumn() >= 487455
        ) or 
        (   // id=4706, type=DOM-API, prop=.comment, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 557055 and loc.getEndColumn() >= 557055
        ) or 
        (   // id=4707, type=DOM-API, prop=.comment, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 927 and loc.getEndLine() = 927 and
            loc.getStartColumn() <= 557055 and loc.getEndColumn() >= 557055
        ) or 
        (   // id=4711, type=DOM-API, prop=__css-map__, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 55 and loc.getEndColumn() >= 55
        ) or 
        (   // id=4713, type=DOM-API, prop=.comment, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 227516 and loc.getEndColumn() >= 227516
        ) or 
        (   // id=4714, type=DOM-API, prop=.comment, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 227516 and loc.getEndColumn() >= 227516
        ) or 
        (   // id=4716, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 33 and loc.getEndLine() = 33 and
            loc.getStartColumn() <= 20236 and loc.getEndColumn() >= 20236
        ) or 
        (   // id=4743, type=DOM-API, prop=[data-v-owner="3"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4744, type=DOM-API, prop=[data-v-owner="3"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4754, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 220641 and loc.getEndColumn() >= 220641
        ) or 
        (   // id=4755, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 220663 and loc.getEndColumn() >= 220663
        ) or 
        (   // id=4774, type=DOM-API, prop=file-upload-button, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 220641 and loc.getEndColumn() >= 220641
        ) or 
        (   // id=4780, type=DOM-API, prop=body, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 213125 and loc.getEndColumn() >= 213125
        ) or 
        (   // id=4781, type=DOM-API, prop=body, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 213125 and loc.getEndColumn() >= 213125
        ) or 
        (   // id=4810, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 224677 and loc.getEndColumn() >= 224677
        ) or 
        (   // id=4814, type=DOM-API, prop=[data-v-owner="6"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4815, type=DOM-API, prop=[data-v-owner="6"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4817, type=DOM-API, prop=[data-v-owner="7"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4818, type=DOM-API, prop=[data-v-owner="7"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4820, type=DOM-API, prop=[data-v-owner="8"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4821, type=DOM-API, prop=[data-v-owner="8"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4823, type=DOM-API, prop=[data-v-owner="9"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4824, type=DOM-API, prop=[data-v-owner="9"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4826, type=DOM-API, prop=[data-v-owner="10"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4827, type=DOM-API, prop=[data-v-owner="10"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4829, type=DOM-API, prop=[data-v-owner="11"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4830, type=DOM-API, prop=[data-v-owner="11"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4832, type=DOM-API, prop=[data-v-owner="12"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4833, type=DOM-API, prop=[data-v-owner="12"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=4857, type=DOM-API, prop=.bili-avatar-img, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 895 and loc.getEndLine() = 895 and
            loc.getStartColumn() <= 2887 and loc.getEndColumn() >= 2887
        ) or 
        (   // id=4858, type=DOM-API, prop=.bili-avatar-img, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 895 and loc.getEndLine() = 895 and
            loc.getStartColumn() <= 2887 and loc.getEndColumn() >= 2887
        ) or 
        (   // id=4860, type=DOM-API, prop=.bili-avatar-img, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 895 and loc.getEndLine() = 895 and
            loc.getStartColumn() <= 655 and loc.getEndColumn() >= 655
        ) or 
        (   // id=4861, type=DOM-API, prop=.bili-avatar-img, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 895 and loc.getEndLine() = 895 and
            loc.getStartColumn() <= 655 and loc.getEndColumn() >= 655
        ) or 
        (   // id=4929, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 248145 and loc.getEndColumn() >= 248145
        ) or 
        (   // id=4937, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 570254 and loc.getEndColumn() >= 570254
        ) or 
        (   // id=4939, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 594418 and loc.getEndColumn() >= 594418
        ) or 
        (   // id=4971, type=DOM-API, prop=biliMainHeader, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 30128 and loc.getEndColumn() >= 30128
        ) or 
        (   // id=4977, type=DOM-API, prop=__css-map__, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 315944 and loc.getEndColumn() >= 315944
        ) or 
        (   // id=4990, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 234 and loc.getEndLine() = 234 and
            loc.getStartColumn() <= 255002 and loc.getEndColumn() >= 255002
        ) or 
        (   // id=4995, type=DOM-API, prop=clip0_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4996, type=DOM-API, prop=filter0_f_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4997, type=DOM-API, prop=paint0_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4998, type=DOM-API, prop=filter1_d_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4999, type=DOM-API, prop=paint1_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5000, type=DOM-API, prop=paint2_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5001, type=DOM-API, prop=filter2_ii_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5002, type=DOM-API, prop=paint3_linear_8665_4990, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5023, type=DOM-API, prop=lottie, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 213402 and loc.getEndColumn() >= 213402
        ) or 
        (   // id=5025, type=DOM-API, prop=bodymovin, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 213459 and loc.getEndColumn() >= 213459
        ) or 
        (   // id=5077, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 56932 and loc.getEndColumn() >= 56932
        ) or 
        (   // id=5080, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 47221 and loc.getEndColumn() >= 47221
        ) or 
        (   // id=5084, type=DOM-API, prop=iframe[src="https://s1.hdslb.com/bfs/seed/jinkela/short/cols/iframe.html"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 648923 and loc.getEndColumn() >= 648923
        ) or 
        (   // id=5085, type=DOM-API, prop=iframe[src="https://s1.hdslb.com/bfs/seed/jinkela/short/cols/iframe.html"], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 648923 and loc.getEndColumn() >= 648923
        ) or 
        (   // id=5089, type=DOM-API, prop=right-entry-item, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 272978 and loc.getEndColumn() >= 272978
        ) or 
        (   // id=5117, type=DOM-API, prop=body, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 47864 and loc.getEndColumn() >= 47864
        ) or 
        (   // id=5118, type=DOM-API, prop=body, api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 47864 and loc.getEndColumn() >= 47864
        ) or 
        (   // id=5136, type=DOM-API, prop=clip0, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5137, type=DOM-API, prop=mask0, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/www.bilibili.com/video/BV1wC411L7ZJ/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=5139, type=DOM-API, prop=meta, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 42 and loc.getEndLine() = 42 and
            loc.getStartColumn() <= 20525 and loc.getEndColumn() >= 20525
        ) or 
        (   // id=5143, type=DOM-API, prop=[data-v-owner="24"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5144, type=DOM-API, prop=[data-v-owner="24"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5145, type=DOM-API, prop=[data-v-owner="26"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5146, type=DOM-API, prop=[data-v-owner="26"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5147, type=DOM-API, prop=[data-v-owner="28"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5148, type=DOM-API, prop=[data-v-owner="28"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5149, type=DOM-API, prop=[data-v-owner="30"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5150, type=DOM-API, prop=[data-v-owner="30"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5151, type=DOM-API, prop=[data-v-owner="32"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5152, type=DOM-API, prop=[data-v-owner="32"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5153, type=DOM-API, prop=[data-v-owner="34"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5154, type=DOM-API, prop=[data-v-owner="34"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5155, type=DOM-API, prop=[data-v-owner="36"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5156, type=DOM-API, prop=[data-v-owner="36"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5157, type=DOM-API, prop=[data-v-owner="38"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5158, type=DOM-API, prop=[data-v-owner="38"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5159, type=DOM-API, prop=[data-v-owner="40"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5160, type=DOM-API, prop=[data-v-owner="40"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5161, type=DOM-API, prop=[data-v-owner="42"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5162, type=DOM-API, prop=[data-v-owner="42"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5163, type=DOM-API, prop=[data-v-owner="44"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5164, type=DOM-API, prop=[data-v-owner="44"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5165, type=DOM-API, prop=[data-v-owner="46"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5166, type=DOM-API, prop=[data-v-owner="46"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5167, type=DOM-API, prop=[data-v-owner="48"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5168, type=DOM-API, prop=[data-v-owner="48"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5169, type=DOM-API, prop=[data-v-owner="50"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5170, type=DOM-API, prop=[data-v-owner="50"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5171, type=DOM-API, prop=[data-v-owner="52"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5172, type=DOM-API, prop=[data-v-owner="52"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5173, type=DOM-API, prop=[data-v-owner="54"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5174, type=DOM-API, prop=[data-v-owner="54"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5175, type=DOM-API, prop=[data-v-owner="56"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5176, type=DOM-API, prop=[data-v-owner="56"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5177, type=DOM-API, prop=[data-v-owner="58"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5178, type=DOM-API, prop=[data-v-owner="58"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5179, type=DOM-API, prop=[data-v-owner="60"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5180, type=DOM-API, prop=[data-v-owner="60"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5181, type=DOM-API, prop=[data-v-owner="62"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5182, type=DOM-API, prop=[data-v-owner="62"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5183, type=DOM-API, prop=[data-v-owner="64"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5184, type=DOM-API, prop=[data-v-owner="64"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5185, type=DOM-API, prop=[data-v-owner="66"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5186, type=DOM-API, prop=[data-v-owner="66"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5187, type=DOM-API, prop=[data-v-owner="68"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5188, type=DOM-API, prop=[data-v-owner="68"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5189, type=DOM-API, prop=[data-v-owner="70"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5190, type=DOM-API, prop=[data-v-owner="70"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5191, type=DOM-API, prop=[data-v-owner="72"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5192, type=DOM-API, prop=[data-v-owner="72"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5193, type=DOM-API, prop=[data-v-owner="74"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5194, type=DOM-API, prop=[data-v-owner="74"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5195, type=DOM-API, prop=[data-v-owner="76"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5196, type=DOM-API, prop=[data-v-owner="76"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5197, type=DOM-API, prop=[data-v-owner="78"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5198, type=DOM-API, prop=[data-v-owner="78"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5199, type=DOM-API, prop=[data-v-owner="80"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5200, type=DOM-API, prop=[data-v-owner="80"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5201, type=DOM-API, prop=[data-v-owner="82"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5202, type=DOM-API, prop=[data-v-owner="82"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5203, type=DOM-API, prop=[data-v-owner="84"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5204, type=DOM-API, prop=[data-v-owner="84"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5205, type=DOM-API, prop=[data-v-owner="86"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5206, type=DOM-API, prop=[data-v-owner="86"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5207, type=DOM-API, prop=[data-v-owner="88"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5208, type=DOM-API, prop=[data-v-owner="88"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5209, type=DOM-API, prop=[data-v-owner="90"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5210, type=DOM-API, prop=[data-v-owner="90"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5211, type=DOM-API, prop=[data-v-owner="92"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5212, type=DOM-API, prop=[data-v-owner="92"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5213, type=DOM-API, prop=[data-v-owner="94"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5214, type=DOM-API, prop=[data-v-owner="94"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5215, type=DOM-API, prop=[data-v-owner="96"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5216, type=DOM-API, prop=[data-v-owner="96"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5217, type=DOM-API, prop=[data-v-owner="98"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5218, type=DOM-API, prop=[data-v-owner="98"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5219, type=DOM-API, prop=[data-v-owner="100"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5220, type=DOM-API, prop=[data-v-owner="100"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5221, type=DOM-API, prop=[data-v-owner="102"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5222, type=DOM-API, prop=[data-v-owner="102"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5223, type=DOM-API, prop=[data-v-owner="104"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5224, type=DOM-API, prop=[data-v-owner="104"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5225, type=DOM-API, prop=[data-v-owner="106"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5226, type=DOM-API, prop=[data-v-owner="106"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5227, type=DOM-API, prop=[data-v-owner="108"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5228, type=DOM-API, prop=[data-v-owner="108"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5229, type=DOM-API, prop=[data-v-owner="110"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5230, type=DOM-API, prop=[data-v-owner="110"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5231, type=DOM-API, prop=[data-v-owner="112"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5232, type=DOM-API, prop=[data-v-owner="112"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5233, type=DOM-API, prop=[data-v-owner="114"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5234, type=DOM-API, prop=[data-v-owner="114"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5235, type=DOM-API, prop=[data-v-owner="116"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5236, type=DOM-API, prop=[data-v-owner="116"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5237, type=DOM-API, prop=[data-v-owner="118"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5238, type=DOM-API, prop=[data-v-owner="118"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5239, type=DOM-API, prop=[data-v-owner="120"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5240, type=DOM-API, prop=[data-v-owner="120"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5241, type=DOM-API, prop=[data-v-owner="122"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5242, type=DOM-API, prop=[data-v-owner="122"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5243, type=DOM-API, prop=[data-v-owner="124"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5244, type=DOM-API, prop=[data-v-owner="124"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5245, type=DOM-API, prop=[data-v-owner="126"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5246, type=DOM-API, prop=[data-v-owner="126"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5247, type=DOM-API, prop=[data-v-owner="128"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5248, type=DOM-API, prop=[data-v-owner="128"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5249, type=DOM-API, prop=[data-v-owner="130"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5250, type=DOM-API, prop=[data-v-owner="130"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5251, type=DOM-API, prop=[data-v-owner="132"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5252, type=DOM-API, prop=[data-v-owner="132"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5253, type=DOM-API, prop=[data-v-owner="134"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5254, type=DOM-API, prop=[data-v-owner="134"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5255, type=DOM-API, prop=[data-v-owner="136"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5256, type=DOM-API, prop=[data-v-owner="136"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5257, type=DOM-API, prop=[data-v-owner="138"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5258, type=DOM-API, prop=[data-v-owner="138"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5259, type=DOM-API, prop=[data-v-owner="140"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5260, type=DOM-API, prop=[data-v-owner="140"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5261, type=DOM-API, prop=[data-v-owner="142"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5262, type=DOM-API, prop=[data-v-owner="142"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5263, type=DOM-API, prop=[data-v-owner="144"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5264, type=DOM-API, prop=[data-v-owner="144"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5265, type=DOM-API, prop=[data-v-owner="146"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5266, type=DOM-API, prop=[data-v-owner="146"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5267, type=DOM-API, prop=[data-v-owner="148"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5268, type=DOM-API, prop=[data-v-owner="148"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5269, type=DOM-API, prop=[data-v-owner="150"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5270, type=DOM-API, prop=[data-v-owner="150"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5271, type=DOM-API, prop=[data-v-owner="152"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5272, type=DOM-API, prop=[data-v-owner="152"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5273, type=DOM-API, prop=[data-v-owner="154"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5274, type=DOM-API, prop=[data-v-owner="154"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5275, type=DOM-API, prop=[data-v-owner="156"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5276, type=DOM-API, prop=[data-v-owner="156"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5277, type=DOM-API, prop=[data-v-owner="158"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5278, type=DOM-API, prop=[data-v-owner="158"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5279, type=DOM-API, prop=[data-v-owner="160"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5280, type=DOM-API, prop=[data-v-owner="160"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5281, type=DOM-API, prop=[data-v-owner="162"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5282, type=DOM-API, prop=[data-v-owner="162"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5283, type=DOM-API, prop=[data-v-owner="164"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5284, type=DOM-API, prop=[data-v-owner="164"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5285, type=DOM-API, prop=[data-v-owner="166"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5286, type=DOM-API, prop=[data-v-owner="166"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5287, type=DOM-API, prop=[data-v-owner="168"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5288, type=DOM-API, prop=[data-v-owner="168"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5289, type=DOM-API, prop=[data-v-owner="170"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5290, type=DOM-API, prop=[data-v-owner="170"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5291, type=DOM-API, prop=[data-v-owner="172"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5292, type=DOM-API, prop=[data-v-owner="172"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5293, type=DOM-API, prop=[data-v-owner="174"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5294, type=DOM-API, prop=[data-v-owner="174"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5295, type=DOM-API, prop=[data-v-owner="176"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5296, type=DOM-API, prop=[data-v-owner="176"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5297, type=DOM-API, prop=[data-v-owner="178"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5298, type=DOM-API, prop=[data-v-owner="178"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5299, type=DOM-API, prop=[data-v-owner="180"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5300, type=DOM-API, prop=[data-v-owner="180"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5301, type=DOM-API, prop=[data-v-owner="182"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5302, type=DOM-API, prop=[data-v-owner="182"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5303, type=DOM-API, prop=[data-v-owner="184"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5304, type=DOM-API, prop=[data-v-owner="184"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5305, type=DOM-API, prop=[data-v-owner="186"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5306, type=DOM-API, prop=[data-v-owner="186"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5307, type=DOM-API, prop=[data-v-owner="188"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5308, type=DOM-API, prop=[data-v-owner="188"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5309, type=DOM-API, prop=[data-v-owner="190"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5310, type=DOM-API, prop=[data-v-owner="190"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5311, type=DOM-API, prop=[data-v-owner="192"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5312, type=DOM-API, prop=[data-v-owner="192"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5313, type=DOM-API, prop=[data-v-owner="194"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5314, type=DOM-API, prop=[data-v-owner="194"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5315, type=DOM-API, prop=[data-v-owner="196"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5316, type=DOM-API, prop=[data-v-owner="196"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5317, type=DOM-API, prop=[data-v-owner="198"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5318, type=DOM-API, prop=[data-v-owner="198"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5319, type=DOM-API, prop=[data-v-owner="200"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5320, type=DOM-API, prop=[data-v-owner="200"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5321, type=DOM-API, prop=[data-v-owner="202"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5322, type=DOM-API, prop=[data-v-owner="202"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5323, type=DOM-API, prop=[data-v-owner="204"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5324, type=DOM-API, prop=[data-v-owner="204"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5325, type=DOM-API, prop=[data-v-owner="206"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5326, type=DOM-API, prop=[data-v-owner="206"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5327, type=DOM-API, prop=[data-v-owner="208"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5328, type=DOM-API, prop=[data-v-owner="208"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5329, type=DOM-API, prop=[data-v-owner="210"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5330, type=DOM-API, prop=[data-v-owner="210"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5331, type=DOM-API, prop=[data-v-owner="212"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5332, type=DOM-API, prop=[data-v-owner="212"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5333, type=DOM-API, prop=[data-v-owner="214"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5334, type=DOM-API, prop=[data-v-owner="214"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5335, type=DOM-API, prop=[data-v-owner="216"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5336, type=DOM-API, prop=[data-v-owner="216"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5337, type=DOM-API, prop=[data-v-owner="218"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5338, type=DOM-API, prop=[data-v-owner="218"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5339, type=DOM-API, prop=[data-v-owner="220"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5340, type=DOM-API, prop=[data-v-owner="220"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5341, type=DOM-API, prop=[data-v-owner="222"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5342, type=DOM-API, prop=[data-v-owner="222"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5343, type=DOM-API, prop=[data-v-owner="224"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5344, type=DOM-API, prop=[data-v-owner="224"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5345, type=DOM-API, prop=[data-v-owner="226"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5346, type=DOM-API, prop=[data-v-owner="226"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5347, type=DOM-API, prop=[data-v-owner="228"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5348, type=DOM-API, prop=[data-v-owner="228"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5349, type=DOM-API, prop=[data-v-owner="230"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5350, type=DOM-API, prop=[data-v-owner="230"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5351, type=DOM-API, prop=[data-v-owner="232"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5352, type=DOM-API, prop=[data-v-owner="232"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5353, type=DOM-API, prop=[data-v-owner="234"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5354, type=DOM-API, prop=[data-v-owner="234"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5355, type=DOM-API, prop=[data-v-owner="236"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5356, type=DOM-API, prop=[data-v-owner="236"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5357, type=DOM-API, prop=[data-v-owner="238"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5358, type=DOM-API, prop=[data-v-owner="238"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5359, type=DOM-API, prop=[data-v-owner="240"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5360, type=DOM-API, prop=[data-v-owner="240"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5361, type=DOM-API, prop=[data-v-owner="242"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5362, type=DOM-API, prop=[data-v-owner="242"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5363, type=DOM-API, prop=[data-v-owner="244"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5364, type=DOM-API, prop=[data-v-owner="244"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5365, type=DOM-API, prop=[data-v-owner="246"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5366, type=DOM-API, prop=[data-v-owner="246"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5367, type=DOM-API, prop=[data-v-owner="248"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5368, type=DOM-API, prop=[data-v-owner="248"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5369, type=DOM-API, prop=[data-v-owner="250"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5370, type=DOM-API, prop=[data-v-owner="250"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5371, type=DOM-API, prop=[data-v-owner="252"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5372, type=DOM-API, prop=[data-v-owner="252"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5373, type=DOM-API, prop=[data-v-owner="254"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5374, type=DOM-API, prop=[data-v-owner="254"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5375, type=DOM-API, prop=[data-v-owner="256"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5376, type=DOM-API, prop=[data-v-owner="256"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5377, type=DOM-API, prop=[data-v-owner="258"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5378, type=DOM-API, prop=[data-v-owner="258"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5379, type=DOM-API, prop=[data-v-owner="260"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5380, type=DOM-API, prop=[data-v-owner="260"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5381, type=DOM-API, prop=[data-v-owner="262"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5382, type=DOM-API, prop=[data-v-owner="262"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5383, type=DOM-API, prop=[data-v-owner="264"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5384, type=DOM-API, prop=[data-v-owner="264"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5385, type=DOM-API, prop=[data-v-owner="266"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5386, type=DOM-API, prop=[data-v-owner="266"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5387, type=DOM-API, prop=[data-v-owner="268"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5388, type=DOM-API, prop=[data-v-owner="268"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5389, type=DOM-API, prop=[data-v-owner="270"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5390, type=DOM-API, prop=[data-v-owner="270"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5391, type=DOM-API, prop=[data-v-owner="272"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5392, type=DOM-API, prop=[data-v-owner="272"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5393, type=DOM-API, prop=[data-v-owner="274"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5394, type=DOM-API, prop=[data-v-owner="274"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5395, type=DOM-API, prop=[data-v-owner="276"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5396, type=DOM-API, prop=[data-v-owner="276"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5397, type=DOM-API, prop=[data-v-owner="278"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5398, type=DOM-API, prop=[data-v-owner="278"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5399, type=DOM-API, prop=[data-v-owner="280"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5400, type=DOM-API, prop=[data-v-owner="280"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5401, type=DOM-API, prop=[data-v-owner="282"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5402, type=DOM-API, prop=[data-v-owner="282"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5403, type=DOM-API, prop=[data-v-owner="284"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5404, type=DOM-API, prop=[data-v-owner="284"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5405, type=DOM-API, prop=[data-v-owner="286"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5406, type=DOM-API, prop=[data-v-owner="286"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5407, type=DOM-API, prop=[data-v-owner="288"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5408, type=DOM-API, prop=[data-v-owner="288"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5409, type=DOM-API, prop=[data-v-owner="290"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5410, type=DOM-API, prop=[data-v-owner="290"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5411, type=DOM-API, prop=[data-v-owner="292"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5412, type=DOM-API, prop=[data-v-owner="292"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5413, type=DOM-API, prop=[data-v-owner="294"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5414, type=DOM-API, prop=[data-v-owner="294"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5415, type=DOM-API, prop=[data-v-owner="296"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5416, type=DOM-API, prop=[data-v-owner="296"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5417, type=DOM-API, prop=[data-v-owner="298"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5418, type=DOM-API, prop=[data-v-owner="298"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5419, type=DOM-API, prop=[data-v-owner="300"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5420, type=DOM-API, prop=[data-v-owner="300"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5421, type=DOM-API, prop=[data-v-owner="302"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5422, type=DOM-API, prop=[data-v-owner="302"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5423, type=DOM-API, prop=[data-v-owner="304"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5424, type=DOM-API, prop=[data-v-owner="304"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5425, type=DOM-API, prop=[data-v-owner="306"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5426, type=DOM-API, prop=[data-v-owner="306"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5427, type=DOM-API, prop=[data-v-owner="308"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5428, type=DOM-API, prop=[data-v-owner="308"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5429, type=DOM-API, prop=[data-v-owner="310"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5430, type=DOM-API, prop=[data-v-owner="310"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5431, type=DOM-API, prop=[data-v-owner="312"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5432, type=DOM-API, prop=[data-v-owner="312"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5433, type=DOM-API, prop=[data-v-owner="314"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5434, type=DOM-API, prop=[data-v-owner="314"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5435, type=DOM-API, prop=[data-v-owner="316"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5436, type=DOM-API, prop=[data-v-owner="316"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5437, type=DOM-API, prop=[data-v-owner="318"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5438, type=DOM-API, prop=[data-v-owner="318"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5439, type=DOM-API, prop=[data-v-owner="320"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5440, type=DOM-API, prop=[data-v-owner="320"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5441, type=DOM-API, prop=[data-v-owner="322"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5442, type=DOM-API, prop=[data-v-owner="322"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5443, type=DOM-API, prop=[data-v-owner="324"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5444, type=DOM-API, prop=[data-v-owner="324"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5445, type=DOM-API, prop=[data-v-owner="326"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5446, type=DOM-API, prop=[data-v-owner="326"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5447, type=DOM-API, prop=[data-v-owner="328"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5448, type=DOM-API, prop=[data-v-owner="328"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5449, type=DOM-API, prop=[data-v-owner="330"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5450, type=DOM-API, prop=[data-v-owner="330"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5451, type=DOM-API, prop=[data-v-owner="332"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5452, type=DOM-API, prop=[data-v-owner="332"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5453, type=DOM-API, prop=[data-v-owner="334"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5454, type=DOM-API, prop=[data-v-owner="334"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5455, type=DOM-API, prop=[data-v-owner="336"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5456, type=DOM-API, prop=[data-v-owner="336"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5572, type=DOM-API, prop=[data-v-owner="338"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5573, type=DOM-API, prop=[data-v-owner="338"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5574, type=DOM-API, prop=[data-v-owner="339"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5575, type=DOM-API, prop=[data-v-owner="339"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5576, type=DOM-API, prop=[data-v-owner="340"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5577, type=DOM-API, prop=[data-v-owner="340"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5578, type=DOM-API, prop=[data-v-owner="342"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5579, type=DOM-API, prop=[data-v-owner="342"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5580, type=DOM-API, prop=[data-v-owner="343"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5581, type=DOM-API, prop=[data-v-owner="343"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5582, type=DOM-API, prop=[data-v-owner="345"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5583, type=DOM-API, prop=[data-v-owner="345"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5584, type=DOM-API, prop=[data-v-owner="346"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5585, type=DOM-API, prop=[data-v-owner="346"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5586, type=DOM-API, prop=[data-v-owner="348"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5587, type=DOM-API, prop=[data-v-owner="348"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5588, type=DOM-API, prop=[data-v-owner="353"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5589, type=DOM-API, prop=[data-v-owner="353"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5590, type=DOM-API, prop=[data-v-owner="355"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5591, type=DOM-API, prop=[data-v-owner="355"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5592, type=DOM-API, prop=[data-v-owner="357"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5593, type=DOM-API, prop=[data-v-owner="357"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5594, type=DOM-API, prop=[data-v-owner="358"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5595, type=DOM-API, prop=[data-v-owner="358"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5596, type=DOM-API, prop=[data-v-owner="360"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5597, type=DOM-API, prop=[data-v-owner="360"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5598, type=DOM-API, prop=[data-v-owner="364"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5599, type=DOM-API, prop=[data-v-owner="364"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5600, type=DOM-API, prop=[data-v-owner="366"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5601, type=DOM-API, prop=[data-v-owner="366"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5602, type=DOM-API, prop=[data-v-owner="368"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5603, type=DOM-API, prop=[data-v-owner="368"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5604, type=DOM-API, prop=[data-v-owner="369"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5605, type=DOM-API, prop=[data-v-owner="369"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5606, type=DOM-API, prop=[data-v-owner="371"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5607, type=DOM-API, prop=[data-v-owner="371"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5608, type=DOM-API, prop=[data-v-owner="375"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5609, type=DOM-API, prop=[data-v-owner="375"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5610, type=DOM-API, prop=[data-v-owner="377"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5611, type=DOM-API, prop=[data-v-owner="377"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5612, type=DOM-API, prop=[data-v-owner="379"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5613, type=DOM-API, prop=[data-v-owner="379"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5614, type=DOM-API, prop=[data-v-owner="380"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5615, type=DOM-API, prop=[data-v-owner="380"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5616, type=DOM-API, prop=[data-v-owner="382"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5617, type=DOM-API, prop=[data-v-owner="382"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5618, type=DOM-API, prop=[data-v-owner="386"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5619, type=DOM-API, prop=[data-v-owner="386"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5620, type=DOM-API, prop=[data-v-owner="388"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5621, type=DOM-API, prop=[data-v-owner="388"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5622, type=DOM-API, prop=[data-v-owner="390"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5623, type=DOM-API, prop=[data-v-owner="390"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5624, type=DOM-API, prop=[data-v-owner="391"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5625, type=DOM-API, prop=[data-v-owner="391"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5626, type=DOM-API, prop=[data-v-owner="393"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5627, type=DOM-API, prop=[data-v-owner="393"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5628, type=DOM-API, prop=[data-v-owner="398"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5629, type=DOM-API, prop=[data-v-owner="398"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5630, type=DOM-API, prop=[data-v-owner="400"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5631, type=DOM-API, prop=[data-v-owner="400"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5632, type=DOM-API, prop=[data-v-owner="402"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5633, type=DOM-API, prop=[data-v-owner="402"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5634, type=DOM-API, prop=[data-v-owner="403"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5635, type=DOM-API, prop=[data-v-owner="403"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5636, type=DOM-API, prop=[data-v-owner="405"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5637, type=DOM-API, prop=[data-v-owner="405"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5638, type=DOM-API, prop=[data-v-owner="409"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5639, type=DOM-API, prop=[data-v-owner="409"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5640, type=DOM-API, prop=[data-v-owner="411"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5641, type=DOM-API, prop=[data-v-owner="411"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5642, type=DOM-API, prop=[data-v-owner="413"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5643, type=DOM-API, prop=[data-v-owner="413"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5644, type=DOM-API, prop=[data-v-owner="414"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5645, type=DOM-API, prop=[data-v-owner="414"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5646, type=DOM-API, prop=[data-v-owner="416"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5647, type=DOM-API, prop=[data-v-owner="416"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5648, type=DOM-API, prop=[data-v-owner="420"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5649, type=DOM-API, prop=[data-v-owner="420"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5650, type=DOM-API, prop=[data-v-owner="422"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5651, type=DOM-API, prop=[data-v-owner="422"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5652, type=DOM-API, prop=[data-v-owner="424"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5653, type=DOM-API, prop=[data-v-owner="424"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5654, type=DOM-API, prop=[data-v-owner="425"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5655, type=DOM-API, prop=[data-v-owner="425"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5656, type=DOM-API, prop=[data-v-owner="427"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5657, type=DOM-API, prop=[data-v-owner="427"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/jinkela/commentpc/comment-pc-vue.next.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 222876 and loc.getEndColumn() >= 222876
        ) or 
        (   // id=5758, type=DOM-API, prop=meta[name=spm_prefix], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 698345 and loc.getEndColumn() >= 698345
        ) or 
        (   // id=5759, type=DOM-API, prop=meta[name=spm_prefix], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 698345 and loc.getEndColumn() >= 698345
        ) or 
        (   // id=6079, type=DOM-API, prop=meta[name=spm_prefix], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 805261 and loc.getEndColumn() >= 805261
        ) or 
        (   // id=6080, type=DOM-API, prop=meta[name=spm_prefix], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 805261 and loc.getEndColumn() >= 805261
        ) or 
        (   // id=6114, type=DOM-API, prop=body, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/laputa-header/bili-header.umd.js") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 1047019 and loc.getEndColumn() >= 1047019
        ) or 
        (   // id=6133, type=DOM-API, prop=head, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/seed/blive/blfe-link-shortassets/dist/component.statistics/log-reporter.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 25434 and loc.getEndColumn() >= 25434
        ) or 
        (   // id=6467, type=DOM-API, prop=alttext-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 1218 and loc.getEndColumn() >= 1218
        ) or 
        (   // id=6468, type=DOM-API, prop=alttext-image, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 1218 and loc.getEndColumn() >= 1218
        ) or 
        (   // id=6479, type=DOM-API, prop=[x-arrow], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 11391 and loc.getEndColumn() >= 11391
        ) or 
        (   // id=6480, type=DOM-API, prop=[x-arrow], api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 11391 and loc.getEndColumn() >= 11391
        ) or 
        (   // id=6488, type=DOM-API, prop=alttext-container, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 1852 and loc.getEndColumn() >= 1852
        ) or 
        (   // id=6489, type=DOM-API, prop=alttext-image, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/SafeLookup/output/html-injection/test-crawler-04-05-16-01/www.bilibili.com/baae65bbda/source/s1.hdslb.com/bfs/static/jinkela/video/stardust-video.74405eb1f35de120b3b613bb2b222c585d282fc0.js") and
            loc.getStartLine() = 136 and loc.getEndLine() = 136 and
            loc.getStartColumn() <= 1852 and loc.getEndColumn() >= 1852
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

DebuggingConfig() { this = "DOM-Clobbering-www.bilibili.com-baae65bbda" }
    
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
