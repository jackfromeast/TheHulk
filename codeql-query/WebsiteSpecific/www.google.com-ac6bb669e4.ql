/**
* @name DOM-Clobbering-www.google.com-ac6bb669e4
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
        (   // id=1, type=WIN-TYPE-1, prop=google 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 424 and loc.getEndColumn() >= 424
        ) or 
        (   // id=2, type=WIN-TYPE-1, prop=google 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 474 and loc.getEndColumn() >= 474
        ) or 
        (   // id=11, type=WIN-TYPE-1, prop=gws_wizbind 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 492 and loc.getEndColumn() >= 492
        ) or 
        (   // id=12, type=WIN-TYPE-1, prop=_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 2794 and loc.getEndColumn() >= 2794
        ) or 
        (   // id=13, type=WIN-TYPE-1, prop=_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 2785 and loc.getEndColumn() >= 2785
        ) or 
        (   // id=14, type=WIN-TYPE-1, prop=_DumpException 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 2824 and loc.getEndColumn() >= 2824
        ) or 
        (   // id=15, type=WIN-TYPE-1, prop=_s 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 2886 and loc.getEndColumn() >= 2886
        ) or 
        (   // id=16, type=WIN-TYPE-1, prop=_s 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 2877 and loc.getEndColumn() >= 2877
        ) or 
        (   // id=17, type=WIN-TYPE-1, prop=_qs 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 2952 and loc.getEndColumn() >= 2952
        ) or 
        (   // id=18, type=WIN-TYPE-1, prop=_qs 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 2943 and loc.getEndColumn() >= 2943
        ) or 
        (   // id=19, type=WIN-TYPE-1, prop=_xjs_toggles 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 3395 and loc.getEndColumn() >= 3395
        ) or 
        (   // id=20, type=WIN-TYPE-1, prop=_F_toggles 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 3373 and loc.getEndColumn() >= 3373
        ) or 
        (   // id=21, type=WIN-TYPE-1, prop=_F_jsUrl 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 24 and loc.getEndLine() = 24 and
            loc.getStartColumn() <= 2559 and loc.getEndColumn() >= 2559
        ) or 
        (   // id=22, type=WIN-TYPE-1, prop=mei 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 25 and loc.getEndLine() = 25 and
            loc.getStartColumn() <= 37 and loc.getEndColumn() >= 37
        ) or 
        (   // id=23, type=WIN-TYPE-1, prop=sdo 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 25 and loc.getEndLine() = 25 and
            loc.getStartColumn() <= 61 and loc.getEndColumn() >= 61
        ) or 
        (   // id=24, type=WIN-TYPE-1, prop=gbar_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 26 and loc.getEndLine() = 26 and
            loc.getStartColumn() <= 875 and loc.getEndColumn() >= 875
        ) or 
        (   // id=25, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 49 and loc.getEndLine() = 49 and
            loc.getStartColumn() <= 116 and loc.getEndColumn() >= 116
        ) or 
        (   // id=26, type=WIN-TYPE-1, prop=WIZ_global_data 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 50 and loc.getEndLine() = 50 and
            loc.getStartColumn() <= 450 and loc.getEndColumn() >= 450
        ) or 
        (   // id=28, type=WIN-TYPE-1, prop=gbar 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 52 and loc.getEndLine() = 52 and
            loc.getStartColumn() <= 48 and loc.getEndColumn() >= 48
        ) or 
        (   // id=29, type=WIN-TYPE-1, prop=execScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 52 and loc.getEndLine() = 52 and
            loc.getStartColumn() <= 76 and loc.getEndColumn() >= 76
        ) or 
        (   // id=30, type=WIN-TYPE-1, prop=gbar 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 52 and loc.getEndLine() = 52 and
            loc.getStartColumn() <= 171 and loc.getEndColumn() >= 171
        ) or 
        (   // id=31, type=WIN-TYPE-1, prop=gbar 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 52 and loc.getEndLine() = 52 and
            loc.getStartColumn() <= 216 and loc.getEndColumn() >= 216
        ) or 
        (   // id=32, type=WIN-TYPE-1, prop=__PVT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 56 and loc.getEndLine() = 56 and
            loc.getStartColumn() <= 61 and loc.getEndColumn() >= 61
        ) or 
        (   // id=33, type=WIN-TYPE-1, prop=gapi 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 62 and loc.getEndLine() = 62 and
            loc.getStartColumn() <= 184 and loc.getEndColumn() >= 184
        ) or 
        (   // id=34, type=WIN-TYPE-1, prop=___jsl 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 62 and loc.getEndLine() = 62 and
            loc.getStartColumn() <= 207 and loc.getEndColumn() >= 207
        ) or 
        (   // id=40, type=WIN-TYPE-1, prop=sbmlhf 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 67 and loc.getEndLine() = 67 and
            loc.getStartColumn() <= 191 and loc.getEndColumn() >= 191
        ) or 
        (   // id=92, type=WIN-TYPE-1, prop=W_jd 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 113 and loc.getEndLine() = 113 and
            loc.getStartColumn() <= 5585 and loc.getEndColumn() >= 5585
        ) or 
        (   // id=93, type=WIN-TYPE-1, prop=W_jd 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 113 and loc.getEndLine() = 113 and
            loc.getStartColumn() <= 5641 and loc.getEndColumn() >= 5641
        ) or 
        (   // id=94, type=WIN-TYPE-1, prop=WIZ_global_data 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 113 and loc.getEndLine() = 113 and
            loc.getStartColumn() <= 5683 and loc.getEndColumn() >= 5683
        ) or 
        (   // id=95, type=WIN-TYPE-1, prop=IJ_values 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 113 and loc.getEndLine() = 113 and
            loc.getStartColumn() <= 6123 and loc.getEndColumn() >= 6123
        ) or 
        (   // id=98, type=WIN-TYPE-1, prop=CLOSURE_FLAGS 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 114 and loc.getEndLine() = 114 and
            loc.getStartColumn() <= 86 and loc.getEndColumn() >= 86
        ) or 
        (   // id=100, type=WIN-TYPE-1, prop=jsl 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 115 and loc.getEndLine() = 115 and
            loc.getStartColumn() <= 486 and loc.getEndColumn() >= 486
        ) or 
        (   // id=101, type=WIN-TYPE-1, prop=jsl 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 115 and loc.getEndLine() = 115 and
            loc.getStartColumn() <= 478 and loc.getEndColumn() >= 478
        ) or 
        (   // id=102, type=WIN-TYPE-1, prop=_hd 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 15 and loc.getEndColumn() >= 15
        ) or 
        (   // id=103, type=WIN-TYPE-1, prop=_hd 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 9 and loc.getEndColumn() >= 9
        ) or 
        (   // id=104, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 297 and loc.getEndLine() = 297 and
            loc.getStartColumn() <= 372 and loc.getEndColumn() >= 372
        ) or 
        (   // id=105, type=WIN-TYPE-1, prop=ontouchstart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 436 and loc.getEndLine() = 436 and
            loc.getStartColumn() <= 397 and loc.getEndColumn() >= 397
        ) or 
        (   // id=108, type=WIN-TYPE-1, prop=closure_listenable_300768 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 440 and loc.getEndLine() = 440 and
            loc.getStartColumn() <= 278 and loc.getEndColumn() >= 278
        ) or 
        (   // id=109, type=WIN-TYPE-1, prop=closure_lm_694676 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 448 and loc.getEndLine() = 448 and
            loc.getStartColumn() <= 385 and loc.getEndColumn() >= 385
        ) or 
        (   // id=110, type=WIN-TYPE-1, prop=closure_lm_694676 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 443 and loc.getEndLine() = 443 and
            loc.getStartColumn() <= 100 and loc.getEndColumn() >= 100
        ) or 
        (   // id=116, type=WIN-TYPE-1, prop=mPPkxd 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 688 and loc.getEndLine() = 688 and
            loc.getStartColumn() <= 239 and loc.getEndColumn() >= 239
        ) or 
        (   // id=117, type=WIN-TYPE-1, prop=lnk 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 283 and loc.getEndLine() = 283 and
            loc.getStartColumn() <= 110 and loc.getEndColumn() >= 110
        ) or 
        (   // id=118, type=WIN-TYPE-1, prop=lnk 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 283 and loc.getEndLine() = 283 and
            loc.getStartColumn() <= 121 and loc.getEndColumn() >= 121
        ) or 
        (   // id=125, type=WIN-TYPE-1, prop=silk 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1043 and loc.getEndLine() = 1043 and
            loc.getStartColumn() <= 166 and loc.getEndColumn() >= 166
        ) or 
        (   // id=126, type=WIN-TYPE-1, prop=silk 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1043 and loc.getEndLine() = 1043 and
            loc.getStartColumn() <= 160 and loc.getEndColumn() >= 160
        ) or 
        (   // id=127, type=WIN-TYPE-1, prop=_F_installCssProto 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 355 and loc.getEndLine() = 355 and
            loc.getStartColumn() <= 413 and loc.getEndColumn() >= 413
        ) or 
        (   // id=128, type=WIN-TYPE-1, prop=execScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 355 and loc.getEndLine() = 355 and
            loc.getStartColumn() <= 441 and loc.getEndColumn() >= 441
        ) or 
        (   // id=129, type=WIN-TYPE-1, prop=_F_installCssProto 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 355 and loc.getEndLine() = 355 and
            loc.getStartColumn() <= 589 and loc.getEndColumn() >= 589
        ) or 
        (   // id=148, type=WIN-TYPE-1, prop=wiz_progress 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 979 and loc.getEndLine() = 979 and
            loc.getStartColumn() <= 201 and loc.getEndColumn() >= 201
        ) or 
        (   // id=159, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 495 and loc.getEndLine() = 495 and
            loc.getStartColumn() <= 205 and loc.getEndColumn() >= 205
        ) or 
        (   // id=397, type=WIN-TYPE-1, prop=_cshid 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 149 and loc.getEndLine() = 149 and
            loc.getStartColumn() <= 209 and loc.getEndColumn() >= 209
        ) or 
        (   // id=410, type=WIN-TYPE-1, prop=_cshid 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 9 and loc.getEndLine() = 9 and
            loc.getStartColumn() <= 446 and loc.getEndColumn() >= 446
        ) or 
        (   // id=511, type=WIN-TYPE-1, prop=userfeedback 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 355 and loc.getEndLine() = 355 and
            loc.getStartColumn() <= 413 and loc.getEndColumn() >= 413
        ) or 
        (   // id=513, type=WIN-TYPE-1, prop=userfeedback 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 355 and loc.getEndLine() = 355 and
            loc.getStartColumn() <= 536 and loc.getEndColumn() >= 536
        ) or 
        (   // id=514, type=WIN-TYPE-1, prop=userfeedback 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 355 and loc.getEndLine() = 355 and
            loc.getStartColumn() <= 581 and loc.getEndColumn() >= 581
        ) or 
        (   // id=515, type=WIN-TYPE-1, prop=ka 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1083 and loc.getEndLine() = 1083 and
            loc.getStartColumn() <= 715 and loc.getEndColumn() >= 715
        ) or 
        (   // id=517, type=WIN-TYPE-1, prop=ka 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1328 and loc.getEndLine() = 1328 and
            loc.getStartColumn() <= 339 and loc.getEndColumn() >= 339
        ) or 
        (   // id=531, type=WIN-TYPE-1, prop=guestRootElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 215 and loc.getEndLine() = 215 and
            loc.getStartColumn() <= 427 and loc.getEndColumn() >= 427
        ) or 
        (   // id=716, type=WIN-TYPE-1, prop=_ck 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1037 and loc.getEndLine() = 1037 and
            loc.getStartColumn() <= 537 and loc.getEndColumn() >= 537
        ) or 
        (   // id=722, type=WIN-TYPE-1, prop=_cshid 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 33 and loc.getEndLine() = 33 and
            loc.getStartColumn() <= 451 and loc.getEndColumn() >= 451
        ) or 
        (   // id=841, type=WIN-TYPE-1, prop=closure_uid_259688637 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 99 and loc.getEndLine() = 99 and
            loc.getStartColumn() <= 219 and loc.getEndColumn() >= 219
        ) or 
        (   // id=842, type=WIN-TYPE-1, prop=closure_listenable_712754 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 16 and loc.getEndLine() = 16 and
            loc.getStartColumn() <= 541 and loc.getEndColumn() >= 541
        ) or 
        (   // id=843, type=WIN-TYPE-1, prop=closure_lm_102326 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 22 and loc.getEndLine() = 22 and
            loc.getStartColumn() <= 144 and loc.getEndColumn() >= 144
        ) or 
        (   // id=844, type=WIN-TYPE-1, prop=closure_lm_102326 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 19 and loc.getEndLine() = 19 and
            loc.getStartColumn() <= 98 and loc.getEndColumn() >= 98
        ) or 
        (   // id=931, type=WIN-TYPE-1, prop=___gapisync 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 513 and loc.getEndLine() = 513 and
            loc.getStartColumn() <= 407 and loc.getEndColumn() >= 407
        ) or 
        (   // id=961, type=WIN-TYPE-1, prop=WIZ_global_data 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 423 and loc.getEndColumn() >= 423
        ) or 
        (   // id=962, type=WIN-TYPE-1, prop=cc_latency_start_time 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1250 and loc.getEndColumn() >= 1250
        ) or 
        (   // id=963, type=WIN-TYPE-1, prop=onaft 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1552 and loc.getEndColumn() >= 1552
        ) or 
        (   // id=964, type=WIN-TYPE-1, prop=_isLazyImage 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1588 and loc.getEndColumn() >= 1588
        ) or 
        (   // id=965, type=WIN-TYPE-1, prop=l 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 4 and loc.getEndColumn() >= 4
        ) or 
        (   // id=966, type=WIN-TYPE-1, prop=cc_aid 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 145 and loc.getEndColumn() >= 145
        ) or 
        (   // id=967, type=WIN-TYPE-1, prop=iml_start 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 159 and loc.getEndColumn() >= 159
        ) or 
        (   // id=968, type=WIN-TYPE-1, prop=css_size 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 194 and loc.getEndColumn() >= 194
        ) or 
        (   // id=969, type=WIN-TYPE-1, prop=cc_latency 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 209 and loc.getEndColumn() >= 209
        ) or 
        (   // id=970, type=WIN-TYPE-1, prop=ccTick 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 221 and loc.getEndColumn() >= 221
        ) or 
        (   // id=971, type=WIN-TYPE-1, prop=onJsLoad 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 234 and loc.getEndColumn() >= 234
        ) or 
        (   // id=972, type=WIN-TYPE-1, prop=onCssLoad 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 267 and loc.getEndColumn() >= 267
        ) or 
        (   // id=973, type=WIN-TYPE-1, prop=_isVisible 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 302 and loc.getEndColumn() >= 302
        ) or 
        (   // id=974, type=WIN-TYPE-1, prop=_recordImlEl 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 252 and loc.getEndColumn() >= 252
        ) or 
        (   // id=976, type=WIN-TYPE-1, prop=prt 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 65 and loc.getEndColumn() >= 65
        ) or 
        (   // id=977, type=WIN-TYPE-1, prop=wiz_tick 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 79 and loc.getEndColumn() >= 79
        ) or 
        (   // id=979, type=WIN-TYPE-1, prop=BOQ_wizbind 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 42 and loc.getEndLine() = 42 and
            loc.getStartColumn() <= 17 and loc.getEndColumn() >= 17
        ) or 
        (   // id=980, type=WIN-TYPE-1, prop=execScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 42 and loc.getEndLine() = 42 and
            loc.getStartColumn() <= 45 and loc.getEndColumn() >= 45
        ) or 
        (   // id=981, type=WIN-TYPE-1, prop=BOQ_wizbind 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 42 and loc.getEndLine() = 42 and
            loc.getStartColumn() <= 193 and loc.getEndColumn() >= 193
        ) or 
        (   // id=982, type=WIN-TYPE-1, prop=BOQ_loadedInitialJS 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 43 and loc.getEndLine() = 43 and
            loc.getStartColumn() <= 355 and loc.getEndColumn() >= 355
        ) or 
        (   // id=985, type=WIN-TYPE-1, prop=_wjdc 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 44 and loc.getEndLine() = 44 and
            loc.getStartColumn() <= 21 and loc.getEndColumn() >= 21
        ) or 
        (   // id=989, type=WIN-TYPE-1, prop=aft_counter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 442 and loc.getEndColumn() >= 442
        ) or 
        (   // id=991, type=WIN-TYPE-1, prop=wiz_progress 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 56 and loc.getEndLine() = 56 and
            loc.getStartColumn() <= 719 and loc.getEndColumn() >= 719
        ) or 
        (   // id=992, type=WIN-TYPE-1, prop=wiz_progress 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 56 and loc.getEndLine() = 56 and
            loc.getStartColumn() <= 2839 and loc.getEndColumn() >= 2839
        ) or 
        (   // id=993, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 116 and loc.getEndColumn() >= 116
        ) or 
        (   // id=994, type=WIN-TYPE-1, prop=osapi 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 42 and loc.getEndLine() = 42 and
            loc.getStartColumn() <= 282 and loc.getEndColumn() >= 282
        ) or 
        (   // id=995, type=WIN-TYPE-1, prop=osapi 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 42 and loc.getEndLine() = 42 and
            loc.getStartColumn() <= 274 and loc.getEndColumn() >= 274
        ) or 
        (   // id=996, type=WIN-TYPE-1, prop=__GOOGLEAPIS 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 188 and loc.getEndColumn() >= 188
        ) or 
        (   // id=997, type=WIN-TYPE-1, prop=___gcfg 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 99 and loc.getEndLine() = 99 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=998, type=WIN-TYPE-1, prop=___gu 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 99 and loc.getEndLine() = 99 and
            loc.getStartColumn() <= 64 and loc.getEndColumn() >= 64
        ) or 
        (   // id=1004, type=WIN-TYPE-1, prop=gadgets 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 298 and loc.getEndColumn() >= 298
        ) or 
        (   // id=1005, type=WIN-TYPE-1, prop=execScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 326 and loc.getEndColumn() >= 326
        ) or 
        (   // id=1006, type=WIN-TYPE-1, prop=gadgets 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 423 and loc.getEndColumn() >= 423
        ) or 
        (   // id=1007, type=WIN-TYPE-1, prop=gadgets 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 464 and loc.getEndColumn() >= 464
        ) or 
        (   // id=1008, type=WIN-TYPE-1, prop=googleapis 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 254 and loc.getEndLine() = 254 and
            loc.getStartColumn() <= 13 and loc.getEndColumn() >= 13
        ) or 
        (   // id=1009, type=WIN-TYPE-1, prop=shindig 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 298 and loc.getEndColumn() >= 298
        ) or 
        (   // id=1011, type=WIN-TYPE-1, prop=shindig 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 423 and loc.getEndColumn() >= 423
        ) or 
        (   // id=1012, type=WIN-TYPE-1, prop=shindig 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 464 and loc.getEndColumn() >= 464
        ) or 
        (   // id=1013, type=WIN-TYPE-1, prop=googleapis 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 298 and loc.getEndColumn() >= 298
        ) or 
        (   // id=1015, type=WIN-TYPE-1, prop=googleapis 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 423 and loc.getEndColumn() >= 423
        ) or 
        (   // id=1016, type=WIN-TYPE-1, prop=googleapis 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 41 and loc.getEndLine() = 41 and
            loc.getStartColumn() <= 464 and loc.getEndColumn() >= 464
        ) or 
        (   // id=1032, type=WIN-TYPE-1, prop=orientation 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/xjs/_/js/kxjs.hd.en.9VMe68TGzN4.O/amAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAABABFAAAIACAAAIAAAAAAACQwCAAIAALAKACAhCEAAYAEIQgIcyAYCACQAAAAgACAEIAgCAAAAAgAIAAAAAAAAAAAAGCCAAAAAAAAAAAAAA0AkAgAAAIBggBAAgAAAAAHkAggNgkIIAAAAAAAAAAAAAAAFIEMwFCSgIgAAAAAAAAAAAAAAASKUTC2M/d0/dg2/br1/rsACT90oEA5KegFWp9Y33gf06GzqXHTdr8mg/msyev,aLUfP.html") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 121 and loc.getEndColumn() >= 121
        ) or 
        (   // id=1033, type=WIN-TYPE-1, prop=orientation 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/xjs/_/js/kxjs.hd.en.9VMe68TGzN4.O/amAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAABABFAAAIACAAAIAAAAAAACQwCAAIAALAKACAhCEAAYAEIQgIcyAYCACQAAAAgACAEIAgCAAAAAgAIAAAAAAAAAAAAGCCAAAAAAAAAAAAAA0AkAgAAAIBggBAAgAAAAAHkAggNgkIIAAAAAAAAAAAAAAAFIEMwFCSgIgAAAAAAAAAAAAAAASKUTC2M/d0/dg2/br1/rsACT90oEA5KegFWp9Y33gf06GzqXHTdr8mg/msyev,aLUfP.html") and
            loc.getStartLine() = 10 and loc.getEndLine() = 10 and
            loc.getStartColumn() <= 206 and loc.getEndColumn() >= 206
        ) or 
        (   // id=1035, type=WIN-TYPE-1, prop=aft_counter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 56 and loc.getEndLine() = 56 and
            loc.getStartColumn() <= 3022 and loc.getEndColumn() >= 3022
        ) or 
        (   // id=1036, type=WIN-TYPE-1, prop=initAft 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 57 and loc.getEndLine() = 57 and
            loc.getStartColumn() <= 10 and loc.getEndColumn() >= 10
        ) or 
        (   // id=1043, type=WIN-TYPE-1, prop=IJ_values 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 84 and loc.getEndColumn() >= 84
        ) or 
        (   // id=1044, type=WIN-TYPE-1, prop=IJ_valuesCb 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 1587 and loc.getEndColumn() >= 1587
        ) or 
        (   // id=1045, type=WIN-TYPE-1, prop=_wjdd 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 44 and loc.getEndLine() = 44 and
            loc.getStartColumn() <= 53 and loc.getEndColumn() >= 53
        ) or 
        (   // id=1046, type=WIN-TYPE-1, prop=wiz_progress 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 2606 and loc.getEndColumn() >= 2606
        ) or 
        (   // id=1047, type=WIN-TYPE-1, prop=stopScanForCss 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 58 and loc.getEndLine() = 58 and
            loc.getStartColumn() <= 2650 and loc.getEndColumn() >= 2650
        ) or 
        (   // id=1054, type=WIN-TYPE-1, prop=default_OneGoogleWidgetUi 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 50 and loc.getEndColumn() >= 50
        ) or 
        (   // id=1055, type=WIN-TYPE-1, prop=default_OneGoogleWidgetUi 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 44 and loc.getEndColumn() >= 44
        ) or 
        (   // id=1056, type=WIN-TYPE-1, prop=_F_toggles 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 128 and loc.getEndColumn() >= 128
        ) or 
        (   // id=1057, type=WIN-TYPE-1, prop=global 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 109 and loc.getEndLine() = 109 and
            loc.getStartColumn() <= 117 and loc.getEndColumn() >= 117
        ) or 
        (   // id=1058, type=WIN-TYPE-1, prop=_F_jsUrl 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 76 and loc.getEndLine() = 76 and
            loc.getStartColumn() <= 35 and loc.getEndColumn() >= 35
        ) or 
        (   // id=1061, type=WIN-TYPE-1, prop=BOQ_loadedInitialJS 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 371 and loc.getEndLine() = 371 and
            loc.getStartColumn() <= 295 and loc.getEndColumn() >= 295
        ) or 
        (   // id=1067, type=WIN-TYPE-1, prop=_F_installCss 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 149 and loc.getEndLine() = 149 and
            loc.getStartColumn() <= 504 and loc.getEndColumn() >= 504
        ) or 
        (   // id=1068, type=WIN-TYPE-1, prop=execScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 149 and loc.getEndLine() = 149 and
            loc.getStartColumn() <= 532 and loc.getEndColumn() >= 532
        ) or 
        (   // id=1069, type=WIN-TYPE-1, prop=_F_installCss 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 149 and loc.getEndLine() = 149 and
            loc.getStartColumn() <= 680 and loc.getEndColumn() >= 680
        ) or 
        (   // id=1075, type=WIN-TYPE-1, prop=_B_err 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 149 and loc.getEndLine() = 149 and
            loc.getStartColumn() <= 504 and loc.getEndColumn() >= 504
        ) or 
        (   // id=1077, type=WIN-TYPE-1, prop=_B_err 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 149 and loc.getEndLine() = 149 and
            loc.getStartColumn() <= 680 and loc.getEndColumn() >= 680
        ) or 
        (   // id=1078, type=WIN-TYPE-1, prop=mozRequestAnimationFrame 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 269 and loc.getEndLine() = 269 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=1079, type=WIN-TYPE-1, prop=webkitAnimationFrame 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 269 and loc.getEndLine() = 269 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=1080, type=WIN-TYPE-1, prop=msRequestAnimationFrame 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 269 and loc.getEndLine() = 269 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=1083, type=WIN-TYPE-1, prop=closure_listenable_506521 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 257 and loc.getEndLine() = 257 and
            loc.getStartColumn() <= 588 and loc.getEndColumn() >= 588
        ) or 
        (   // id=1084, type=WIN-TYPE-1, prop=closure_lm_462571 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 262 and loc.getEndLine() = 262 and
            loc.getStartColumn() <= 19 and loc.getEndColumn() >= 19
        ) or 
        (   // id=1085, type=WIN-TYPE-1, prop=closure_lm_462571 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 259 and loc.getEndLine() = 259 and
            loc.getStartColumn() <= 97 and loc.getEndColumn() >= 97
        ) or 
        (   // id=1087, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 183 and loc.getEndLine() = 183 and
            loc.getStartColumn() <= 94 and loc.getEndColumn() >= 94
        ) or 
        (   // id=1088, type=WIN-TYPE-1, prop=wiz_progress 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 106 and loc.getEndLine() = 106 and
            loc.getStartColumn() <= 131 and loc.getEndColumn() >= 131
        ) or 
        (   // id=1095, type=WIN-TYPE-1, prop=_F_getIjData 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 383 and loc.getEndLine() = 383 and
            loc.getStartColumn() <= 20 and loc.getEndColumn() >= 20
        ) or 
        (   // id=1130, type=WIN-TYPE-1, prop=__SAPISID 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 157 and loc.getEndLine() = 157 and
            loc.getStartColumn() <= 393 and loc.getEndColumn() >= 393
        ) or 
        (   // id=1131, type=WIN-TYPE-1, prop=__APISID 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 157 and loc.getEndLine() = 157 and
            loc.getStartColumn() <= 408 and loc.getEndColumn() >= 408
        ) or 
        (   // id=1132, type=WIN-TYPE-1, prop=__3PSAPISID 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 157 and loc.getEndLine() = 157 and
            loc.getStartColumn() <= 422 and loc.getEndColumn() >= 422
        ) or 
        (   // id=1133, type=WIN-TYPE-1, prop=__OVERRIDE_SID 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 157 and loc.getEndLine() = 157 and
            loc.getStartColumn() <= 439 and loc.getEndColumn() >= 439
        ) or 
        (   // id=1161, type=WIN-TYPE-1, prop=_mxNDff 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 28 and loc.getEndColumn() >= 28
        ) or 
        (   // id=1162, type=WIN-TYPE-1, prop=_mxNDff 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 80 and loc.getEndColumn() >= 80
        ) or 
        (   // id=1171, type=WIN-TYPE-1, prop=closure_uid_920143003 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 151 and loc.getEndLine() = 151 and
            loc.getStartColumn() <= 157 and loc.getEndColumn() >= 157
        ) or 
        (   // id=1191, type=WIN-TYPE-1, prop=ontouchstart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 262 and loc.getEndLine() = 262 and
            loc.getStartColumn() <= 54 and loc.getEndColumn() >= 54
        ) or 
        (   // id=1192, type=WIN-TYPE-1, prop=DocumentTouch 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 262 and loc.getEndLine() = 262 and
            loc.getStartColumn() <= 134 and loc.getEndColumn() >= 134
        ) or 
        (   // id=1249, type=WIN-TYPE-1, prop=ly11Pc 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 863 and loc.getEndLine() = 863 and
            loc.getStartColumn() <= 392 and loc.getEndColumn() >= 392
        ) or 
        (   // id=1300, type=WIN-TYPE-1, prop=_cshid 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 211 and loc.getEndColumn() >= 211
        ) or 
        (   // id=1349, type=WIN-TYPE-1, prop=__SAPISID 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 686 and loc.getEndLine() = 686 and
            loc.getStartColumn() <= 378 and loc.getEndColumn() >= 378
        ) or 
        (   // id=1350, type=WIN-TYPE-1, prop=__APISID 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 686 and loc.getEndLine() = 686 and
            loc.getStartColumn() <= 393 and loc.getEndColumn() >= 393
        ) or 
        (   // id=1351, type=WIN-TYPE-1, prop=__3PSAPISID 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 686 and loc.getEndLine() = 686 and
            loc.getStartColumn() <= 407 and loc.getEndColumn() >= 407
        ) or 
        (   // id=1352, type=WIN-TYPE-1, prop=__OVERRIDE_SID 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 686 and loc.getEndLine() = 686 and
            loc.getStartColumn() <= 424 and loc.getEndColumn() >= 424
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
        (   // id=119, type=DOC-TYPE-1, prop=__wizdispatcher 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 733 and loc.getEndLine() = 733 and
            loc.getStartColumn() <= 423 and loc.getEndColumn() >= 423
        ) or 
        (   // id=133, type=DOC-TYPE-1, prop=parentWindow 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 480 and loc.getEndLine() = 480 and
            loc.getStartColumn() <= 345 and loc.getEndColumn() >= 345
        ) or 
        (   // id=139, type=DOC-TYPE-1, prop=__wizdispatcher_resolve 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 961 and loc.getEndLine() = 961 and
            loc.getStartColumn() <= 524 and loc.getEndColumn() >= 524
        ) or 
        (   // id=154, type=DOC-TYPE-1, prop=parentWindow 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 494 and loc.getEndLine() = 494 and
            loc.getStartColumn() <= 345 and loc.getEndColumn() >= 345
        ) or 
        (   // id=466, type=DOC-TYPE-1, prop=parentWindow 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 480 and loc.getEndLine() = 480 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=714, type=DOC-TYPE-1, prop=getAttribute 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 150 and loc.getEndLine() = 150 and
            loc.getStartColumn() <= 157 and loc.getEndColumn() >= 157
        ) or 
        (   // id=720, type=DOC-TYPE-1, prop=getAttribute 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 180 and loc.getEndColumn() >= 180
        ) or 
        (   // id=851, type=DOC-TYPE-1, prop=closure_listenable_712754 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 16 and loc.getEndLine() = 16 and
            loc.getStartColumn() <= 540 and loc.getEndColumn() >= 540
        ) or 
        (   // id=852, type=DOC-TYPE-1, prop=closure_lm_102326 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 22 and loc.getEndLine() = 22 and
            loc.getStartColumn() <= 143 and loc.getEndColumn() >= 143
        ) or 
        (   // id=921, type=DOC-TYPE-1, prop=className 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 441 and loc.getEndColumn() >= 441
        ) or 
        (   // id=1081, type=DOC-TYPE-1, prop=parentWindow 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 175 and loc.getEndLine() = 175 and
            loc.getStartColumn() <= 169 and loc.getEndColumn() >= 169
        ) or 
        (   // id=1086, type=DOC-TYPE-1, prop=__wizdispatcher_resolve 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 285 and loc.getEndLine() = 285 and
            loc.getStartColumn() <= 845 and loc.getEndColumn() >= 845
        ) or 
        (   // id=1159, type=DOC-TYPE-1, prop=parentWindow 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 22 and loc.getEndLine() = 22 and
            loc.getStartColumn() <= 39 and loc.getEndColumn() >= 39
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
        (   // id=3, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 9 and loc.getEndColumn() >= 9
        ) or 
        (   // id=4, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 239 and loc.getEndColumn() >= 239
        ) or 
        (   // id=8, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 2552 and loc.getEndColumn() >= 2552
        ) or 
        (   // id=10, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 22 and loc.getEndLine() = 22 and
            loc.getStartColumn() <= 134 and loc.getEndColumn() >= 134
        ) or 
        (   // id=87, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 865 and loc.getEndColumn() >= 865
        ) or 
        (   // id=88, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 7 and loc.getEndLine() = 7 and
            loc.getStartColumn() <= 905 and loc.getEndColumn() >= 905
        ) or 
        (   // id=89, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 504 and loc.getEndColumn() >= 504
        ) or 
        (   // id=90, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 552 and loc.getEndColumn() >= 552
        ) or 
        (   // id=91, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 579 and loc.getEndColumn() >= 579
        ) or 
        (   // id=106, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 436 and loc.getEndLine() = 436 and
            loc.getStartColumn() <= 432 and loc.getEndColumn() >= 432
        ) or 
        (   // id=107, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 436 and loc.getEndLine() = 436 and
            loc.getStartColumn() <= 475 and loc.getEndColumn() >= 475
        ) or 
        (   // id=112, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 566 and loc.getEndLine() = 566 and
            loc.getStartColumn() <= 846 and loc.getEndColumn() >= 846
        ) or 
        (   // id=113, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 566 and loc.getEndLine() = 566 and
            loc.getStartColumn() <= 879 and loc.getEndColumn() >= 879
        ) or 
        (   // id=120, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 224 and loc.getEndLine() = 224 and
            loc.getStartColumn() <= 31 and loc.getEndColumn() >= 31
        ) or 
        (   // id=121, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 224 and loc.getEndLine() = 224 and
            loc.getStartColumn() <= 117 and loc.getEndColumn() >= 117
        ) or 
        (   // id=122, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 224 and loc.getEndLine() = 224 and
            loc.getStartColumn() <= 192 and loc.getEndColumn() >= 192
        ) or 
        (   // id=123, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 224 and loc.getEndLine() = 224 and
            loc.getStartColumn() <= 267 and loc.getEndColumn() >= 267
        ) or 
        (   // id=124, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 982 and loc.getEndLine() = 982 and
            loc.getStartColumn() <= 44 and loc.getEndColumn() >= 44
        ) or 
        (   // id=140, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 250 and loc.getEndLine() = 250 and
            loc.getStartColumn() <= 307 and loc.getEndColumn() >= 307
        ) or 
        (   // id=153, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 478 and loc.getEndLine() = 478 and
            loc.getStartColumn() <= 311 and loc.getEndColumn() >= 311
        ) or 
        (   // id=160, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 321 and loc.getEndColumn() >= 321
        ) or 
        (   // id=218, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 23 and loc.getEndLine() = 23 and
            loc.getStartColumn() <= 639 and loc.getEndColumn() >= 639
        ) or 
        (   // id=267, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1371 and loc.getEndLine() = 1371 and
            loc.getStartColumn() <= 191 and loc.getEndColumn() >= 191
        ) or 
        (   // id=277, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 998 and loc.getEndLine() = 998 and
            loc.getStartColumn() <= 230 and loc.getEndColumn() >= 230
        ) or 
        (   // id=383, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 164 and loc.getEndLine() = 164 and
            loc.getStartColumn() <= 406 and loc.getEndColumn() >= 406
        ) or 
        (   // id=384, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 219 and loc.getEndLine() = 219 and
            loc.getStartColumn() <= 141 and loc.getEndColumn() >= 141
        ) or 
        (   // id=412, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 446 and loc.getEndColumn() >= 446
        ) or 
        (   // id=419, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2139 and loc.getEndLine() = 2139 and
            loc.getStartColumn() <= 277 and loc.getEndColumn() >= 277
        ) or 
        (   // id=420, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2139 and loc.getEndLine() = 2139 and
            loc.getStartColumn() <= 291 and loc.getEndColumn() >= 291
        ) or 
        (   // id=421, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2139 and loc.getEndLine() = 2139 and
            loc.getStartColumn() <= 307 and loc.getEndColumn() >= 307
        ) or 
        (   // id=458, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2147 and loc.getEndLine() = 2147 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=461, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2147 and loc.getEndLine() = 2147 and
            loc.getStartColumn() <= 114 and loc.getEndColumn() >= 114
        ) or 
        (   // id=464, type=DOC-TYPE-2, prop=scrollingElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 480 and loc.getEndLine() = 480 and
            loc.getStartColumn() <= 231 and loc.getEndColumn() >= 231
        ) or 
        (   // id=465, type=DOC-TYPE-2, prop=scrollingElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 480 and loc.getEndLine() = 480 and
            loc.getStartColumn() <= 250 and loc.getEndColumn() >= 250
        ) or 
        (   // id=532, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 215 and loc.getEndLine() = 215 and
            loc.getStartColumn() <= 476 and loc.getEndColumn() >= 476
        ) or 
        (   // id=601, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1831 and loc.getEndLine() = 1831 and
            loc.getStartColumn() <= 329 and loc.getEndColumn() >= 329
        ) or 
        (   // id=602, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1741 and loc.getEndLine() = 1741 and
            loc.getStartColumn() <= 335 and loc.getEndColumn() >= 335
        ) or 
        (   // id=718, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1099 and loc.getEndLine() = 1099 and
            loc.getStartColumn() <= 482 and loc.getEndColumn() >= 482
        ) or 
        (   // id=719, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 33 and loc.getEndLine() = 33 and
            loc.getStartColumn() <= 392 and loc.getEndColumn() >= 392
        ) or 
        (   // id=726, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 35 and loc.getEndLine() = 35 and
            loc.getStartColumn() <= 274 and loc.getEndColumn() >= 274
        ) or 
        (   // id=731, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 74 and loc.getEndLine() = 74 and
            loc.getStartColumn() <= 103 and loc.getEndColumn() >= 103
        ) or 
        (   // id=735, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 60 and loc.getEndLine() = 60 and
            loc.getStartColumn() <= 829 and loc.getEndColumn() >= 829
        ) or 
        (   // id=744, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 479 and loc.getEndLine() = 479 and
            loc.getStartColumn() <= 57 and loc.getEndColumn() >= 57
        ) or 
        (   // id=745, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 479 and loc.getEndLine() = 479 and
            loc.getStartColumn() <= 66 and loc.getEndColumn() >= 66
        ) or 
        (   // id=748, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 63 and loc.getEndLine() = 63 and
            loc.getStartColumn() <= 46 and loc.getEndColumn() >= 46
        ) or 
        (   // id=840, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 119 and loc.getEndLine() = 119 and
            loc.getStartColumn() <= 479 and loc.getEndColumn() >= 479
        ) or 
        (   // id=846, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 38 and loc.getEndLine() = 38 and
            loc.getStartColumn() <= 93 and loc.getEndColumn() >= 93
        ) or 
        (   // id=850, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 172 and loc.getEndLine() = 172 and
            loc.getStartColumn() <= 113 and loc.getEndColumn() >= 113
        ) or 
        (   // id=915, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 245 and loc.getEndLine() = 245 and
            loc.getStartColumn() <= 80 and loc.getEndColumn() >= 80
        ) or 
        (   // id=975, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 263 and loc.getEndColumn() >= 263
        ) or 
        (   // id=978, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 37 and loc.getEndLine() = 37 and
            loc.getStartColumn() <= 527 and loc.getEndColumn() >= 527
        ) or 
        (   // id=1000, type=DOC-TYPE-2, prop=scripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 99 and loc.getEndLine() = 99 and
            loc.getStartColumn() <= 130 and loc.getEndColumn() >= 130
        ) or 
        (   // id=1003, type=DOC-TYPE-2, prop=scripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 117 and loc.getEndLine() = 117 and
            loc.getStartColumn() <= 59 and loc.getEndColumn() >= 59
        ) or 
        (   // id=1042, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 3 and loc.getEndLine() = 3 and
            loc.getStartColumn() <= 144 and loc.getEndColumn() >= 144
        ) or 
        (   // id=1074, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 356 and loc.getEndLine() = 356 and
            loc.getStartColumn() <= 767 and loc.getEndColumn() >= 767
        ) or 
        (   // id=1106, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 37 and loc.getEndLine() = 37 and
            loc.getStartColumn() <= 436 and loc.getEndColumn() >= 436
        ) or 
        (   // id=1158, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 175 and loc.getEndLine() = 175 and
            loc.getStartColumn() <= 71 and loc.getEndColumn() >= 71
        ) or 
        (   // id=1175, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 438 and loc.getEndLine() = 438 and
            loc.getStartColumn() <= 423 and loc.getEndColumn() >= 423
        ) or 
        (   // id=1176, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 438 and loc.getEndLine() = 438 and
            loc.getStartColumn() <= 395 and loc.getEndColumn() >= 395
        ) or 
        (   // id=1179, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 411 and loc.getEndLine() = 411 and
            loc.getStartColumn() <= 82 and loc.getEndColumn() >= 82
        ) or 
        (   // id=1185, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 240 and loc.getEndLine() = 240 and
            loc.getStartColumn() <= 347 and loc.getEndColumn() >= 347
        ) or 
        (   // id=1190, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 258 and loc.getEndLine() = 258 and
            loc.getStartColumn() <= 122 and loc.getEndColumn() >= 122
        ) or 
        (   // id=1197, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 273 and loc.getEndLine() = 273 and
            loc.getStartColumn() <= 359 and loc.getEndColumn() >= 359
        ) or 
        (   // id=1198, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 273 and loc.getEndLine() = 273 and
            loc.getStartColumn() <= 409 and loc.getEndColumn() >= 409
        ) or 
        (   // id=1199, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 273 and loc.getEndLine() = 273 and
            loc.getStartColumn() <= 458 and loc.getEndColumn() >= 458
        ) or 
        (   // id=1217, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 444 and loc.getEndColumn() >= 444
        ) or 
        (   // id=1243, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 863 and loc.getEndLine() = 863 and
            loc.getStartColumn() <= 531 and loc.getEndColumn() >= 531
        ) or 
        (   // id=1246, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 863 and loc.getEndLine() = 863 and
            loc.getStartColumn() <= 631 and loc.getEndColumn() >= 631
        ) or 
        (   // id=1252, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 872 and loc.getEndLine() = 872 and
            loc.getStartColumn() <= 261 and loc.getEndColumn() >= 261
        ) or 
        (   // id=1253, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 872 and loc.getEndLine() = 872 and
            loc.getStartColumn() <= 299 and loc.getEndColumn() >= 299
        ) or 
        (   // id=1254, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 671 and loc.getEndLine() = 671 and
            loc.getStartColumn() <= 171 and loc.getEndColumn() >= 171
        ) or 
        (   // id=1255, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 813 and loc.getEndLine() = 813 and
            loc.getStartColumn() <= 181 and loc.getEndColumn() >= 181
        ) or 
        (   // id=1261, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 815 and loc.getEndLine() = 815 and
            loc.getStartColumn() <= 439 and loc.getEndColumn() >= 439
        ) or 
        (   // id=1262, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 816 and loc.getEndLine() = 816 and
            loc.getStartColumn() <= 23 and loc.getEndColumn() >= 23
        ) or 
        (   // id=1275, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 595 and loc.getEndLine() = 595 and
            loc.getStartColumn() <= 336 and loc.getEndColumn() >= 336
        ) or 
        (   // id=1341, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 774 and loc.getEndLine() = 774 and
            loc.getStartColumn() <= 376 and loc.getEndColumn() >= 376
        ) or 
        (   // id=1397, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 4 and loc.getEndLine() = 4 and
            loc.getStartColumn() <= 332 and loc.getEndColumn() >= 332
        ) or 
        (   // id=1418, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1641 and loc.getEndLine() = 1641 and
            loc.getStartColumn() <= 427 and loc.getEndColumn() >= 427
        ) or 
        (   // id=1423, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 140 and loc.getEndLine() = 140 and
            loc.getStartColumn() <= 395 and loc.getEndColumn() >= 395
        ) or 
        (   // id=1427, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 463 and loc.getEndLine() = 463 and
            loc.getStartColumn() <= 356 and loc.getEndColumn() >= 356
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
        (   // id=35, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 66 and loc.getEndLine() = 66 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=36, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 66 and loc.getEndLine() = 66 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=38, type=DOM-API, prop=form, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 67 and loc.getEndLine() = 67 and
            loc.getStartColumn() <= 33 and loc.getEndColumn() >= 33
        ) or 
        (   // id=42, type=DOM-API, prop=.gb_k .gb_d, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 75 and loc.getEndLine() = 75 and
            loc.getStartColumn() <= 17 and loc.getEndColumn() >= 17
        ) or 
        (   // id=45, type=DOM-API, prop=gb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 75 and loc.getEndLine() = 75 and
            loc.getStartColumn() <= 58 and loc.getEndColumn() >= 58
        ) or 
        (   // id=46, type=DOM-API, prop=#gb.gb_Zc, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 75 and loc.getEndLine() = 75 and
            loc.getStartColumn() <= 58 and loc.getEndColumn() >= 58
        ) or 
        (   // id=49, type=DOM-API, prop=.gb_b .gb_d, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 84 and loc.getEndLine() = 84 and
            loc.getStartColumn() <= 17 and loc.getEndColumn() >= 17
        ) or 
        (   // id=52, type=DOM-API, prop=gb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 84 and loc.getEndLine() = 84 and
            loc.getStartColumn() <= 58 and loc.getEndColumn() >= 58
        ) or 
        (   // id=53, type=DOM-API, prop=#gb.gb_Zc, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 84 and loc.getEndLine() = 84 and
            loc.getStartColumn() <= 58 and loc.getEndColumn() >= 58
        ) or 
        (   // id=59, type=DOM-API, prop=script[nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 106 and loc.getEndLine() = 106 and
            loc.getStartColumn() <= 139 and loc.getEndColumn() >= 139
        ) or 
        (   // id=62, type=DOM-API, prop=HEAD, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 106 and loc.getEndLine() = 106 and
            loc.getStartColumn() <= 425 and loc.getEndColumn() >= 425
        ) or 
        (   // id=68, type=DOM-API, prop=style[nonce],link[rel="stylesheet"][nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 66 and loc.getEndColumn() >= 66
        ) or 
        (   // id=77, type=DOM-API, prop=img, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 113 and loc.getEndLine() = 113 and
            loc.getStartColumn() <= 313 and loc.getEndColumn() >= 313
        ) or 
        (   // id=85, type=DOM-API, prop=Ib7Efc, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 12 and loc.getEndLine() = 12 and
            loc.getStartColumn() <= 753 and loc.getEndColumn() >= 753
        ) or 
        (   // id=97, type=DOM-API, prop=img, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 113 and loc.getEndLine() = 113 and
            loc.getStartColumn() <= 27991 and loc.getEndColumn() >= 27991
        ) or 
        (   // id=131, type=DOM-API, prop=[jsname='coFSxe'], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 276 and loc.getEndLine() = 276 and
            loc.getStartColumn() <= 242 and loc.getEndColumn() >= 242
        ) or 
        (   // id=132, type=DOM-API, prop=[jsname='coFSxe'], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 276 and loc.getEndLine() = 276 and
            loc.getStartColumn() <= 242 and loc.getEndColumn() >= 242
        ) or 
        (   // id=161, type=DOM-API, prop=Non-Undefined, api=forms
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=162, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=163, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=164, type=DOM-API, prop=input, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=165, type=DOM-API, prop=button, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=181, type=DOM-API, prop=[jscontroller],[jsmodel],[jsowner],[jsaction*="trigger."], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 836 and loc.getEndLine() = 836 and
            loc.getStartColumn() <= 355 and loc.getEndColumn() >= 355
        ) or 
        (   // id=182, type=DOM-API, prop=[jscontroller],[jsmodel],[jsowner],[jsaction*="trigger."], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 836 and loc.getEndLine() = 836 and
            loc.getStartColumn() <= 355 and loc.getEndColumn() >= 355
        ) or 
        (   // id=184, type=DOM-API, prop=[jsname=coFSxe] [jscontroller],[jsname=coFSxe] [jsmodel],[jsname=coFSxe] [jsowner],[jsname=coFSxe] [jsaction*="trigger."], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 837 and loc.getEndLine() = 837 and
            loc.getStartColumn() <= 167 and loc.getEndColumn() >= 167
        ) or 
        (   // id=185, type=DOM-API, prop=[jsname=coFSxe] [jscontroller],[jsname=coFSxe] [jsmodel],[jsname=coFSxe] [jsowner],[jsname=coFSxe] [jsaction*="trigger."], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 837 and loc.getEndLine() = 837 and
            loc.getStartColumn() <= 167 and loc.getEndColumn() >= 167
        ) or 
        (   // id=223, type=DOM-API, prop=[jsname="gLFyf"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=224, type=DOM-API, prop=[jsname="gLFyf"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=225, type=DOM-API, prop=[jsshadow], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 845 and loc.getEndLine() = 845 and
            loc.getStartColumn() <= 229 and loc.getEndColumn() >= 229
        ) or 
        (   // id=231, type=DOM-API, prop=[jsname="aJyGR"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=232, type=DOM-API, prop=[jsname="aJyGR"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=241, type=DOM-API, prop=[jsname="ofh9id"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=242, type=DOM-API, prop=[jsname="ofh9id"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=246, type=DOM-API, prop=[jsname="UUbT9"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=247, type=DOM-API, prop=[jsname="UUbT9"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=255, type=DOM-API, prop=[jsname="RP0xob"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=256, type=DOM-API, prop=[jsname="RP0xob"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=263, type=DOM-API, prop=[jsname="pkjasb"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=264, type=DOM-API, prop=[jsname="pkjasb"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=265, type=DOM-API, prop=[jsname="s1VaRe"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=266, type=DOM-API, prop=[jsname="s1VaRe"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=269, type=DOM-API, prop=[jsname="R5mgy"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=270, type=DOM-API, prop=[jsname="R5mgy"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=280, type=DOM-API, prop=[jsname="F7uqIe"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=281, type=DOM-API, prop=[jsname="F7uqIe"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=289, type=DOM-API, prop=[jsname="RoMYmb"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=290, type=DOM-API, prop=[jsname="RoMYmb"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=321, type=DOM-API, prop=[name=q], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 144 and loc.getEndColumn() >= 144
        ) or 
        (   // id=322, type=DOM-API, prop=[name=q], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 144 and loc.getEndColumn() >= 144
        ) or 
        (   // id=325, type=DOM-API, prop=[jsname="vdLsw"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=326, type=DOM-API, prop=[jsname="vdLsw"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=331, type=DOM-API, prop=[jsname="erkvQe"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=332, type=DOM-API, prop=[jsname="erkvQe"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=335, type=DOM-API, prop=[jsname="tovEib"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=336, type=DOM-API, prop=[jsname="tovEib"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=339, type=DOM-API, prop=[jsname="aajZCb"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=340, type=DOM-API, prop=[jsname="aajZCb"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=343, type=DOM-API, prop=[jsname="RjPuVb"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=344, type=DOM-API, prop=[jsname="RjPuVb"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=347, type=DOM-API, prop=[jsname="VlcLAe"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=348, type=DOM-API, prop=[jsname="VlcLAe"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=351, type=DOM-API, prop=[jsname="JUypV"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=352, type=DOM-API, prop=[jsname="JUypV"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=355, type=DOM-API, prop=[jsname="lh87ke"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=356, type=DOM-API, prop=[jsname="lh87ke"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=360, type=DOM-API, prop=tophf, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1891 and loc.getEndLine() = 1891 and
            loc.getStartColumn() <= 473 and loc.getEndColumn() >= 473
        ) or 
        (   // id=361, type=DOM-API, prop=#tophf, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1891 and loc.getEndLine() = 1891 and
            loc.getStartColumn() <= 473 and loc.getEndColumn() >= 473
        ) or 
        (   // id=363, type=DOM-API, prop=.gNO89b, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 144 and loc.getEndColumn() >= 144
        ) or 
        (   // id=364, type=DOM-API, prop=.gNO89b, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 144 and loc.getEndColumn() >= 144
        ) or 
        (   // id=365, type=DOM-API, prop=.Tg7LZd, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 144 and loc.getEndColumn() >= 144
        ) or 
        (   // id=366, type=DOM-API, prop=.Tg7LZd, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 144 and loc.getEndColumn() >= 144
        ) or 
        (   // id=367, type=DOM-API, prop=.RNmpXc, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 286 and loc.getEndColumn() >= 286
        ) or 
        (   // id=369, type=DOM-API, prop=gbqfbb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 286 and loc.getEndColumn() >= 286
        ) or 
        (   // id=370, type=DOM-API, prop=#gbqfbb, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 286 and loc.getEndColumn() >= 286
        ) or 
        (   // id=372, type=DOM-API, prop=[jsname="uFMOof"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=373, type=DOM-API, prop=[jsname="uFMOof"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=375, type=DOM-API, prop=tophf, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1875 and loc.getEndLine() = 1875 and
            loc.getStartColumn() <= 90 and loc.getEndColumn() >= 90
        ) or 
        (   // id=376, type=DOM-API, prop=INPUT, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 712 and loc.getEndColumn() >= 712
        ) or 
        (   // id=381, type=DOM-API, prop=script[nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 145 and loc.getEndLine() = 145 and
            loc.getStartColumn() <= 84 and loc.getEndColumn() >= 84
        ) or 
        (   // id=394, type=DOM-API, prop=biw, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1097 and loc.getEndLine() = 1097 and
            loc.getStartColumn() <= 272 and loc.getEndColumn() >= 272
        ) or 
        (   // id=396, type=DOM-API, prop=bih, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1097 and loc.getEndLine() = 1097 and
            loc.getStartColumn() <= 272 and loc.getEndColumn() >= 272
        ) or 
        (   // id=399, type=DOM-API, prop=spch, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 115 and loc.getEndLine() = 115 and
            loc.getStartColumn() <= 543 and loc.getEndColumn() >= 543
        ) or 
        (   // id=401, type=DOM-API, prop=_Eg4jZoyKFqyI7NYPqqyUYA_4, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 115 and loc.getEndLine() = 115 and
            loc.getStartColumn() <= 543 and loc.getEndColumn() >= 543
        ) or 
        (   // id=413, type=DOM-API, prop=.wtF6od, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 452 and loc.getEndColumn() >= 452
        ) or 
        (   // id=414, type=DOM-API, prop=.wtF6od, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 452 and loc.getEndColumn() >= 452
        ) or 
        (   // id=416, type=DOM-API, prop=Odp5De, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=418, type=DOM-API, prop=rso, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=423, type=DOM-API, prop=gsr, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=424, type=DOM-API, prop=atvcap, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2137 and loc.getEndLine() = 2137 and
            loc.getStartColumn() <= 349 and loc.getEndColumn() >= 349
        ) or 
        (   // id=425, type=DOM-API, prop=#atvcap, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2137 and loc.getEndLine() = 2137 and
            loc.getStartColumn() <= 349 and loc.getEndColumn() >= 349
        ) or 
        (   // id=427, type=DOM-API, prop=JCMEhe, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2134 and loc.getEndLine() = 2134 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=428, type=DOM-API, prop=#JCMEhe, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2134 and loc.getEndLine() = 2134 and
            loc.getStartColumn() <= 25 and loc.getEndColumn() >= 25
        ) or 
        (   // id=430, type=DOM-API, prop=tvcap, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2134 and loc.getEndLine() = 2134 and
            loc.getStartColumn() <= 58 and loc.getEndColumn() >= 58
        ) or 
        (   // id=431, type=DOM-API, prop=#tvcap, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2134 and loc.getEndLine() = 2134 and
            loc.getStartColumn() <= 58 and loc.getEndColumn() >= 58
        ) or 
        (   // id=436, type=DOM-API, prop=.vcsx, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=437, type=DOM-API, prop=.vcsx, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=444, type=DOM-API, prop=tads, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 20 and loc.getEndColumn() >= 20
        ) or 
        (   // id=445, type=DOM-API, prop=#tads, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 20 and loc.getEndColumn() >= 20
        ) or 
        (   // id=447, type=DOM-API, prop=tadsb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 175 and loc.getEndColumn() >= 175
        ) or 
        (   // id=448, type=DOM-API, prop=#tadsb, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 175 and loc.getEndColumn() >= 175
        ) or 
        (   // id=450, type=DOM-API, prop=HbKV2c, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=451, type=DOM-API, prop=#HbKV2c, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=453, type=DOM-API, prop=bGmlqc, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 297 and loc.getEndColumn() >= 297
        ) or 
        (   // id=454, type=DOM-API, prop=#bGmlqc, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2138 and loc.getEndLine() = 2138 and
            loc.getStartColumn() <= 297 and loc.getEndColumn() >= 297
        ) or 
        (   // id=457, type=DOM-API, prop=img, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2146 and loc.getEndLine() = 2146 and
            loc.getStartColumn() <= 503 and loc.getEndColumn() >= 503
        ) or 
        (   // id=462, type=DOM-API, prop=.IormK img, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2147 and loc.getEndLine() = 2147 and
            loc.getStartColumn() <= 120 and loc.getEndColumn() >= 120
        ) or 
        (   // id=463, type=DOM-API, prop=.IormK img, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2147 and loc.getEndLine() = 2147 and
            loc.getStartColumn() <= 120 and loc.getEndColumn() >= 120
        ) or 
        (   // id=470, type=DOM-API, prop=oUAcPd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 205 and loc.getEndColumn() >= 205
        ) or 
        (   // id=501, type=DOM-API, prop=HEAD, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 494 and loc.getEndLine() = 494 and
            loc.getStartColumn() <= 59 and loc.getEndColumn() >= 59
        ) or 
        (   // id=506, type=DOM-API, prop=style[nonce],link[rel="stylesheet"][nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 467 and loc.getEndLine() = 467 and
            loc.getStartColumn() <= 174 and loc.getEndColumn() >= 174
        ) or 
        (   // id=534, type=DOM-API, prop=.yi, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1323 and loc.getEndLine() = 1323 and
            loc.getStartColumn() <= 498 and loc.getEndColumn() >= 498
        ) or 
        (   // id=535, type=DOM-API, prop=.yi, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1323 and loc.getEndLine() = 1323 and
            loc.getStartColumn() <= 498 and loc.getEndColumn() >= 498
        ) or 
        (   // id=537, type=DOM-API, prop=gbqfbb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=585, type=DOM-API, prop=spch, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=587, type=DOM-API, prop=spch-dlg, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=591, type=DOM-API, prop=spchc, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=593, type=DOM-API, prop=spchf, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=595, type=DOM-API, prop=spchi, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=597, type=DOM-API, prop=spchb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=599, type=DOM-API, prop=spchl, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 474 and loc.getEndLine() = 474 and
            loc.getStartColumn() <= 611 and loc.getEndColumn() >= 611
        ) or 
        (   // id=603, type=DOM-API, prop=[jsaction*="hATt5e"],[jscontroller][__IS_OWNER], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 764 and loc.getEndLine() = 764 and
            loc.getStartColumn() <= 318 and loc.getEndColumn() >= 318
        ) or 
        (   // id=604, type=DOM-API, prop=[jsaction*="hATt5e"],[jscontroller][__IS_OWNER], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 764 and loc.getEndLine() = 764 and
            loc.getStartColumn() <= 318 and loc.getEndColumn() >= 318
        ) or 
        (   // id=605, type=DOM-API, prop=.pHiOh, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=606, type=DOM-API, prop=.pHiOh, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=691, type=DOM-API, prop=.ayzqOc, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=692, type=DOM-API, prop=.ayzqOc, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=727, type=DOM-API, prop=[data-aqid], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 35 and loc.getEndLine() = 35 and
            loc.getStartColumn() <= 280 and loc.getEndColumn() >= 280
        ) or 
        (   // id=749, type=DOM-API, prop=[decode-data-ved], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 64 and loc.getEndLine() = 64 and
            loc.getStartColumn() <= 160 and loc.getEndColumn() >= 160
        ) or 
        (   // id=750, type=DOM-API, prop=[decode-data-ved], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 64 and loc.getEndLine() = 64 and
            loc.getStartColumn() <= 160 and loc.getEndColumn() >= 160
        ) or 
        (   // id=753, type=DOM-API, prop=[data-hveid], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 64 and loc.getEndLine() = 64 and
            loc.getStartColumn() <= 255 and loc.getEndColumn() >= 255
        ) or 
        (   // id=754, type=DOM-API, prop=[data-hveid], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 64 and loc.getEndLine() = 64 and
            loc.getStartColumn() <= 255 and loc.getEndColumn() >= 255
        ) or 
        (   // id=759, type=DOM-API, prop=G-SCROLLING-CAROUSEL, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 476 and loc.getEndLine() = 476 and
            loc.getStartColumn() <= 127 and loc.getEndColumn() >= 127
        ) or 
        (   // id=760, type=DOM-API, prop=G-SCROLLING-CAROUSEL, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 476 and loc.getEndLine() = 476 and
            loc.getStartColumn() <= 127 and loc.getEndColumn() >= 127
        ) or 
        (   // id=762, type=DOM-API, prop=[data-scca], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 213 and loc.getEndColumn() >= 213
        ) or 
        (   // id=763, type=DOM-API, prop=[data-scca], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 213 and loc.getEndColumn() >= 213
        ) or 
        (   // id=767, type=DOM-API, prop=G-TABS, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 476 and loc.getEndLine() = 476 and
            loc.getStartColumn() <= 127 and loc.getEndColumn() >= 127
        ) or 
        (   // id=768, type=DOM-API, prop=G-TABS, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 476 and loc.getEndLine() = 476 and
            loc.getStartColumn() <= 127 and loc.getEndColumn() >= 127
        ) or 
        (   // id=772, type=DOM-API, prop=.smsrc, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=773, type=DOM-API, prop=.smsrc, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=777, type=DOM-API, prop=.hscc, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=778, type=DOM-API, prop=.hscc, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 475 and loc.getEndLine() = 475 and
            loc.getStartColumn() <= 83 and loc.getEndColumn() >= 83
        ) or 
        (   // id=784, type=DOM-API, prop=[jsname="GkjeIf"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=785, type=DOM-API, prop=[jsname="GkjeIf"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=788, type=DOM-API, prop=[jsname="hUEw1d"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=789, type=DOM-API, prop=[jsname="hUEw1d"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=791, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1141 and loc.getEndLine() = 1141 and
            loc.getStartColumn() <= 36 and loc.getEndColumn() >= 36
        ) or 
        (   // id=792, type=DOM-API, prop=[data-subtree], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1150 and loc.getEndLine() = 1150 and
            loc.getStartColumn() <= 55 and loc.getEndColumn() >= 55
        ) or 
        (   // id=793, type=DOM-API, prop=[data-subtree], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1150 and loc.getEndLine() = 1150 and
            loc.getStartColumn() <= 55 and loc.getEndColumn() >= 55
        ) or 
        (   // id=797, type=DOM-API, prop=img, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2119 and loc.getEndLine() = 2119 and
            loc.getStartColumn() <= 62 and loc.getEndColumn() >= 62
        ) or 
        (   // id=798, type=DOM-API, prop=[data-async-ph], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1156 and loc.getEndLine() = 1156 and
            loc.getStartColumn() <= 66 and loc.getEndColumn() >= 66
        ) or 
        (   // id=799, type=DOM-API, prop=[data-async-ph], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/d122171027.js") and
            loc.getStartLine() = 1156 and loc.getEndLine() = 1156 and
            loc.getStartColumn() <= 66 and loc.getEndColumn() >= 66
        ) or 
        (   // id=809, type=DOM-API, prop=[data-subtree], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2120 and loc.getEndLine() = 2120 and
            loc.getStartColumn() <= 300 and loc.getEndColumn() >= 300
        ) or 
        (   // id=810, type=DOM-API, prop=[data-subtree], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 2120 and loc.getEndLine() = 2120 and
            loc.getStartColumn() <= 300 and loc.getEndColumn() >= 300
        ) or 
        (   // id=813, type=DOM-API, prop=[jsname="Nll0ne"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=814, type=DOM-API, prop=[jsname="Nll0ne"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=816, type=DOM-API, prop=[jsaction*="dpLbMb"],[jscontroller][__IS_OWNER], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 764 and loc.getEndLine() = 764 and
            loc.getStartColumn() <= 318 and loc.getEndColumn() >= 318
        ) or 
        (   // id=817, type=DOM-API, prop=[jsaction*="dpLbMb"],[jscontroller][__IS_OWNER], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 764 and loc.getEndLine() = 764 and
            loc.getStartColumn() <= 318 and loc.getEndColumn() >= 318
        ) or 
        (   // id=820, type=DOM-API, prop=gb_Ra, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=823, type=DOM-API, prop=gb_vd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=824, type=DOM-API, prop=gb_fd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=825, type=DOM-API, prop=gb_k, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=828, type=DOM-API, prop=gb_jd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=829, type=DOM-API, prop=gb_sd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=830, type=DOM-API, prop=gb_zd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=831, type=DOM-API, prop=gb_Cd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=832, type=DOM-API, prop=gb_8c, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=833, type=DOM-API, prop=gb_Vd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=834, type=DOM-API, prop=gb_hd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=835, type=DOM-API, prop=gb_Bd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=836, type=DOM-API, prop=.gb_ld, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=837, type=DOM-API, prop=.gb_ld, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=838, type=DOM-API, prop=gb_ie, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=839, type=DOM-API, prop=gb_je, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=849, type=DOM-API, prop=gb_Fa, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=860, type=DOM-API, prop=.gb_nd:not(.gb_d), api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 257 and loc.getEndLine() = 257 and
            loc.getStartColumn() <= 679 and loc.getEndColumn() >= 679
        ) or 
        (   // id=863, type=DOM-API, prop=.gb_Ia, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 257 and loc.getEndLine() = 257 and
            loc.getStartColumn() <= 981 and loc.getEndColumn() >= 981
        ) or 
        (   // id=866, type=DOM-API, prop=gb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 257 and loc.getEndLine() = 257 and
            loc.getStartColumn() <= 1020 and loc.getEndColumn() >= 1020
        ) or 
        (   // id=867, type=DOM-API, prop=#gb.gb_Zc, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 257 and loc.getEndLine() = 257 and
            loc.getStartColumn() <= 1020 and loc.getEndColumn() >= 1020
        ) or 
        (   // id=870, type=DOM-API, prop=.gb_j .gb_d, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 257 and loc.getEndLine() = 257 and
            loc.getStartColumn() <= 1092 and loc.getEndColumn() >= 1092
        ) or 
        (   // id=872, type=DOM-API, prop=gb_Vc, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=874, type=DOM-API, prop=gb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 484 and loc.getEndLine() = 484 and
            loc.getStartColumn() <= 207 and loc.getEndColumn() >= 207
        ) or 
        (   // id=875, type=DOM-API, prop=#gb [data-ogsr-up], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 484 and loc.getEndLine() = 484 and
            loc.getStartColumn() <= 207 and loc.getEndColumn() >= 207
        ) or 
        (   // id=892, type=DOM-API, prop=.gb_d, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=893, type=DOM-API, prop=.gb_d, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=894, type=DOM-API, prop=.gb_Ia, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=895, type=DOM-API, prop=.gb_Ia, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=902, type=DOM-API, prop=gb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 485 and loc.getEndLine() = 485 and
            loc.getStartColumn() <= 208 and loc.getEndColumn() >= 208
        ) or 
        (   // id=903, type=DOM-API, prop=#gb [data-ogsr-alt], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 485 and loc.getEndLine() = 485 and
            loc.getStartColumn() <= 208 and loc.getEndColumn() >= 208
        ) or 
        (   // id=907, type=DOM-API, prop=[data-eqid], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 444 and loc.getEndLine() = 444 and
            loc.getStartColumn() <= 349 and loc.getEndColumn() >= 349
        ) or 
        (   // id=911, type=DOM-API, prop=gb_d, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 485 and loc.getEndLine() = 485 and
            loc.getStartColumn() <= 407 and loc.getEndColumn() >= 407
        ) or 
        (   // id=912, type=DOM-API, prop=gb_n, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=918, type=DOM-API, prop=gb_Jd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=919, type=DOM-API, prop=.gb_J, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=920, type=DOM-API, prop=.gb_J, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 78 and loc.getEndLine() = 78 and
            loc.getStartColumn() <= 237 and loc.getEndColumn() >= 237
        ) or 
        (   // id=925, type=DOM-API, prop=gb_U, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 101 and loc.getEndLine() = 101 and
            loc.getStartColumn() <= 738 and loc.getEndColumn() >= 738
        ) or 
        (   // id=935, type=DOM-API, prop=script[nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 509 and loc.getEndLine() = 509 and
            loc.getStartColumn() <= 340 and loc.getEndColumn() >= 340
        ) or 
        (   // id=938, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/og/_/js/kog.qtm.en_US.oT1FwJRCVC4.2019.O/rtj/mqabr,q_d,qcwid,qapid,qald,q_dg/exmqaaw,qadd,qaid,qein,qhaw,qhba,qhbr,qhch,qhga,qhid,qhin/d1/ed1/rsAA2YrTvBynad-nWEy1xIb9j1w6LpLOF6IQ.html") and
            loc.getStartLine() = 510 and loc.getEndLine() = 510 and
            loc.getStartColumn() <= 320 and loc.getEndColumn() >= 320
        ) or 
        (   // id=984, type=DOM-API, prop=base-js, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 43 and loc.getEndLine() = 43 and
            loc.getStartColumn() <= 405 and loc.getEndColumn() >= 405
        ) or 
        (   // id=999, type=DOM-API, prop=Non-Undefined, api=scripts
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 99 and loc.getEndLine() = 99 and
            loc.getStartColumn() <= 131 and loc.getEndColumn() >= 131
        ) or 
        (   // id=1002, type=DOM-API, prop=Non-Undefined, api=scripts
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/apis.google.com/_/scs/abc-static/_/js/kgapi.gapi.en.dCBC8e6ENbg.O/mgapi_iframes,googleapis_client/rtj/sv1/d1/ed1/amAAAC/rsAHpOoo8oB7UmguRctpg6togRivSNxNKjzQ/cbgapi.loaded_0") and
            loc.getStartLine() = 117 and loc.getEndLine() = 117 and
            loc.getStartColumn() <= 60 and loc.getEndColumn() >= 60
        ) or 
        (   // id=1038, type=DOM-API, prop=img, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 57 and loc.getEndLine() = 57 and
            loc.getStartColumn() <= 64 and loc.getEndColumn() >= 64
        ) or 
        (   // id=1040, type=DOM-API, prop=img, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 57 and loc.getEndLine() = 57 and
            loc.getStartColumn() <= 174 and loc.getEndColumn() >= 174
        ) or 
        (   // id=1048, type=DOM-API, prop=Undefined, api=forms
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1049, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1052, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1064, type=DOM-API, prop=base-js, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 368 and loc.getEndLine() = 368 and
            loc.getStartColumn() <= 92 and loc.getEndColumn() >= 92
        ) or 
        (   // id=1066, type=DOM-API, prop=base-js, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 368 and loc.getEndLine() = 368 and
            loc.getStartColumn() <= 129 and loc.getEndColumn() >= 129
        ) or 
        (   // id=1073, type=DOM-API, prop=base-js, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 76 and loc.getEndLine() = 76 and
            loc.getStartColumn() <= 125 and loc.getEndColumn() >= 125
        ) or 
        (   // id=1097, type=DOM-API, prop=[jscontroller],[jsmodel],[jsowner],[jsaction*="trigger."], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 290 and loc.getEndLine() = 290 and
            loc.getStartColumn() <= 97 and loc.getEndColumn() >= 97
        ) or 
        (   // id=1098, type=DOM-API, prop=[jscontroller],[jsmodel],[jsowner],[jsaction*="trigger."], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 290 and loc.getEndLine() = 290 and
            loc.getStartColumn() <= 97 and loc.getEndColumn() >= 97
        ) or 
        (   // id=1103, type=DOM-API, prop=script[nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 50 and loc.getEndLine() = 50 and
            loc.getStartColumn() <= 85 and loc.getEndColumn() >= 85
        ) or 
        (   // id=1114, type=DOM-API, prop=[data-ogmv] > [role="dialog"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 171 and loc.getEndColumn() >= 171
        ) or 
        (   // id=1117, type=DOM-API, prop=[data-ogmv] > [role="dialog"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 50 and loc.getEndLine() = 50 and
            loc.getStartColumn() <= 203 and loc.getEndColumn() >= 203
        ) or 
        (   // id=1123, type=DOM-API, prop=[data-ogmv], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/ogs.google.com/widget/callout.html") and
            loc.getStartLine() = 54 and loc.getEndLine() = 54 and
            loc.getStartColumn() <= 499 and loc.getEndColumn() >= 499
        ) or 
        (   // id=1146, type=DOM-API, prop=style[nonce],link[rel="stylesheet"][nonce], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 166 and loc.getEndLine() = 166 and
            loc.getStartColumn() <= 1831 and loc.getEndColumn() >= 1831
        ) or 
        (   // id=1149, type=DOM-API, prop=HEAD, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 181 and loc.getEndLine() = 181 and
            loc.getStartColumn() <= 457 and loc.getEndColumn() >= 457
        ) or 
        (   // id=1184, type=DOM-API, prop=yDmH0d, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 242 and loc.getEndLine() = 242 and
            loc.getStartColumn() <= 224 and loc.getEndColumn() >= 224
        ) or 
        (   // id=1201, type=DOM-API, prop=gb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 242 and loc.getEndLine() = 242 and
            loc.getStartColumn() <= 224 and loc.getEndColumn() >= 224
        ) or 
        (   // id=1202, type=DOM-API, prop=.SSPGKf:not(.JwkDRc), api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 315 and loc.getEndLine() = 315 and
            loc.getStartColumn() <= 195 and loc.getEndColumn() >= 195
        ) or 
        (   // id=1203, type=DOM-API, prop=.SSPGKf:not(.JwkDRc), api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 315 and loc.getEndLine() = 315 and
            loc.getStartColumn() <= 195 and loc.getEndColumn() >= 195
        ) or 
        (   // id=1206, type=DOM-API, prop=base, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 584 and loc.getEndLine() = 584 and
            loc.getStartColumn() <= 354 and loc.getEndColumn() >= 354
        ) or 
        (   // id=1210, type=DOM-API, prop=[c-wiz][view], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 551 and loc.getEndLine() = 551 and
            loc.getStartColumn() <= 38 and loc.getEndColumn() >= 38
        ) or 
        (   // id=1212, type=DOM-API, prop=.SSPGKf, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 315 and loc.getEndLine() = 315 and
            loc.getStartColumn() <= 195 and loc.getEndColumn() >= 195
        ) or 
        (   // id=1213, type=DOM-API, prop=.SSPGKf, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 315 and loc.getEndLine() = 315 and
            loc.getStartColumn() <= 195 and loc.getEndColumn() >= 195
        ) or 
        (   // id=1215, type=DOM-API, prop=view-header title, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 315 and loc.getEndLine() = 315 and
            loc.getStartColumn() <= 195 and loc.getEndColumn() >= 195
        ) or 
        (   // id=1216, type=DOM-API, prop=view-header title, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 315 and loc.getEndLine() = 315 and
            loc.getStartColumn() <= 195 and loc.getEndColumn() >= 195
        ) or 
        (   // id=1218, type=DOM-API, prop=[jsaction*="HO6t5b"],[jscontroller][__IS_OWNER], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1219, type=DOM-API, prop=[jsaction*="HO6t5b"],[jscontroller][__IS_OWNER], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1220, type=DOM-API, prop=[jsaction*="IBB03b"],[jscontroller][__IS_OWNER], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1221, type=DOM-API, prop=[jsaction*="IBB03b"],[jscontroller][__IS_OWNER], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1223, type=DOM-API, prop=[jsaction*="qako4e"],[jscontroller][__IS_OWNER], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1224, type=DOM-API, prop=[jsaction*="qako4e"],[jscontroller][__IS_OWNER], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1236, type=DOM-API, prop=[jsname="Sx9Kwc"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 145 and loc.getEndLine() = 145 and
            loc.getStartColumn() <= 273 and loc.getEndColumn() >= 273
        ) or 
        (   // id=1237, type=DOM-API, prop=[jsname="Sx9Kwc"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 145 and loc.getEndLine() = 145 and
            loc.getStartColumn() <= 273 and loc.getEndColumn() >= 273
        ) or 
        (   // id=1238, type=DOM-API, prop=[jscontroller], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 149 and loc.getEndLine() = 149 and
            loc.getStartColumn() <= 264 and loc.getEndColumn() >= 264
        ) or 
        (   // id=1239, type=DOM-API, prop=[jscontroller], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 149 and loc.getEndLine() = 149 and
            loc.getStartColumn() <= 264 and loc.getEndColumn() >= 264
        ) or 
        (   // id=1264, type=DOM-API, prop=[jsname="Ipv8bc"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 145 and loc.getEndLine() = 145 and
            loc.getStartColumn() <= 273 and loc.getEndColumn() >= 273
        ) or 
        (   // id=1265, type=DOM-API, prop=[jsname="Ipv8bc"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 145 and loc.getEndLine() = 145 and
            loc.getStartColumn() <= 273 and loc.getEndColumn() >= 273
        ) or 
        (   // id=1271, type=DOM-API, prop=gb, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 242 and loc.getEndLine() = 242 and
            loc.getStartColumn() <= 319 and loc.getEndColumn() >= 319
        ) or 
        (   // id=1276, type=DOM-API, prop=[jsaction*="MZ56ec"],[jscontroller][__IS_OWNER], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1277, type=DOM-API, prop=[jsaction*="MZ56ec"],[jscontroller][__IS_OWNER], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1304, type=DOM-API, prop=___gatsby, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1305, type=DOM-API, prop=react-root, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1331, type=DOM-API, prop=[jsaction*="vSCbUd"],[jscontroller][__IS_OWNER], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1332, type=DOM-API, prop=[jsaction*="vSCbUd"],[jscontroller][__IS_OWNER], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1342, type=DOM-API, prop=[jslog*=impression], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 774 and loc.getEndLine() = 774 and
            loc.getStartColumn() <= 400 and loc.getEndColumn() >= 400
        ) or 
        (   // id=1343, type=DOM-API, prop=[jslog*=impression], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/9c38dc6acc.js") and
            loc.getStartLine() = 774 and loc.getEndLine() = 774 and
            loc.getStartColumn() <= 400 and loc.getEndColumn() >= 400
        ) or 
        (   // id=1358, type=DOM-API, prop=[jsaction*="xixHIb"],[jscontroller][__IS_OWNER], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1359, type=DOM-API, prop=[jsaction*="xixHIb"],[jscontroller][__IS_OWNER], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1362, type=DOM-API, prop=[jsaction*="GvneHb"],[jscontroller][__IS_OWNER], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1363, type=DOM-API, prop=[jsaction*="GvneHb"],[jscontroller][__IS_OWNER], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.gstatic.com/_/mss/boq-one-google/_/js/kboq-one-google.OneGoogleWidgetUi.en.kIS1Dzh9gxA.es5.O/amEDDobA/d1/excm_b,_tp,calloutview/ed1/dg0/wt2/ujg1/rsAM-SdHvVjI37RrLHhU_vACoXtjGC9mw7Jw/m_b,_tp.html") and
            loc.getStartLine() = 287 and loc.getEndLine() = 287 and
            loc.getStartColumn() <= 149 and loc.getEndColumn() >= 149
        ) or 
        (   // id=1420, type=DOM-API, prop=ynRric, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1890 and loc.getEndLine() = 1890 and
            loc.getStartColumn() <= 2201 and loc.getEndColumn() >= 2201
        ) or 
        (   // id=1428, type=DOM-API, prop=[jsname="E80e9e"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=1429, type=DOM-API, prop=[jsname="E80e9e"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 204 and loc.getEndLine() = 204 and
            loc.getStartColumn() <= 126 and loc.getEndColumn() >= 126
        ) or 
        (   // id=1432, type=DOM-API, prop=G43f7e, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1884 and loc.getEndLine() = 1884 and
            loc.getStartColumn() <= 296 and loc.getEndColumn() >= 296
        ) or 
        (   // id=1434, type=DOM-API, prop=YMXe, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1835 and loc.getEndLine() = 1835 and
            loc.getStartColumn() <= 87 and loc.getEndColumn() >= 87
        ) or 
        (   // id=1435, type=DOM-API, prop=.pcTkSc, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 286 and loc.getEndColumn() >= 286
        ) or 
        (   // id=1437, type=DOM-API, prop=.wM6W7d, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 286 and loc.getEndColumn() >= 286
        ) or 
        (   // id=1451, type=DOM-API, prop=.sbic, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 286 and loc.getEndColumn() >= 286
        ) or 
        (   // id=1453, type=DOM-API, prop=.ClJ9Yb, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 286 and loc.getEndColumn() >= 286
        ) or 
        (   // id=1455, type=DOM-API, prop=.AQZ9Vd, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 286 and loc.getEndColumn() >= 286
        ) or 
        (   // id=1465, type=DOM-API, prop=.lnnVSe, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 742 and loc.getEndLine() = 742 and
            loc.getStartColumn() <= 286 and loc.getEndColumn() >= 286
        ) or 
        (   // id=1467, type=DOM-API, prop=AQZ9Vd, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/f11234c759.js") and
            loc.getStartLine() = 1835 and loc.getEndLine() = 1835 and
            loc.getStartColumn() <= 478 and loc.getEndColumn() >= 478
        ) or 
        (   // id=1747, type=DOM-API, prop=Alh6id, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=1748, type=DOM-API, prop=_Eg4jZoyKFqyI7NYPqqyUYA_6, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage/home/jackfromeast/Desktop/TheHulk/tmp/test-webpage-04-19-20-36/www.google.com/ac6bb669e4/source/www.google.com/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
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

DebuggingConfig() { this = "DOM-Clobbering-www.google.com-ac6bb669e4" }
    
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
