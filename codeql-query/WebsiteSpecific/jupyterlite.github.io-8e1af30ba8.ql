/**
* @name DOM-Clobbering-jupyterlite.github.io-8e1af30ba8
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
import Sinks.TheHulkSink
        
class IdentifiedClobberableSourceWinTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceWinTypeOne() {
        exists(DataFlow::PropRead propRead |
        exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (
        (   // id=21, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 33103 and loc.getEndColumn() >= 33103
        ) or 
        (   // id=25, type=WIN-TYPE-1, prop=webpackChunk_JUPYTERLAB_CORE_OUTPUT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 62976 and loc.getEndColumn() >= 62976
        ) or 
        (   // id=26, type=WIN-TYPE-1, prop=webpackChunk_JUPYTERLAB_CORE_OUTPUT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 62970 and loc.getEndColumn() >= 62970
        ) or 
        (   // id=61, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.832d780237fca436ff92.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3140 and loc.getEndColumn() >= 3140
        ) or 
        (   // id=64, type=WIN-TYPE-1, prop=webpackChunk_jupyter_notebook_lab_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.832d780237fca436ff92.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8183 and loc.getEndColumn() >= 8183
        ) or 
        (   // id=65, type=WIN-TYPE-1, prop=webpackChunk_jupyter_notebook_lab_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.832d780237fca436ff92.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8177 and loc.getEndColumn() >= 8177
        ) or 
        (   // id=66, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3075 and loc.getEndColumn() >= 3075
        ) or 
        (   // id=70, type=WIN-TYPE-1, prop=webpackChunk_jupyterlab_fasta_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6835 and loc.getEndColumn() >= 6835
        ) or 
        (   // id=71, type=WIN-TYPE-1, prop=webpackChunk_jupyterlab_fasta_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6829 and loc.getEndColumn() >= 6829
        ) or 
        (   // id=72, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4522 and loc.getEndColumn() >= 4522
        ) or 
        (   // id=76, type=WIN-TYPE-1, prop=webpackChunk_jupyter_widgets_jupyterlab_manager 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10392 and loc.getEndColumn() >= 10392
        ) or 
        (   // id=77, type=WIN-TYPE-1, prop=webpackChunk_jupyter_widgets_jupyterlab_manager 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10386 and loc.getEndColumn() >= 10386
        ) or 
        (   // id=78, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3355 and loc.getEndColumn() >= 3355
        ) or 
        (   // id=82, type=WIN-TYPE-1, prop=webpackChunk_jupyterlab_geojson_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7255 and loc.getEndColumn() >= 7255
        ) or 
        (   // id=83, type=WIN-TYPE-1, prop=webpackChunk_jupyterlab_geojson_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7249 and loc.getEndColumn() >= 7249
        ) or 
        (   // id=84, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/p5-kernel-extension/static/remoteEntry.9117113815033289c4d5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3185 and loc.getEndColumn() >= 3185
        ) or 
        (   // id=87, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_p5_kernel_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/p5-kernel-extension/static/remoteEntry.9117113815033289c4d5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7088 and loc.getEndColumn() >= 7088
        ) or 
        (   // id=88, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_p5_kernel_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/p5-kernel-extension/static/remoteEntry.9117113815033289c4d5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7082 and loc.getEndColumn() >= 7082
        ) or 
        (   // id=89, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/javascript-kernel-extension/static/remoteEntry.6014628263d9ee9ca44a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3097 and loc.getEndColumn() >= 3097
        ) or 
        (   // id=93, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_javascript_kernel_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/javascript-kernel-extension/static/remoteEntry.6014628263d9ee9ca44a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7125 and loc.getEndColumn() >= 7125
        ) or 
        (   // id=94, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_javascript_kernel_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/javascript-kernel-extension/static/remoteEntry.6014628263d9ee9ca44a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7119 and loc.getEndColumn() >= 7119
        ) or 
        (   // id=95, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2990 and loc.getEndColumn() >= 2990
        ) or 
        (   // id=98, type=WIN-TYPE-1, prop=webpackChunkipycanvas 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6694 and loc.getEndColumn() >= 6694
        ) or 
        (   // id=99, type=WIN-TYPE-1, prop=webpackChunkipycanvas 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6688 and loc.getEndColumn() >= 6688
        ) or 
        (   // id=100, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.5005680d014e4b7f3db1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3540 and loc.getEndColumn() >= 3540
        ) or 
        (   // id=104, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_pyodide_kernel_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.5005680d014e4b7f3db1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7670 and loc.getEndColumn() >= 7670
        ) or 
        (   // id=105, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_pyodide_kernel_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.5005680d014e4b7f3db1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7664 and loc.getEndColumn() >= 7664
        ) or 
        (   // id=106, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@timkpaine/jupyterlab_miami_nights/static/remoteEntry.382ac9f028a244bc2d44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2409 and loc.getEndColumn() >= 2409
        ) or 
        (   // id=109, type=WIN-TYPE-1, prop=webpackChunk_timkpaine_jupyterlab_miami_nights 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@timkpaine/jupyterlab_miami_nights/static/remoteEntry.382ac9f028a244bc2d44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5885 and loc.getEndColumn() >= 5885
        ) or 
        (   // id=110, type=WIN-TYPE-1, prop=webpackChunk_timkpaine_jupyterlab_miami_nights 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@timkpaine/jupyterlab_miami_nights/static/remoteEntry.382ac9f028a244bc2d44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5879 and loc.getEndColumn() >= 5879
        ) or 
        (   // id=111, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3807 and loc.getEndColumn() >= 3807
        ) or 
        (   // id=114, type=WIN-TYPE-1, prop=webpackChunkbqplot 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8308 and loc.getEndColumn() >= 8308
        ) or 
        (   // id=115, type=WIN-TYPE-1, prop=webpackChunkbqplot 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8302 and loc.getEndColumn() >= 8302
        ) or 
        (   // id=116, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipyevents/static/remoteEntry.4d5ef87d14f03accc582.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2787 and loc.getEndColumn() >= 2787
        ) or 
        (   // id=119, type=WIN-TYPE-1, prop=webpackChunkipyevents 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipyevents/static/remoteEntry.4d5ef87d14f03accc582.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6316 and loc.getEndColumn() >= 6316
        ) or 
        (   // id=120, type=WIN-TYPE-1, prop=webpackChunkipyevents 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipyevents/static/remoteEntry.4d5ef87d14f03accc582.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6310 and loc.getEndColumn() >= 6310
        ) or 
        (   // id=121, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2594 and loc.getEndColumn() >= 2594
        ) or 
        (   // id=124, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_night 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6017 and loc.getEndColumn() >= 6017
        ) or 
        (   // id=125, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_night 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6011 and loc.getEndColumn() >= 6011
        ) or 
        (   // id=126, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-plotly/static/remoteEntry.5ee426487d188c3eb29e.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3725 and loc.getEndColumn() >= 3725
        ) or 
        (   // id=129, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_plotly 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-plotly/static/remoteEntry.5ee426487d188c3eb29e.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7507 and loc.getEndColumn() >= 7507
        ) or 
        (   // id=130, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_plotly 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-plotly/static/remoteEntry.5ee426487d188c3eb29e.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7501 and loc.getEndColumn() >= 7501
        ) or 
        (   // id=131, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5487 and loc.getEndColumn() >= 5487
        ) or 
        (   // id=135, type=WIN-TYPE-1, prop=webpackChunkjupyter_leaflet 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11783 and loc.getEndColumn() >= 11783
        ) or 
        (   // id=136, type=WIN-TYPE-1, prop=webpackChunkjupyter_leaflet 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11777 and loc.getEndColumn() >= 11777
        ) or 
        (   // id=137, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-matplotlib/static/remoteEntry.2245c790a510bf1865ea.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3158 and loc.getEndColumn() >= 3158
        ) or 
        (   // id=140, type=WIN-TYPE-1, prop=webpackChunkjupyter_matplotlib 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-matplotlib/static/remoteEntry.2245c790a510bf1865ea.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6922 and loc.getEndColumn() >= 6922
        ) or 
        (   // id=141, type=WIN-TYPE-1, prop=webpackChunkjupyter_matplotlib 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-matplotlib/static/remoteEntry.2245c790a510bf1865ea.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6916 and loc.getEndColumn() >= 6916
        ) or 
        (   // id=142, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2709 and loc.getEndColumn() >= 2709
        ) or 
        (   // id=145, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_pygments 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3724 and loc.getEndColumn() >= 3724
        ) or 
        (   // id=146, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_pygments 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3718 and loc.getEndColumn() >= 3718
        ) or 
        (   // id=209, type=WIN-TYPE-1, prop=__REACT_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 129088 and loc.getEndColumn() >= 129088
        ) or 
        (   // id=210, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 130173 and loc.getEndColumn() >= 130173
        ) or 
        (   // id=212, type=WIN-TYPE-1, prop=MSApp 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 13254 and loc.getEndColumn() >= 13254
        ) or 
        (   // id=215, type=WIN-TYPE-1, prop=__REACT_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 126767 and loc.getEndColumn() >= 126767
        ) or 
        (   // id=537, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/755.6424780.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4875 and loc.getEndColumn() >= 4875
        ) or 
        (   // id=538, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/755.6424780.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11642 and loc.getEndColumn() >= 11642
        ) or 
        (   // id=539, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/755.6424780.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 9427 and loc.getEndColumn() >= 9427
        ) or 
        (   // id=540, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/7811.bd10193.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 4449 and loc.getEndColumn() >= 4449
        ) or 
        (   // id=541, type=WIN-TYPE-1, prop=FAST 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/8734.0965980.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1458 and loc.getEndColumn() >= 1458
        ) or 
        (   // id=554, type=WIN-TYPE-1, prop=SuppressedError 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 133 and loc.getEndLine() = 133 and
            loc.getStartColumn() <= 2509 and loc.getEndColumn() >= 2509
        ) or 
        (   // id=569, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 378 and loc.getEndColumn() >= 378
        ) or 
        (   // id=570, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 462 and loc.getEndColumn() >= 462
        ) or 
        (   // id=572, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1762 and loc.getEndColumn() >= 1762
        ) or 
        (   // id=573, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1772 and loc.getEndColumn() >= 1772
        ) or 
        (   // id=574, type=WIN-TYPE-1, prop=core 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3159 and loc.getEndColumn() >= 3159
        ) or 
        (   // id=582, type=WIN-TYPE-1, prop=__ $YJS$ __ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/9643.4b4e30e.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 82212 and loc.getEndColumn() >= 82212
        ) or 
        (   // id=583, type=WIN-TYPE-1, prop=__ $YJS$ __ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/9643.4b4e30e.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 82363 and loc.getEndColumn() >= 82363
        ) or 
        (   // id=785, type=WIN-TYPE-1, prop=openDatabase 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/927.399dde7.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 9712 and loc.getEndColumn() >= 9712
        ) or 
        (   // id=786, type=WIN-TYPE-1, prop=openDatabase 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/927.399dde7.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 18446 and loc.getEndColumn() >= 18446
        ) or 
        (   // id=791, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4324.992bd2c.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1158 and loc.getEndColumn() >= 1158
        ) or 
        (   // id=792, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4324.992bd2c.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1661 and loc.getEndColumn() >= 1661
        ) or 
        (   // id=798, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/644.52a1098a3a5f3e45abff.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37207 and loc.getEndColumn() >= 37207
        ) or 
        (   // id=799, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/644.52a1098a3a5f3e45abff.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 35299 and loc.getEndColumn() >= 35299
        ) or 
        (   // id=856, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 86949 and loc.getEndColumn() >= 86949
        ) or 
        (   // id=857, type=WIN-TYPE-1, prop=$ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 86961 and loc.getEndColumn() >= 86961
        ) or 
        (   // id=858, type=WIN-TYPE-1, prop=Backbone 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/644.52a1098a3a5f3e45abff.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 321 and loc.getEndColumn() >= 321
        ) or 
        (   // id=859, type=WIN-TYPE-1, prop=Backbone 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/644.52a1098a3a5f3e45abff.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 294 and loc.getEndColumn() >= 294
        ) or 
        (   // id=895, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 15615 and loc.getEndColumn() >= 15615
        ) or 
        (   // id=896, type=WIN-TYPE-1, prop=opera 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 15917 and loc.getEndColumn() >= 15917
        ) or 
        (   // id=897, type=WIN-TYPE-1, prop=L_DISABLE_3D 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16202 and loc.getEndColumn() >= 16202
        ) or 
        (   // id=898, type=WIN-TYPE-1, prop=orientation 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16242 and loc.getEndColumn() >= 16242
        ) or 
        (   // id=899, type=WIN-TYPE-1, prop=ontouchstart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16404 and loc.getEndColumn() >= 16404
        ) or 
        (   // id=900, type=WIN-TYPE-1, prop=L_NO_TOUCH 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16446 and loc.getEndColumn() >= 16446
        ) or 
        (   // id=908, type=WIN-TYPE-1, prop=L 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 148785 and loc.getEndColumn() >= 148785
        ) or 
        (   // id=909, type=WIN-TYPE-1, prop=L 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 148844 and loc.getEndColumn() >= 148844
        ) or 
        (   // id=910, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 386456 and loc.getEndColumn() >= 386456
        ) or 
        (   // id=911, type=WIN-TYPE-1, prop=_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 391638 and loc.getEndColumn() >= 391638
        ) or 
        (   // id=912, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 391768 and loc.getEndColumn() >= 391768
        ) or 
        (   // id=913, type=WIN-TYPE-1, prop=_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 452310 and loc.getEndColumn() >= 452310
        ) or 
        (   // id=915, type=WIN-TYPE-1, prop=$ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 372077 and loc.getEndColumn() >= 372077
        ) or 
        (   // id=916, type=WIN-TYPE-1, prop=jBone 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 372083 and loc.getEndColumn() >= 372083
        ) or 
        (   // id=917, type=WIN-TYPE-1, prop=C2S 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 173917 and loc.getEndColumn() >= 173917
        ) or 
        (   // id=918, type=WIN-TYPE-1, prop=IO_VERSION 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 127130 and loc.getEndColumn() >= 127130
        ) or 
        (   // id=920, type=WIN-TYPE-1, prop=BlobBuilder 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153178 and loc.getEndColumn() >= 153178
        ) or 
        (   // id=921, type=WIN-TYPE-1, prop=WebKitBlobBuilder 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153198 and loc.getEndColumn() >= 153198
        ) or 
        (   // id=922, type=WIN-TYPE-1, prop=MozBlobBuilder 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153224 and loc.getEndColumn() >= 153224
        ) or 
        (   // id=923, type=WIN-TYPE-1, prop=MSBlobBuilder 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153247 and loc.getEndColumn() >= 153247
        ) or 
        (   // id=925, type=WIN-TYPE-1, prop=externalHost 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 154263 and loc.getEndColumn() >= 154263
        ) or 
        (   // id=926, type=WIN-TYPE-1, prop=requestFileSystem 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 154324 and loc.getEndColumn() >= 154324
        ) or 
        (   // id=927, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 156554 and loc.getEndColumn() >= 156554
        ) or 
        (   // id=928, type=WIN-TYPE-1, prop=almond 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 156589 and loc.getEndColumn() >= 156589
        ) or 
        (   // id=929, type=WIN-TYPE-1, prop=MSA_VERSION 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 14546 and loc.getEndColumn() >= 14546
        ) or 
        (   // id=932, type=WIN-TYPE-1, prop=MSInputMethodContext 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/981.3f93685e278b785a3338.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 1138 and loc.getEndColumn() >= 1138
        ) or 
        (   // id=933, type=WIN-TYPE-1, prop=PopperUtils 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/981.3f93685e278b785a3338.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 20751 and loc.getEndColumn() >= 20751
        ) or 
        (   // id=939, type=WIN-TYPE-1, prop=TYPED_ARRAY_SUPPORT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipycanvas/static/764.dc7b08f6512a8a28ecfe.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7664 and loc.getEndColumn() >= 7664
        ) or 
        (   // id=950, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/961.cf93e7085b1c412600d8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 23611 and loc.getEndColumn() >= 23611
        ) or 
        (   // id=951, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/961.cf93e7085b1c412600d8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 24703 and loc.getEndColumn() >= 24703
        ) or 
        (   // id=954, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 33440 and loc.getEndColumn() >= 33440
        ) or 
        (   // id=955, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4067 and loc.getEndColumn() >= 4067
        ) or 
        (   // id=956, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4199 and loc.getEndColumn() >= 4199
        ) or 
        (   // id=957, type=WIN-TYPE-1, prop=DEBUG 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16546 and loc.getEndColumn() >= 16546
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
        (   // id=213, type=DOC-TYPE-1, prop=documentMode 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 30531 and loc.getEndColumn() >= 30531
        ) or 
        (   // id=561, type=DOC-TYPE-1, prop=host 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/2930.896decd.js") and
            loc.getStartLine() = 467 and loc.getEndLine() = 467 and
            loc.getStartColumn() <= 89 and loc.getEndColumn() >= 89
        ) or 
        (   // id=807, type=DOC-TYPE-1, prop=namespaceURI 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 3669 and loc.getEndColumn() >= 3669
        ) or 
        (   // id=907, type=DOC-TYPE-1, prop=namespaces 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 129052 and loc.getEndColumn() >= 129052
        ) or 
        (   // id=2218, type=DOC-TYPE-1, prop=_reactListeningyi74uh5q8oi 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 37773 and loc.getEndColumn() >= 37773
        ) or 
        (   // id=9382, type=DOC-TYPE-1, prop=host 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/3218.758a794.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 3792 and loc.getEndColumn() >= 3792
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
        (   // id=16, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/config-utils.js") and
            loc.getStartLine() = 242 and loc.getEndLine() = 242 and
            loc.getStartColumn() <= 11 and loc.getEndColumn() >= 11
        ) or 
        (   // id=20, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/config-utils.js") and
            loc.getStartLine() = 261 and loc.getEndLine() = 261 and
            loc.getStartColumn() <= 11 and loc.getEndColumn() >= 11
        ) or 
        (   // id=22, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 33169 and loc.getEndColumn() >= 33169
        ) or 
        (   // id=23, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 33189 and loc.getEndColumn() >= 33189
        ) or 
        (   // id=30, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 600 and loc.getEndColumn() >= 600
        ) or 
        (   // id=62, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.832d780237fca436ff92.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3206 and loc.getEndColumn() >= 3206
        ) or 
        (   // id=63, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.832d780237fca436ff92.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3226 and loc.getEndColumn() >= 3226
        ) or 
        (   // id=67, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3141 and loc.getEndColumn() >= 3141
        ) or 
        (   // id=68, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3161 and loc.getEndColumn() >= 3161
        ) or 
        (   // id=73, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4588 and loc.getEndColumn() >= 4588
        ) or 
        (   // id=74, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4608 and loc.getEndColumn() >= 4608
        ) or 
        (   // id=79, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3421 and loc.getEndColumn() >= 3421
        ) or 
        (   // id=80, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3441 and loc.getEndColumn() >= 3441
        ) or 
        (   // id=85, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/p5-kernel-extension/static/remoteEntry.9117113815033289c4d5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3251 and loc.getEndColumn() >= 3251
        ) or 
        (   // id=86, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/p5-kernel-extension/static/remoteEntry.9117113815033289c4d5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3271 and loc.getEndColumn() >= 3271
        ) or 
        (   // id=90, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/javascript-kernel-extension/static/remoteEntry.6014628263d9ee9ca44a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3163 and loc.getEndColumn() >= 3163
        ) or 
        (   // id=91, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/javascript-kernel-extension/static/remoteEntry.6014628263d9ee9ca44a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3183 and loc.getEndColumn() >= 3183
        ) or 
        (   // id=96, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3056 and loc.getEndColumn() >= 3056
        ) or 
        (   // id=97, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3076 and loc.getEndColumn() >= 3076
        ) or 
        (   // id=101, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.5005680d014e4b7f3db1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3606 and loc.getEndColumn() >= 3606
        ) or 
        (   // id=102, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.5005680d014e4b7f3db1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3626 and loc.getEndColumn() >= 3626
        ) or 
        (   // id=107, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@timkpaine/jupyterlab_miami_nights/static/remoteEntry.382ac9f028a244bc2d44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2475 and loc.getEndColumn() >= 2475
        ) or 
        (   // id=108, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@timkpaine/jupyterlab_miami_nights/static/remoteEntry.382ac9f028a244bc2d44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2495 and loc.getEndColumn() >= 2495
        ) or 
        (   // id=112, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3873 and loc.getEndColumn() >= 3873
        ) or 
        (   // id=113, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3893 and loc.getEndColumn() >= 3893
        ) or 
        (   // id=117, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipyevents/static/remoteEntry.4d5ef87d14f03accc582.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2853 and loc.getEndColumn() >= 2853
        ) or 
        (   // id=118, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipyevents/static/remoteEntry.4d5ef87d14f03accc582.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2873 and loc.getEndColumn() >= 2873
        ) or 
        (   // id=122, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2660 and loc.getEndColumn() >= 2660
        ) or 
        (   // id=123, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2680 and loc.getEndColumn() >= 2680
        ) or 
        (   // id=127, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-plotly/static/remoteEntry.5ee426487d188c3eb29e.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3791 and loc.getEndColumn() >= 3791
        ) or 
        (   // id=128, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-plotly/static/remoteEntry.5ee426487d188c3eb29e.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3811 and loc.getEndColumn() >= 3811
        ) or 
        (   // id=132, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5553 and loc.getEndColumn() >= 5553
        ) or 
        (   // id=133, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5573 and loc.getEndColumn() >= 5573
        ) or 
        (   // id=138, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-matplotlib/static/remoteEntry.2245c790a510bf1865ea.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3224 and loc.getEndColumn() >= 3224
        ) or 
        (   // id=139, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-matplotlib/static/remoteEntry.2245c790a510bf1865ea.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3244 and loc.getEndColumn() >= 3244
        ) or 
        (   // id=143, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2775 and loc.getEndColumn() >= 2775
        ) or 
        (   // id=144, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2795 and loc.getEndColumn() >= 2795
        ) or 
        (   // id=150, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8695 and loc.getEndColumn() >= 8695
        ) or 
        (   // id=203, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 439470 and loc.getEndColumn() >= 439470
        ) or 
        (   // id=204, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 439501 and loc.getEndColumn() >= 439501
        ) or 
        (   // id=552, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/2930.896decd.js") and
            loc.getStartLine() = 1464 and loc.getEndLine() = 1464 and
            loc.getStartColumn() <= 5040 and loc.getEndColumn() >= 5040
        ) or 
        (   // id=553, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/2930.896decd.js") and
            loc.getStartLine() = 1464 and loc.getEndLine() = 1464 and
            loc.getStartColumn() <= 5160 and loc.getEndColumn() >= 5160
        ) or 
        (   // id=557, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 47406 and loc.getEndColumn() >= 47406
        ) or 
        (   // id=558, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48391 and loc.getEndColumn() >= 48391
        ) or 
        (   // id=559, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48408 and loc.getEndColumn() >= 48408
        ) or 
        (   // id=560, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48657 and loc.getEndColumn() >= 48657
        ) or 
        (   // id=562, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48768 and loc.getEndColumn() >= 48768
        ) or 
        (   // id=655, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.832d780237fca436ff92.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2311 and loc.getEndColumn() >= 2311
        ) or 
        (   // id=663, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3105 and loc.getEndColumn() >= 3105
        ) or 
        (   // id=677, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2244 and loc.getEndColumn() >= 2244
        ) or 
        (   // id=687, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3418 and loc.getEndColumn() >= 3418
        ) or 
        (   // id=691, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2609 and loc.getEndColumn() >= 2609
        ) or 
        (   // id=699, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/javascript-kernel-extension/static/remoteEntry.6014628263d9ee9ca44a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2248 and loc.getEndColumn() >= 2248
        ) or 
        (   // id=707, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/p5-kernel-extension/static/remoteEntry.9117113815033289c4d5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2360 and loc.getEndColumn() >= 2360
        ) or 
        (   // id=712, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.5005680d014e4b7f3db1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2700 and loc.getEndColumn() >= 2700
        ) or 
        (   // id=716, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@timkpaine/jupyterlab_miami_nights/static/remoteEntry.382ac9f028a244bc2d44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1888 and loc.getEndColumn() >= 1888
        ) or 
        (   // id=720, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2655 and loc.getEndColumn() >= 2655
        ) or 
        (   // id=733, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2250 and loc.getEndColumn() >= 2250
        ) or 
        (   // id=740, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipyevents/static/remoteEntry.4d5ef87d14f03accc582.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2125 and loc.getEndColumn() >= 2125
        ) or 
        (   // id=765, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-matplotlib/static/remoteEntry.2245c790a510bf1865ea.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2346 and loc.getEndColumn() >= 2346
        ) or 
        (   // id=769, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1942 and loc.getEndColumn() >= 1942
        ) or 
        (   // id=773, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-plotly/static/remoteEntry.5ee426487d188c3eb29e.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2906 and loc.getEndColumn() >= 2906
        ) or 
        (   // id=781, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2051 and loc.getEndColumn() >= 2051
        ) or 
        (   // id=787, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11419 and loc.getEndColumn() >= 11419
        ) or 
        (   // id=788, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11964 and loc.getEndColumn() >= 11964
        ) or 
        (   // id=789, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 140845 and loc.getEndColumn() >= 140845
        ) or 
        (   // id=790, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 140866 and loc.getEndColumn() >= 140866
        ) or 
        (   // id=805, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8543 and loc.getEndColumn() >= 8543
        ) or 
        (   // id=806, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8568 and loc.getEndColumn() >= 8568
        ) or 
        (   // id=809, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 3708 and loc.getEndColumn() >= 3708
        ) or 
        (   // id=842, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 33241 and loc.getEndColumn() >= 33241
        ) or 
        (   // id=855, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 82107 and loc.getEndColumn() >= 82107
        ) or 
        (   // id=894, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 15575 and loc.getEndColumn() >= 15575
        ) or 
        (   // id=905, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 20616 and loc.getEndColumn() >= 20616
        ) or 
        (   // id=930, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/815.4fcd9a1489787115f930.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6624 and loc.getEndColumn() >= 6624
        ) or 
        (   // id=952, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 36695 and loc.getEndColumn() >= 36695
        ) or 
        (   // id=959, type=DOC-TYPE-2, prop=all 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13192 and loc.getEndColumn() >= 13192
        ) or 
        (   // id=1057, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 143782 and loc.getEndColumn() >= 143782
        ) or 
        (   // id=1064, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1331894 and loc.getEndColumn() >= 1331894
        ) or 
        (   // id=2379, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10077 and loc.getEndColumn() >= 10077
        ) or 
        (   // id=2986, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1664959 and loc.getEndColumn() >= 1664959
        ) or 
        (   // id=4057, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1330204 and loc.getEndColumn() >= 1330204
        ) or 
        (   // id=4933, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 862393 and loc.getEndColumn() >= 862393
        ) or 
        (   // id=4936, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 868261 and loc.getEndColumn() >= 868261
        ) or 
        (   // id=7421, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1501280 and loc.getEndColumn() >= 1501280
        ) or 
        (   // id=8102, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 145191 and loc.getEndColumn() >= 145191
        ) or 
        (   // id=9321, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1446773 and loc.getEndColumn() >= 1446773
        ) or 
        (   // id=9346, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 155678 and loc.getEndColumn() >= 155678
        ) or 
        (   // id=9347, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 99978 and loc.getEndColumn() >= 99978
        ) or 
        (   // id=9349, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 191310 and loc.getEndColumn() >= 191310
        ) or 
        (   // id=9387, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 87070 and loc.getEndColumn() >= 87070
        ) or 
        (   // id=9388, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 87126 and loc.getEndColumn() >= 87126
        ) or 
        (   // id=9389, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 87162 and loc.getEndColumn() >= 87162
        ) or 
        (   // id=9390, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 87235 and loc.getEndColumn() >= 87235
        ) or 
        (   // id=9397, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48884 and loc.getEndColumn() >= 48884
        ) or 
        (   // id=9403, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48001 and loc.getEndColumn() >= 48001
        ) or 
        (   // id=9406, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 48207 and loc.getEndColumn() >= 48207
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
        (   // id=1, type=DOM-API, prop=Undefined, api=forms
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7, type=DOM-API, prop=___gatsby, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8, type=DOM-API, prop=react-root, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=10, type=DOM-API, prop=jupyter-config-data, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/config-utils.js") and
            loc.getStartLine() = 60 and loc.getEndLine() = 60 and
            loc.getStartColumn() <= 32 and loc.getEndColumn() >= 32
        ) or 
        (   // id=12, type=DOM-API, prop=jupyter-config-data, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/config-utils.js") and
            loc.getStartLine() = 181 and loc.getEndLine() = 181 and
            loc.getStartColumn() <= 18 and loc.getEndColumn() >= 18
        ) or 
        (   // id=18, type=DOM-API, prop=jupyter-lite-main, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/config-utils.js") and
            loc.getStartLine() = 257 and loc.getEndLine() = 257 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=28, type=DOM-API, prop=jupyter-config-data, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 195 and loc.getEndColumn() >= 195
        ) or 
        (   // id=148, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8091 and loc.getEndColumn() >= 8091
        ) or 
        (   // id=202, type=DOM-API, prop=jupyter-config-data, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 436713 and loc.getEndColumn() >= 436713
        ) or 
        (   // id=217, type=DOM-API, prop=[data-icon-id="undefined"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1350367 and loc.getEndColumn() >= 1350367
        ) or 
        (   // id=218, type=DOM-API, prop=[data-icon-id="undefined"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1350367 and loc.getEndColumn() >= 1350367
        ) or 
        (   // id=550, type=DOM-API, prop=meta[property="csp-nonce"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/2930.896decd.js") and
            loc.getStartLine() = 1464 and loc.getEndLine() = 1464 and
            loc.getStartColumn() <= 4909 and loc.getEndColumn() >= 4909
        ) or 
        (   // id=622, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/9903.633a36a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 242755 and loc.getEndColumn() >= 242755
        ) or 
        (   // id=653, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.832d780237fca436ff92.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1707 and loc.getEndColumn() >= 1707
        ) or 
        (   // id=661, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2501 and loc.getEndColumn() >= 2501
        ) or 
        (   // id=675, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1640 and loc.getEndColumn() >= 1640
        ) or 
        (   // id=685, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2814 and loc.getEndColumn() >= 2814
        ) or 
        (   // id=689, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2005 and loc.getEndColumn() >= 2005
        ) or 
        (   // id=697, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/javascript-kernel-extension/static/remoteEntry.6014628263d9ee9ca44a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1644 and loc.getEndColumn() >= 1644
        ) or 
        (   // id=705, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/p5-kernel-extension/static/remoteEntry.9117113815033289c4d5.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1756 and loc.getEndColumn() >= 1756
        ) or 
        (   // id=710, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.5005680d014e4b7f3db1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2096 and loc.getEndColumn() >= 2096
        ) or 
        (   // id=714, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@timkpaine/jupyterlab_miami_nights/static/remoteEntry.382ac9f028a244bc2d44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1284 and loc.getEndColumn() >= 1284
        ) or 
        (   // id=718, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2051 and loc.getEndColumn() >= 2051
        ) or 
        (   // id=731, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1646 and loc.getEndColumn() >= 1646
        ) or 
        (   // id=738, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/ipyevents/static/remoteEntry.4d5ef87d14f03accc582.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1521 and loc.getEndColumn() >= 1521
        ) or 
        (   // id=763, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-matplotlib/static/remoteEntry.2245c790a510bf1865ea.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1742 and loc.getEndColumn() >= 1742
        ) or 
        (   // id=767, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1338 and loc.getEndColumn() >= 1338
        ) or 
        (   // id=771, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-plotly/static/remoteEntry.5ee426487d188c3eb29e.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2302 and loc.getEndColumn() >= 2302
        ) or 
        (   // id=779, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1447 and loc.getEndColumn() >= 1447
        ) or 
        (   // id=795, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-notebook/lab-extension/static/93.eae3497dd223d842d198.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2841 and loc.getEndColumn() >= 2841
        ) or 
        (   // id=813, type=DOM-API, prop=jQuery37003269350180337296, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8815 and loc.getEndColumn() >= 8815
        ) or 
        (   // id=817, type=DOM-API, prop=:scope, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8946 and loc.getEndColumn() >= 8946
        ) or 
        (   // id=818, type=DOM-API, prop=:scope, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8946 and loc.getEndColumn() >= 8946
        ) or 
        (   // id=821, type=DOM-API, prop=:has(*,:jqfake), api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 9013 and loc.getEndColumn() >= 9013
        ) or 
        (   // id=823, type=DOM-API, prop=[selected], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10094 and loc.getEndColumn() >= 10094
        ) or 
        (   // id=824, type=DOM-API, prop=[selected], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10094 and loc.getEndColumn() >= 10094
        ) or 
        (   // id=825, type=DOM-API, prop=[id~=jQuery37003269350180337296-], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10170 and loc.getEndColumn() >= 10170
        ) or 
        (   // id=826, type=DOM-API, prop=[id~=jQuery37003269350180337296-], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10170 and loc.getEndColumn() >= 10170
        ) or 
        (   // id=827, type=DOM-API, prop=jQuery37003269350180337296, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10226 and loc.getEndColumn() >= 10226
        ) or 
        (   // id=828, type=DOM-API, prop=a#jQuery37003269350180337296+*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10226 and loc.getEndColumn() >= 10226
        ) or 
        (   // id=829, type=DOM-API, prop=a#jQuery37003269350180337296+*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10226 and loc.getEndColumn() >= 10226
        ) or 
        (   // id=830, type=DOM-API, prop=:checked, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10285 and loc.getEndColumn() >= 10285
        ) or 
        (   // id=831, type=DOM-API, prop=:checked, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10285 and loc.getEndColumn() >= 10285
        ) or 
        (   // id=833, type=DOM-API, prop=:disabled, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10477 and loc.getEndColumn() >= 10477
        ) or 
        (   // id=834, type=DOM-API, prop=:disabled, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10477 and loc.getEndColumn() >= 10477
        ) or 
        (   // id=836, type=DOM-API, prop=[name=''], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10618 and loc.getEndColumn() >= 10618
        ) or 
        (   // id=837, type=DOM-API, prop=[name=''], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10618 and loc.getEndColumn() >= 10618
        ) or 
        (   // id=862, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyter-widgets/jupyterlab-manager/static/134.fe2572ece3b7955c89bb.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 69790 and loc.getEndColumn() >= 69790
        ) or 
        (   // id=878, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/fasta-extension/static/643.929c653e8b3ed3e6bb69.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7402 and loc.getEndColumn() >= 7402
        ) or 
        (   // id=885, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/@jupyterlab/geojson-extension/static/643.bdb928a9116846bf6939.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19642 and loc.getEndColumn() >= 19642
        ) or 
        (   // id=936, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/bqplot/static/133.184b7ff4eeea6053c218.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13116 and loc.getEndColumn() >= 13116
        ) or 
        (   // id=945, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/665.5238b4be159a24e206a7.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5988 and loc.getEndColumn() >= 5988
        ) or 
        (   // id=958, type=DOM-API, prop=Non-Undefined, api=all
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13193 and loc.getEndColumn() >= 13193
        ) or 
        (   // id=962, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13428 and loc.getEndColumn() >= 13428
        ) or 
        (   // id=981, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab-plotly/static/423.d0d3e2912c33c7566484.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4759 and loc.getEndColumn() >= 4759
        ) or 
        (   // id=994, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/extensions/jupyterlab_pygments/static/747.67662283a5707eeb4d4c.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6606 and loc.getEndColumn() >= 6606
        ) or 
        (   // id=1028, type=DOM-API, prop=lm-TabBar-content, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1620410 and loc.getEndColumn() >= 1620410
        ) or 
        (   // id=1062, type=DOM-API, prop=parsererror, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1347895 and loc.getEndColumn() >= 1347895
        ) or 
        (   // id=1087, type=DOM-API, prop=jp-SearchIconGroup, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 145637 and loc.getEndColumn() >= 145637
        ) or 
        (   // id=1088, type=DOM-API, prop=lm-CommandPalette-input, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1593009 and loc.getEndColumn() >= 1593009
        ) or 
        (   // id=1094, type=DOM-API, prop=lm-close-icon, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1593736 and loc.getEndColumn() >= 1593736
        ) or 
        (   // id=1098, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 82629 and loc.getEndColumn() >= 82629
        ) or 
        (   // id=1105, type=DOM-API, prop=lm-CommandPalette-content, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1593097 and loc.getEndColumn() >= 1593097
        ) or 
        (   // id=1315, type=DOM-API, prop=li[tabindex="0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1622832 and loc.getEndColumn() >= 1622832
        ) or 
        (   // id=1320, type=DOM-API, prop=body, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1330, type=DOM-API, prop=.jp-Activity, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1386, type=DOM-API, prop=.jp-CodeConsole-promptCell .jp-mod-completer-enabled, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1390, type=DOM-API, prop=.jp-FileEditor .jp-mod-completer-enabled, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1394, type=DOM-API, prop=.jp-Notebook.jp-mod-editMode .jp-mod-completer-enabled, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1398, type=DOM-API, prop=.jp-CodeConsole[data-jp-interaction-mode='terminal'] .jp-CodeConsole-promptCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1402, type=DOM-API, prop=.jp-CodeConsole[data-jp-interaction-mode='notebook'] .jp-CodeConsole-promptCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1410, type=DOM-API, prop=.jp-mod-search-active, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1414, type=DOM-API, prop=.jp-mod-searchable, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1424, type=DOM-API, prop=.jp-DirListing-content .jp-DirListing-itemText, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1434, type=DOM-API, prop=.jp-DirListing:focus, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1444, type=DOM-API, prop=.jp-ImageViewer, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1462, type=DOM-API, prop=body[data-jp-inspector='open'], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1470, type=DOM-API, prop=.jp-Notebook.jp-mod-editMode, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1476, type=DOM-API, prop=.jp-Notebook.jp-mod-commandMode:not(.jp-mod-readWrite) :focus, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1508, type=DOM-API, prop=.jp-Notebook.jp-mod-commandMode .jp-Cell:focus, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1584, type=DOM-API, prop=.jp-SettingEditor, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1590, type=DOM-API, prop=body.jp-mod-tooltip .jp-CodeConsole-promptCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1594, type=DOM-API, prop=body.jp-mod-tooltip .jp-Notebook, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1598, type=DOM-API, prop=.jp-CodeConsole-promptCell .jp-InputArea-editor:not(.jp-mod-has-primary-selection):not(.jp-mod-in-leading-whitespace), api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1602, type=DOM-API, prop=.jp-FileEditor .jp-CodeMirrorEditor:not(.jp-mod-has-primary-selection):not(.jp-mod-in-leading-whitespace), api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=1606, type=DOM-API, prop=.jp-Notebook.jp-mod-editMode .jp-InputArea-editor:not(.jp-mod-has-primary-selection):not(.jp-mod-in-leading-whitespace):not(.jp-mod-completer-active), api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=2223, type=DOM-API, prop=lm-Menu-content, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1603401 and loc.getEndColumn() >= 1603401
        ) or 
        (   // id=2239, type=DOM-API, prop=lm-MenuBar-content, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1673719 and loc.getEndColumn() >= 1673719
        ) or 
        (   // id=2723, type=DOM-API, prop=[data-jp-undoer], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=2767, type=DOM-API, prop=[data-jp-kernel-user]:not(.jp-mod-readWrite) :focus:not(:read-write), api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=2879, type=DOM-API, prop=[data-jp-code-runner], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=2912, type=DOM-API, prop=.jp-RenderedMermaid, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=2968, type=DOM-API, prop=.jp-DirListing-header, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 146476 and loc.getEndColumn() >= 146476
        ) or 
        (   // id=2982, type=DOM-API, prop=.jp-DirListing-headerItemIcon, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 146476 and loc.getEndColumn() >= 146476
        ) or 
        (   // id=4932, type=DOM-API, prop=file-upload-button, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 636161 and loc.getEndColumn() >= 636161
        ) or 
        (   // id=4935, type=DOM-API, prop=jp-NotebookExtension-sideBySideMargins, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 868219 and loc.getEndColumn() >= 868219
        ) or 
        (   // id=5651, type=DOM-API, prop=.jp-OutputArea-child, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=5657, type=DOM-API, prop=.jp-Notebook .jp-mod-completer-active, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=5678, type=DOM-API, prop=.jp-ConsolePanel .jp-mod-completer-active, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=5788, type=DOM-API, prop=.jp-FileEditor .jp-mod-completer-active, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7422, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1564028 and loc.getEndColumn() >= 1564028
        ) or 
        (   // id=7439, type=DOM-API, prop=undefined, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/8734.0965980.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37306 and loc.getEndColumn() >= 37306
        ) or 
        (   // id=7440, type=DOM-API, prop=undefined, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/8734.0965980.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37306 and loc.getEndColumn() >= 37306
        ) or 
        (   // id=7458, type=DOM-API, prop=.jp-DirListing-content, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 146476 and loc.getEndColumn() >= 146476
        ) or 
        (   // id=7470, type=DOM-API, prop=.jp-RunningSessions-item.jp-mod-kernel, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7472, type=DOM-API, prop=.jp-Notebook .jp-Cell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7474, type=DOM-API, prop=.jp-DirListing-content, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7476, type=DOM-API, prop=.jp-FileEditor, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7478, type=DOM-API, prop=.jp-DirListing-item[data-isdir], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7480, type=DOM-API, prop=.jp-CodeConsole-promptCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7482, type=DOM-API, prop=.jp-DirListing-item[data-isdir="false"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7484, type=DOM-API, prop=#jp-main-dock-panel .lm-DockPanel-tabBar .lm-TabBar-tab, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7486, type=DOM-API, prop=[data-type="document-title"].jp-mod-current, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7488, type=DOM-API, prop=.jp-Notebook .jp-CodeCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7490, type=DOM-API, prop=.jp-CodeConsole-content, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7492, type=DOM-API, prop=.jp-DirListing-item[data-isdir="false"].jp-mod-running, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7494, type=DOM-API, prop=.MathJax, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7496, type=DOM-API, prop=.jp-Notebook, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7498, type=DOM-API, prop=.jp-DirListing-header, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7500, type=DOM-API, prop=[data-type="document-title"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7502, type=DOM-API, prop=.jp-CodeConsole, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7504, type=DOM-API, prop=.jp-SideBar .lm-TabBar-tab, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7506, type=DOM-API, prop=.jp-TableOfContents-content[data-document-type="notebook"] .jp-tocItem, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=7508, type=DOM-API, prop=.jp-RenderedMarkdown, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=8586, type=DOM-API, prop=.jp-mod-inline-completer-active, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=8590, type=DOM-API, prop=.jp-mod-completer-enabled, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1517990 and loc.getEndColumn() >= 1517990
        ) or 
        (   // id=9316, type=DOM-API, prop=jp-button, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1119912 and loc.getEndColumn() >= 1119912
        ) or 
        (   // id=9331, type=DOM-API, prop=lm-TabBar-addButton, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1620494 and loc.getEndColumn() >= 1620494
        ) or 
        (   // id=9353, type=DOM-API, prop=*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 4163 and loc.getEndLine() = 4163 and
            loc.getStartColumn() <= 2621 and loc.getEndColumn() >= 2621
        ) or 
        (   // id=9354, type=DOM-API, prop=*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/4333.fdaab90.js") and
            loc.getStartLine() = 4163 and loc.getEndLine() = 4163 and
            loc.getStartColumn() <= 2621 and loc.getEndColumn() >= 2621
        ) or 
        (   // id=9358, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=9369, type=DOM-API, prop=jp-button, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/jlab_core.b96c356.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1119816 and loc.getEndColumn() >= 1119816
        ) or 
        (   // id=9470, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 3384 and loc.getEndColumn() >= 3384
        ) or 
        (   // id=9471, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11254 and loc.getEndColumn() >= 11254
        ) or 
        (   // id=9473, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/jupyter/jupyter-04-25-12-38/jupyterlite.github.io/8e1af30ba8/source/jupyterlite.github.io/demo/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 94392 and loc.getEndColumn() >= 94392
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

DebuggingConfig() { this = "DOM-Clobbering-jupyterlite.github.io-8e1af30ba8" }
    
    override predicate isSource(DataFlow::Node source) { 
    source instanceof IdentifiedClobberableSource
    }

    // Extended here to include the SocketWriteSink
    override predicate isSink(DataFlow::Node sink) { 
        sink instanceof ClientSideSinks
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
