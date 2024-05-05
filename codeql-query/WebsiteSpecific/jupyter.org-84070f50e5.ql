/**
* @name DOM-Clobbering-jupyter.org-84070f50e5
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
        (   // id=21, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 31173 and loc.getEndColumn() >= 31173
        ) or 
        (   // id=25, type=WIN-TYPE-1, prop=webpackChunk_JUPYTERLAB_CORE_OUTPUT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 59614 and loc.getEndColumn() >= 59614
        ) or 
        (   // id=26, type=WIN-TYPE-1, prop=webpackChunk_JUPYTERLAB_CORE_OUTPUT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 59608 and loc.getEndColumn() >= 59608
        ) or 
        (   // id=57, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.0dca0b46350f0c25c608.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3137 and loc.getEndColumn() >= 3137
        ) or 
        (   // id=60, type=WIN-TYPE-1, prop=webpackChunk_jupyter_notebook_lab_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.0dca0b46350f0c25c608.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8179 and loc.getEndColumn() >= 8179
        ) or 
        (   // id=61, type=WIN-TYPE-1, prop=webpackChunk_jupyter_notebook_lab_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.0dca0b46350f0c25c608.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8173 and loc.getEndColumn() >= 8173
        ) or 
        (   // id=62, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3075 and loc.getEndColumn() >= 3075
        ) or 
        (   // id=66, type=WIN-TYPE-1, prop=webpackChunk_jupyterlab_fasta_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6835 and loc.getEndColumn() >= 6835
        ) or 
        (   // id=67, type=WIN-TYPE-1, prop=webpackChunk_jupyterlab_fasta_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6829 and loc.getEndColumn() >= 6829
        ) or 
        (   // id=68, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3355 and loc.getEndColumn() >= 3355
        ) or 
        (   // id=72, type=WIN-TYPE-1, prop=webpackChunk_jupyterlab_geojson_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7255 and loc.getEndColumn() >= 7255
        ) or 
        (   // id=73, type=WIN-TYPE-1, prop=webpackChunk_jupyterlab_geojson_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7249 and loc.getEndColumn() >= 7249
        ) or 
        (   // id=74, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4522 and loc.getEndColumn() >= 4522
        ) or 
        (   // id=78, type=WIN-TYPE-1, prop=webpackChunk_jupyter_widgets_jupyterlab_manager 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10392 and loc.getEndColumn() >= 10392
        ) or 
        (   // id=79, type=WIN-TYPE-1, prop=webpackChunk_jupyter_widgets_jupyterlab_manager 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10386 and loc.getEndColumn() >= 10386
        ) or 
        (   // id=80, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.badedd5607b5d4e57583.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3540 and loc.getEndColumn() >= 3540
        ) or 
        (   // id=84, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_pyodide_kernel_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.badedd5607b5d4e57583.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7670 and loc.getEndColumn() >= 7670
        ) or 
        (   // id=85, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_pyodide_kernel_extension 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.badedd5607b5d4e57583.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7664 and loc.getEndColumn() >= 7664
        ) or 
        (   // id=86, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3807 and loc.getEndColumn() >= 3807
        ) or 
        (   // id=89, type=WIN-TYPE-1, prop=webpackChunkbqplot 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8308 and loc.getEndColumn() >= 8308
        ) or 
        (   // id=90, type=WIN-TYPE-1, prop=webpackChunkbqplot 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 8302 and loc.getEndColumn() >= 8302
        ) or 
        (   // id=91, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2594 and loc.getEndColumn() >= 2594
        ) or 
        (   // id=94, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_night 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6017 and loc.getEndColumn() >= 6017
        ) or 
        (   // id=95, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_night 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6011 and loc.getEndColumn() >= 6011
        ) or 
        (   // id=96, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/xeus-sqlite-kernel/static/remoteEntry.960d5d0f875a651e597f.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2831 and loc.getEndColumn() >= 2831
        ) or 
        (   // id=100, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_xeus_sqlite_kernel 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/xeus-sqlite-kernel/static/remoteEntry.960d5d0f875a651e597f.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6495 and loc.getEndColumn() >= 6495
        ) or 
        (   // id=101, type=WIN-TYPE-1, prop=webpackChunk_jupyterlite_xeus_sqlite_kernel 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/xeus-sqlite-kernel/static/remoteEntry.960d5d0f875a651e597f.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6489 and loc.getEndColumn() >= 6489
        ) or 
        (   // id=102, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-matplotlib/static/remoteEntry.101bc12d4d5cef8f7eb1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3158 and loc.getEndColumn() >= 3158
        ) or 
        (   // id=105, type=WIN-TYPE-1, prop=webpackChunkjupyter_matplotlib 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-matplotlib/static/remoteEntry.101bc12d4d5cef8f7eb1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6922 and loc.getEndColumn() >= 6922
        ) or 
        (   // id=106, type=WIN-TYPE-1, prop=webpackChunkjupyter_matplotlib 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-matplotlib/static/remoteEntry.101bc12d4d5cef8f7eb1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6916 and loc.getEndColumn() >= 6916
        ) or 
        (   // id=107, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-open-url-parameter/static/remoteEntry.c7a31b7a4c60a21a3aa0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2767 and loc.getEndColumn() >= 2767
        ) or 
        (   // id=110, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_open_url_parameter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-open-url-parameter/static/remoteEntry.c7a31b7a4c60a21a3aa0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6481 and loc.getEndColumn() >= 6481
        ) or 
        (   // id=111, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_open_url_parameter 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-open-url-parameter/static/remoteEntry.c7a31b7a4c60a21a3aa0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6475 and loc.getEndColumn() >= 6475
        ) or 
        (   // id=112, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2990 and loc.getEndColumn() >= 2990
        ) or 
        (   // id=115, type=WIN-TYPE-1, prop=webpackChunkipycanvas 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6694 and loc.getEndColumn() >= 6694
        ) or 
        (   // id=116, type=WIN-TYPE-1, prop=webpackChunkipycanvas 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6688 and loc.getEndColumn() >= 6688
        ) or 
        (   // id=117, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5487 and loc.getEndColumn() >= 5487
        ) or 
        (   // id=121, type=WIN-TYPE-1, prop=webpackChunkjupyter_leaflet 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11783 and loc.getEndColumn() >= 11783
        ) or 
        (   // id=122, type=WIN-TYPE-1, prop=webpackChunkjupyter_leaflet 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11777 and loc.getEndColumn() >= 11777
        ) or 
        (   // id=123, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-plotly/static/remoteEntry.c764a537ae4fed4fb4ca.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3725 and loc.getEndColumn() >= 3725
        ) or 
        (   // id=126, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_plotly 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-plotly/static/remoteEntry.c764a537ae4fed4fb4ca.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7507 and loc.getEndColumn() >= 7507
        ) or 
        (   // id=127, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_plotly 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-plotly/static/remoteEntry.c764a537ae4fed4fb4ca.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7501 and loc.getEndColumn() >= 7501
        ) or 
        (   // id=128, type=WIN-TYPE-1, prop=importScripts 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2709 and loc.getEndColumn() >= 2709
        ) or 
        (   // id=131, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_pygments 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3724 and loc.getEndColumn() >= 3724
        ) or 
        (   // id=132, type=WIN-TYPE-1, prop=webpackChunkjupyterlab_pygments 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3718 and loc.getEndColumn() >= 3718
        ) or 
        (   // id=194, type=WIN-TYPE-1, prop=__REACT_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 129088 and loc.getEndColumn() >= 129088
        ) or 
        (   // id=195, type=WIN-TYPE-1, prop=setImmediate 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 130173 and loc.getEndColumn() >= 130173
        ) or 
        (   // id=197, type=WIN-TYPE-1, prop=MSApp 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 13254 and loc.getEndColumn() >= 13254
        ) or 
        (   // id=200, type=WIN-TYPE-1, prop=__REACT_DEVTOOLS_GLOBAL_HOOK__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 126767 and loc.getEndColumn() >= 126767
        ) or 
        (   // id=507, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/4746.de61e2b.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5661 and loc.getEndColumn() >= 5661
        ) or 
        (   // id=508, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/4746.de61e2b.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 10233 and loc.getEndColumn() >= 10233
        ) or 
        (   // id=509, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/4746.de61e2b.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7970 and loc.getEndColumn() >= 7970
        ) or 
        (   // id=510, type=WIN-TYPE-1, prop=exports 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/9854.2f2d782.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 5327 and loc.getEndColumn() >= 5327
        ) or 
        (   // id=511, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/5125.d4c32d9.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 70096 and loc.getEndColumn() >= 70096
        ) or 
        (   // id=512, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/5125.d4c32d9.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 85078 and loc.getEndColumn() >= 85078
        ) or 
        (   // id=513, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/5125.d4c32d9.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 80278 and loc.getEndColumn() >= 80278
        ) or 
        (   // id=514, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/5125.d4c32d9.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 68400 and loc.getEndColumn() >= 68400
        ) or 
        (   // id=515, type=WIN-TYPE-1, prop=__g 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 378 and loc.getEndColumn() >= 378
        ) or 
        (   // id=516, type=WIN-TYPE-1, prop=__e 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 462 and loc.getEndColumn() >= 462
        ) or 
        (   // id=518, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1762 and loc.getEndColumn() >= 1762
        ) or 
        (   // id=519, type=WIN-TYPE-1, prop=__core-js_shared__ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1772 and loc.getEndColumn() >= 1772
        ) or 
        (   // id=520, type=WIN-TYPE-1, prop=core 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/850.16f7c82.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3159 and loc.getEndColumn() >= 3159
        ) or 
        (   // id=528, type=WIN-TYPE-1, prop=__ $YJS$ __ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/9643.f61adcb.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 82210 and loc.getEndColumn() >= 82210
        ) or 
        (   // id=529, type=WIN-TYPE-1, prop=__ $YJS$ __ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/9643.f61adcb.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 82361 and loc.getEndColumn() >= 82361
        ) or 
        (   // id=721, type=WIN-TYPE-1, prop=openDatabase 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/927.399dde7.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 9712 and loc.getEndColumn() >= 9712
        ) or 
        (   // id=722, type=WIN-TYPE-1, prop=openDatabase 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/927.399dde7.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 18446 and loc.getEndColumn() >= 18446
        ) or 
        (   // id=732, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/4324.992bd2c.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1158 and loc.getEndColumn() >= 1158
        ) or 
        (   // id=733, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/4324.992bd2c.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1661 and loc.getEndColumn() >= 1661
        ) or 
        (   // id=734, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/644.52a1098a3a5f3e45abff.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 37207 and loc.getEndColumn() >= 37207
        ) or 
        (   // id=735, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/644.52a1098a3a5f3e45abff.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 35299 and loc.getEndColumn() >= 35299
        ) or 
        (   // id=792, type=WIN-TYPE-1, prop=jQuery 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 86949 and loc.getEndColumn() >= 86949
        ) or 
        (   // id=793, type=WIN-TYPE-1, prop=$ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 86961 and loc.getEndColumn() >= 86961
        ) or 
        (   // id=794, type=WIN-TYPE-1, prop=Backbone 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/644.52a1098a3a5f3e45abff.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 321 and loc.getEndColumn() >= 321
        ) or 
        (   // id=795, type=WIN-TYPE-1, prop=Backbone 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/644.52a1098a3a5f3e45abff.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 294 and loc.getEndColumn() >= 294
        ) or 
        (   // id=824, type=WIN-TYPE-1, prop=ActiveXObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 15615 and loc.getEndColumn() >= 15615
        ) or 
        (   // id=825, type=WIN-TYPE-1, prop=opera 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 15917 and loc.getEndColumn() >= 15917
        ) or 
        (   // id=826, type=WIN-TYPE-1, prop=L_DISABLE_3D 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16202 and loc.getEndColumn() >= 16202
        ) or 
        (   // id=827, type=WIN-TYPE-1, prop=orientation 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16242 and loc.getEndColumn() >= 16242
        ) or 
        (   // id=828, type=WIN-TYPE-1, prop=ontouchstart 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16404 and loc.getEndColumn() >= 16404
        ) or 
        (   // id=829, type=WIN-TYPE-1, prop=L_NO_TOUCH 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 16446 and loc.getEndColumn() >= 16446
        ) or 
        (   // id=837, type=WIN-TYPE-1, prop=L 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 148785 and loc.getEndColumn() >= 148785
        ) or 
        (   // id=838, type=WIN-TYPE-1, prop=L 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 148844 and loc.getEndColumn() >= 148844
        ) or 
        (   // id=846, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 386456 and loc.getEndColumn() >= 386456
        ) or 
        (   // id=847, type=WIN-TYPE-1, prop=_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 391638 and loc.getEndColumn() >= 391638
        ) or 
        (   // id=848, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 391768 and loc.getEndColumn() >= 391768
        ) or 
        (   // id=849, type=WIN-TYPE-1, prop=_ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 452310 and loc.getEndColumn() >= 452310
        ) or 
        (   // id=851, type=WIN-TYPE-1, prop=$ 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 372077 and loc.getEndColumn() >= 372077
        ) or 
        (   // id=852, type=WIN-TYPE-1, prop=jBone 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 372083 and loc.getEndColumn() >= 372083
        ) or 
        (   // id=853, type=WIN-TYPE-1, prop=C2S 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 173917 and loc.getEndColumn() >= 173917
        ) or 
        (   // id=854, type=WIN-TYPE-1, prop=IO_VERSION 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 127130 and loc.getEndColumn() >= 127130
        ) or 
        (   // id=856, type=WIN-TYPE-1, prop=BlobBuilder 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153178 and loc.getEndColumn() >= 153178
        ) or 
        (   // id=857, type=WIN-TYPE-1, prop=WebKitBlobBuilder 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153198 and loc.getEndColumn() >= 153198
        ) or 
        (   // id=858, type=WIN-TYPE-1, prop=MozBlobBuilder 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153224 and loc.getEndColumn() >= 153224
        ) or 
        (   // id=859, type=WIN-TYPE-1, prop=MSBlobBuilder 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 153247 and loc.getEndColumn() >= 153247
        ) or 
        (   // id=861, type=WIN-TYPE-1, prop=externalHost 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 154263 and loc.getEndColumn() >= 154263
        ) or 
        (   // id=862, type=WIN-TYPE-1, prop=requestFileSystem 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 154324 and loc.getEndColumn() >= 154324
        ) or 
        (   // id=863, type=WIN-TYPE-1, prop=define 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 156554 and loc.getEndColumn() >= 156554
        ) or 
        (   // id=864, type=WIN-TYPE-1, prop=almond 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 156589 and loc.getEndColumn() >= 156589
        ) or 
        (   // id=865, type=WIN-TYPE-1, prop=MSA_VERSION 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/410.a7e6b5eae966dbeb7f67.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 14546 and loc.getEndColumn() >= 14546
        ) or 
        (   // id=866, type=WIN-TYPE-1, prop=TYPED_ARRAY_SUPPORT 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/ipycanvas/static/764.dc7b08f6512a8a28ecfe.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 7664 and loc.getEndColumn() >= 7664
        ) or 
        (   // id=871, type=WIN-TYPE-1, prop=MSInputMethodContext 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/981.3f93685e278b785a3338.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 1138 and loc.getEndColumn() >= 1138
        ) or 
        (   // id=872, type=WIN-TYPE-1, prop=PopperUtils 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/981.3f93685e278b785a3338.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 20751 and loc.getEndColumn() >= 20751
        ) or 
        (   // id=885, type=WIN-TYPE-1, prop=Buffer 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/961.cf93e7085b1c412600d8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 23611 and loc.getEndColumn() >= 23611
        ) or 
        (   // id=886, type=WIN-TYPE-1, prop=process 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/961.cf93e7085b1c412600d8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 24703 and loc.getEndColumn() >= 24703
        ) or 
        (   // id=889, type=WIN-TYPE-1, prop=QObject 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 33440 and loc.getEndColumn() >= 33440
        ) or 
        (   // id=890, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4067 and loc.getEndColumn() >= 4067
        ) or 
        (   // id=891, type=WIN-TYPE-1, prop=regeneratorRuntime 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4199 and loc.getEndColumn() >= 4199
        ) or 
        (   // id=892, type=WIN-TYPE-1, prop=DEBUG 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 16546 and loc.getEndColumn() >= 16546
        ) or 
        (   // id=8942, type=WIN-TYPE-1, prop=nodeName 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 40860 and loc.getEndColumn() >= 40860
        ) or 
        (   // id=8943, type=WIN-TYPE-1, prop=nodeName 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 29994 and loc.getEndColumn() >= 29994
        ) or 
        (   // id=8944, type=WIN-TYPE-1, prop=nodeName 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 40988 and loc.getEndColumn() >= 40988
        ) or 
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
        (   // id=198, type=DOC-TYPE-1, prop=documentMode 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 30531 and loc.getEndColumn() >= 30531
        ) or 
        (   // id=743, type=DOC-TYPE-1, prop=namespaceURI 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 3669 and loc.getEndColumn() >= 3669
        ) or 
        (   // id=836, type=DOC-TYPE-1, prop=namespaces 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 129052 and loc.getEndColumn() >= 129052
        ) or 
        (   // id=1984, type=DOC-TYPE-1, prop=_reactListening66yoogzwzpq 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 37773 and loc.getEndColumn() >= 37773
        ) or 
        (   // id=8667, type=DOC-TYPE-1, prop=__reactContainer$okzfnimkcpd 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 45028 and loc.getEndColumn() >= 45028
        ) or 
        (   // id=8668, type=DOC-TYPE-1, prop=__reactFiber$okzfnimkcpd 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 45035 and loc.getEndColumn() >= 45035
        ) or 
        (   // id=8945, type=DOC-TYPE-1, prop=window 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 33414 and loc.getEndColumn() >= 33414
        ) or 
        (   // id=9267, type=DOC-TYPE-1, prop=scrollTop 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3783 and loc.getEndColumn() >= 3783
        ) or 
        (   // id=9268, type=DOC-TYPE-1, prop=scrollLeft 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3795 and loc.getEndColumn() >= 3795
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
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/config-utils.js") and
            loc.getStartLine() = 242 and loc.getEndLine() = 242 and
            loc.getStartColumn() <= 11 and loc.getEndColumn() >= 11
        ) or 
        (   // id=20, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/config-utils.js") and
            loc.getStartLine() = 261 and loc.getEndLine() = 261 and
            loc.getStartColumn() <= 11 and loc.getEndColumn() >= 11
        ) or 
        (   // id=22, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 31239 and loc.getEndColumn() >= 31239
        ) or 
        (   // id=23, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 31259 and loc.getEndColumn() >= 31259
        ) or 
        (   // id=30, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 600 and loc.getEndColumn() >= 600
        ) or 
        (   // id=58, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.0dca0b46350f0c25c608.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3203 and loc.getEndColumn() >= 3203
        ) or 
        (   // id=59, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.0dca0b46350f0c25c608.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3223 and loc.getEndColumn() >= 3223
        ) or 
        (   // id=63, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3141 and loc.getEndColumn() >= 3141
        ) or 
        (   // id=64, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3161 and loc.getEndColumn() >= 3161
        ) or 
        (   // id=69, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3421 and loc.getEndColumn() >= 3421
        ) or 
        (   // id=70, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3441 and loc.getEndColumn() >= 3441
        ) or 
        (   // id=75, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4588 and loc.getEndColumn() >= 4588
        ) or 
        (   // id=76, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4608 and loc.getEndColumn() >= 4608
        ) or 
        (   // id=81, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.badedd5607b5d4e57583.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3606 and loc.getEndColumn() >= 3606
        ) or 
        (   // id=82, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.badedd5607b5d4e57583.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3626 and loc.getEndColumn() >= 3626
        ) or 
        (   // id=87, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3873 and loc.getEndColumn() >= 3873
        ) or 
        (   // id=88, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3893 and loc.getEndColumn() >= 3893
        ) or 
        (   // id=92, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2660 and loc.getEndColumn() >= 2660
        ) or 
        (   // id=93, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2680 and loc.getEndColumn() >= 2680
        ) or 
        (   // id=97, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/xeus-sqlite-kernel/static/remoteEntry.960d5d0f875a651e597f.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2897 and loc.getEndColumn() >= 2897
        ) or 
        (   // id=98, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/xeus-sqlite-kernel/static/remoteEntry.960d5d0f875a651e597f.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2917 and loc.getEndColumn() >= 2917
        ) or 
        (   // id=103, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-matplotlib/static/remoteEntry.101bc12d4d5cef8f7eb1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3224 and loc.getEndColumn() >= 3224
        ) or 
        (   // id=104, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-matplotlib/static/remoteEntry.101bc12d4d5cef8f7eb1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3244 and loc.getEndColumn() >= 3244
        ) or 
        (   // id=108, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-open-url-parameter/static/remoteEntry.c7a31b7a4c60a21a3aa0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2833 and loc.getEndColumn() >= 2833
        ) or 
        (   // id=109, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-open-url-parameter/static/remoteEntry.c7a31b7a4c60a21a3aa0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2853 and loc.getEndColumn() >= 2853
        ) or 
        (   // id=113, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3056 and loc.getEndColumn() >= 3056
        ) or 
        (   // id=114, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3076 and loc.getEndColumn() >= 3076
        ) or 
        (   // id=118, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5553 and loc.getEndColumn() >= 5553
        ) or 
        (   // id=119, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5573 and loc.getEndColumn() >= 5573
        ) or 
        (   // id=124, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-plotly/static/remoteEntry.c764a537ae4fed4fb4ca.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3791 and loc.getEndColumn() >= 3791
        ) or 
        (   // id=125, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-plotly/static/remoteEntry.c764a537ae4fed4fb4ca.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3811 and loc.getEndColumn() >= 3811
        ) or 
        (   // id=129, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2775 and loc.getEndColumn() >= 2775
        ) or 
        (   // id=130, type=DOC-TYPE-2, prop=currentScript 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2795 and loc.getEndColumn() >= 2795
        ) or 
        (   // id=136, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7978 and loc.getEndColumn() >= 7978
        ) or 
        (   // id=182, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.0dca0b46350f0c25c608.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2309 and loc.getEndColumn() >= 2309
        ) or 
        (   // id=190, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 401152 and loc.getEndColumn() >= 401152
        ) or 
        (   // id=191, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 401183 and loc.getEndColumn() >= 401183
        ) or 
        (   // id=603, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3105 and loc.getEndColumn() >= 3105
        ) or 
        (   // id=617, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2244 and loc.getEndColumn() >= 2244
        ) or 
        (   // id=633, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 3418 and loc.getEndColumn() >= 3418
        ) or 
        (   // id=637, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2609 and loc.getEndColumn() >= 2609
        ) or 
        (   // id=645, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.badedd5607b5d4e57583.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2700 and loc.getEndColumn() >= 2700
        ) or 
        (   // id=649, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/xeus-sqlite-kernel/static/remoteEntry.960d5d0f875a651e597f.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2149 and loc.getEndColumn() >= 2149
        ) or 
        (   // id=653, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2655 and loc.getEndColumn() >= 2655
        ) or 
        (   // id=666, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2250 and loc.getEndColumn() >= 2250
        ) or 
        (   // id=693, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-matplotlib/static/remoteEntry.101bc12d4d5cef8f7eb1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2346 and loc.getEndColumn() >= 2346
        ) or 
        (   // id=697, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1942 and loc.getEndColumn() >= 1942
        ) or 
        (   // id=701, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-open-url-parameter/static/remoteEntry.c7a31b7a4c60a21a3aa0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2089 and loc.getEndColumn() >= 2089
        ) or 
        (   // id=709, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-plotly/static/remoteEntry.c764a537ae4fed4fb4ca.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2906 and loc.getEndColumn() >= 2906
        ) or 
        (   // id=714, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2051 and loc.getEndColumn() >= 2051
        ) or 
        (   // id=728, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11419 and loc.getEndColumn() >= 11419
        ) or 
        (   // id=729, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 11964 and loc.getEndColumn() >= 11964
        ) or 
        (   // id=730, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 140845 and loc.getEndColumn() >= 140845
        ) or 
        (   // id=731, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 140866 and loc.getEndColumn() >= 140866
        ) or 
        (   // id=741, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8543 and loc.getEndColumn() >= 8543
        ) or 
        (   // id=742, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8568 and loc.getEndColumn() >= 8568
        ) or 
        (   // id=745, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 3708 and loc.getEndColumn() >= 3708
        ) or 
        (   // id=778, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 33241 and loc.getEndColumn() >= 33241
        ) or 
        (   // id=791, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 82107 and loc.getEndColumn() >= 82107
        ) or 
        (   // id=823, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 15575 and loc.getEndColumn() >= 15575
        ) or 
        (   // id=834, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/243.45f065b556905df86ca2.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 20616 and loc.getEndColumn() >= 20616
        ) or 
        (   // id=869, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/815.4fcd9a1489787115f930.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6624 and loc.getEndColumn() >= 6624
        ) or 
        (   // id=887, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 36695 and loc.getEndColumn() >= 36695
        ) or 
        (   // id=894, type=DOC-TYPE-2, prop=all 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13192 and loc.getEndColumn() >= 13192
        ) or 
        (   // id=991, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 138864 and loc.getEndColumn() >= 138864
        ) or 
        (   // id=998, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1245343 and loc.getEndColumn() >= 1245343
        ) or 
        (   // id=2145, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10077 and loc.getEndColumn() >= 10077
        ) or 
        (   // id=2682, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1568588 and loc.getEndColumn() >= 1568588
        ) or 
        (   // id=3569, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1243653 and loc.getEndColumn() >= 1243653
        ) or 
        (   // id=4410, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 801934 and loc.getEndColumn() >= 801934
        ) or 
        (   // id=4413, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 828786 and loc.getEndColumn() >= 828786
        ) or 
        (   // id=6428, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1404909 and loc.getEndColumn() >= 1404909
        ) or 
        (   // id=6962, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 140273 and loc.getEndColumn() >= 140273
        ) or 
        (   // id=7522, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1355497 and loc.getEndColumn() >= 1355497
        ) or 
        (   // id=7543, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 150587 and loc.getEndColumn() >= 150587
        ) or 
        (   // id=7544, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 95100 and loc.getEndColumn() >= 95100
        ) or 
        (   // id=7546, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 185491 and loc.getEndColumn() >= 185491
        ) or 
        (   // id=7577, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 83521 and loc.getEndColumn() >= 83521
        ) or 
        (   // id=7578, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 83577 and loc.getEndColumn() >= 83577
        ) or 
        (   // id=7579, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 83613 and loc.getEndColumn() >= 83613
        ) or 
        (   // id=7580, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 83686 and loc.getEndColumn() >= 83686
        ) or 
        (   // id=8532, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 116306 and loc.getEndColumn() >= 116306
        ) or 
        (   // id=8557, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 109954 and loc.getEndColumn() >= 109954
        ) or 
        (   // id=8612, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 404057 and loc.getEndColumn() >= 404057
        ) or 
        (   // id=8614, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 403790 and loc.getEndColumn() >= 403790
        ) or 
        (   // id=8654, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1881.caa26c6.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 76676 and loc.getEndColumn() >= 76676
        ) or 
        (   // id=8666, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 95296 and loc.getEndColumn() >= 95296
        ) or 
        (   // id=8795, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 284118 and loc.getEndColumn() >= 284118
        ) or 
        (   // id=8814, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 125279 and loc.getEndColumn() >= 125279
        ) or 
        (   // id=8819, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/4434.547c185.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1357 and loc.getEndColumn() >= 1357
        ) or 
        (   // id=8821, type=DOC-TYPE-2, prop=head 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/4434.547c185.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1646 and loc.getEndColumn() >= 1646
        ) or 
        (   // id=8840, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 40823 and loc.getEndColumn() >= 40823
        ) or 
        (   // id=8872, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 346323 and loc.getEndColumn() >= 346323
        ) or 
        (   // id=8873, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 346518 and loc.getEndColumn() >= 346518
        ) or 
        (   // id=8875, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 358318 and loc.getEndColumn() >= 358318
        ) or 
        (   // id=8876, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 358388 and loc.getEndColumn() >= 358388
        ) or 
        (   // id=8877, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 364778 and loc.getEndColumn() >= 364778
        ) or 
        (   // id=8885, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 82381 and loc.getEndColumn() >= 82381
        ) or 
        (   // id=8914, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 147130 and loc.getEndColumn() >= 147130
        ) or 
        (   // id=9148, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1515472 and loc.getEndColumn() >= 1515472
        ) or 
        (   // id=9149, type=DOC-TYPE-2, prop=documentElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1515522 and loc.getEndColumn() >= 1515522
        ) or 
        (   // id=9154, type=DOC-TYPE-2, prop=body 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1516590 and loc.getEndColumn() >= 1516590
        ) or 
        (   // id=9256, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 148297 and loc.getEndColumn() >= 148297
        ) or 
        (   // id=9477, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 107638 and loc.getEndColumn() >= 107638
        ) or 
        (   // id=9912, type=DOC-TYPE-2, prop=activeElement 
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/2955.c8d0773.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 42619 and loc.getEndColumn() >= 42619
        ) or )
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
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=4, type=DOM-API, prop=iframe, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7, type=DOM-API, prop=___gatsby, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=8, type=DOM-API, prop=react-root, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=10, type=DOM-API, prop=jupyter-config-data, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/config-utils.js") and
            loc.getStartLine() = 60 and loc.getEndLine() = 60 and
            loc.getStartColumn() <= 32 and loc.getEndColumn() >= 32
        ) or 
        (   // id=12, type=DOM-API, prop=jupyter-config-data, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/config-utils.js") and
            loc.getStartLine() = 181 and loc.getEndLine() = 181 and
            loc.getStartColumn() <= 18 and loc.getEndColumn() >= 18
        ) or 
        (   // id=18, type=DOM-API, prop=jupyter-lite-main, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/config-utils.js") and
            loc.getStartLine() = 257 and loc.getEndLine() = 257 and
            loc.getStartColumn() <= 30 and loc.getEndColumn() >= 30
        ) or 
        (   // id=28, type=DOM-API, prop=jupyter-config-data, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 195 and loc.getEndColumn() >= 195
        ) or 
        (   // id=134, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/lab/bundle.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7374 and loc.getEndColumn() >= 7374
        ) or 
        (   // id=180, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-notebook/lab-extension/static/remoteEntry.0dca0b46350f0c25c608.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1705 and loc.getEndColumn() >= 1705
        ) or 
        (   // id=189, type=DOM-API, prop=jupyter-config-data, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 398395 and loc.getEndColumn() >= 398395
        ) or 
        (   // id=202, type=DOM-API, prop=[data-icon-id="undefined"], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1263679 and loc.getEndColumn() >= 1263679
        ) or 
        (   // id=203, type=DOM-API, prop=[data-icon-id="undefined"], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1263679 and loc.getEndColumn() >= 1263679
        ) or 
        (   // id=568, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/9903.633a36a.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 242755 and loc.getEndColumn() >= 242755
        ) or 
        (   // id=601, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/remoteEntry.9f387e5e108e458f62c3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2501 and loc.getEndColumn() >= 2501
        ) or 
        (   // id=615, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/remoteEntry.b15a25cb741a6c7381f8.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1640 and loc.getEndColumn() >= 1640
        ) or 
        (   // id=631, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/remoteEntry.5e71a5e8dcb6330c0085.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2814 and loc.getEndColumn() >= 2814
        ) or 
        (   // id=635, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/geojson-extension/static/remoteEntry.6a76d3e37f02d3977b44.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2005 and loc.getEndColumn() >= 2005
        ) or 
        (   // id=643, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/pyodide-kernel-extension/static/remoteEntry.badedd5607b5d4e57583.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2096 and loc.getEndColumn() >= 2096
        ) or 
        (   // id=647, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlite/xeus-sqlite-kernel/static/remoteEntry.960d5d0f875a651e597f.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1545 and loc.getEndColumn() >= 1545
        ) or 
        (   // id=651, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/remoteEntry.a36d13f475360b3d8988.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2051 and loc.getEndColumn() >= 2051
        ) or 
        (   // id=664, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/ipycanvas/static/remoteEntry.9693baf6fc7fc4c880d2.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1646 and loc.getEndColumn() >= 1646
        ) or 
        (   // id=691, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-matplotlib/static/remoteEntry.101bc12d4d5cef8f7eb1.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1742 and loc.getEndColumn() >= 1742
        ) or 
        (   // id=695, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-night/static/remoteEntry.6a37df5d4590b29196a3.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1338 and loc.getEndColumn() >= 1338
        ) or 
        (   // id=699, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-open-url-parameter/static/remoteEntry.c7a31b7a4c60a21a3aa0.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1485 and loc.getEndColumn() >= 1485
        ) or 
        (   // id=707, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-plotly/static/remoteEntry.c764a537ae4fed4fb4ca.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2302 and loc.getEndColumn() >= 2302
        ) or 
        (   // id=712, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab_pygments/static/remoteEntry.5cbb9d2323598fbda535.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1447 and loc.getEndColumn() >= 1447
        ) or 
        (   // id=725, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-notebook/lab-extension/static/93.eddcbb0f5a946c74796b.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2860 and loc.getEndColumn() >= 2860
        ) or 
        (   // id=749, type=DOM-API, prop=jQuery3700917834450061954, api=getElementsByName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8815 and loc.getEndColumn() >= 8815
        ) or 
        (   // id=753, type=DOM-API, prop=:scope, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8946 and loc.getEndColumn() >= 8946
        ) or 
        (   // id=754, type=DOM-API, prop=:scope, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 8946 and loc.getEndColumn() >= 8946
        ) or 
        (   // id=757, type=DOM-API, prop=:has(*,:jqfake), api=querySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 9013 and loc.getEndColumn() >= 9013
        ) or 
        (   // id=759, type=DOM-API, prop=[selected], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10094 and loc.getEndColumn() >= 10094
        ) or 
        (   // id=760, type=DOM-API, prop=[selected], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10094 and loc.getEndColumn() >= 10094
        ) or 
        (   // id=761, type=DOM-API, prop=[id~=jQuery3700917834450061954-], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10170 and loc.getEndColumn() >= 10170
        ) or 
        (   // id=762, type=DOM-API, prop=[id~=jQuery3700917834450061954-], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10170 and loc.getEndColumn() >= 10170
        ) or 
        (   // id=763, type=DOM-API, prop=jQuery3700917834450061954, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10226 and loc.getEndColumn() >= 10226
        ) or 
        (   // id=764, type=DOM-API, prop=a#jQuery3700917834450061954+*, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10226 and loc.getEndColumn() >= 10226
        ) or 
        (   // id=765, type=DOM-API, prop=a#jQuery3700917834450061954+*, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10226 and loc.getEndColumn() >= 10226
        ) or 
        (   // id=766, type=DOM-API, prop=:checked, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10285 and loc.getEndColumn() >= 10285
        ) or 
        (   // id=767, type=DOM-API, prop=:checked, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10285 and loc.getEndColumn() >= 10285
        ) or 
        (   // id=769, type=DOM-API, prop=:disabled, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10477 and loc.getEndColumn() >= 10477
        ) or 
        (   // id=770, type=DOM-API, prop=:disabled, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10477 and loc.getEndColumn() >= 10477
        ) or 
        (   // id=772, type=DOM-API, prop=[name=''], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10618 and loc.getEndColumn() >= 10618
        ) or 
        (   // id=773, type=DOM-API, prop=[name=''], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/291.cff5ef71b29e18850479.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 10618 and loc.getEndColumn() >= 10618
        ) or 
        (   // id=798, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyter-widgets/jupyterlab-manager/static/134.fe2572ece3b7955c89bb.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 69790 and loc.getEndColumn() >= 69790
        ) or 
        (   // id=814, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/geojson-extension/static/643.bdb928a9116846bf6939.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 19642 and loc.getEndColumn() >= 19642
        ) or 
        (   // id=841, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/@jupyterlab/fasta-extension/static/643.929c653e8b3ed3e6bb69.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 7402 and loc.getEndColumn() >= 7402
        ) or 
        (   // id=875, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/bqplot/static/133.184b7ff4eeea6053c218.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13116 and loc.getEndColumn() >= 13116
        ) or 
        (   // id=880, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/665.5238b4be159a24e206a7.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 5988 and loc.getEndColumn() >= 5988
        ) or 
        (   // id=893, type=DOM-API, prop=Non-Undefined, api=all
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13193 and loc.getEndColumn() >= 13193
        ) or 
        (   // id=897, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyter-leaflet/static/874.5a1aed3c32b82a312609.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 13428 and loc.getEndColumn() >= 13428
        ) or 
        (   // id=916, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-open-url-parameter/static/747.81bc8c282a9a99aa0a8f.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 2293 and loc.getEndColumn() >= 2293
        ) or 
        (   // id=921, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab-plotly/static/423.d0d3e2912c33c7566484.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 4759 and loc.getEndColumn() >= 4759
        ) or 
        (   // id=930, type=DOM-API, prop=head, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/extensions/jupyterlab_pygments/static/747.67662283a5707eeb4d4c.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 6606 and loc.getEndColumn() >= 6606
        ) or 
        (   // id=962, type=DOM-API, prop=lm-TabBar-content, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1524039 and loc.getEndColumn() >= 1524039
        ) or 
        (   // id=996, type=DOM-API, prop=parsererror, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1261220 and loc.getEndColumn() >= 1261220
        ) or 
        (   // id=1010, type=DOM-API, prop=jp-SearchIconGroup, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 140719 and loc.getEndColumn() >= 140719
        ) or 
        (   // id=1011, type=DOM-API, prop=lm-CommandPalette-input, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1496638 and loc.getEndColumn() >= 1496638
        ) or 
        (   // id=1017, type=DOM-API, prop=lm-close-icon, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1497365 and loc.getEndColumn() >= 1497365
        ) or 
        (   // id=1021, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 79504 and loc.getEndColumn() >= 79504
        ) or 
        (   // id=1038, type=DOM-API, prop=lm-CommandPalette-content, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1496726 and loc.getEndColumn() >= 1496726
        ) or 
        (   // id=1227, type=DOM-API, prop=li[tabindex="0"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1526461 and loc.getEndColumn() >= 1526461
        ) or 
        (   // id=1232, type=DOM-API, prop=body, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1242, type=DOM-API, prop=.jp-Activity, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1256, type=DOM-API, prop=.jp-CodeConsole-promptCell .jp-mod-completer-enabled, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1260, type=DOM-API, prop=.jp-FileEditor .jp-mod-completer-enabled, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1264, type=DOM-API, prop=.jp-Notebook.jp-mod-editMode .jp-mod-completer-enabled, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1268, type=DOM-API, prop=.jp-CodeConsole[data-jp-interaction-mode='notebook'] .jp-CodeConsole-promptCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1272, type=DOM-API, prop=.jp-CodeConsole[data-jp-interaction-mode='terminal'] .jp-CodeConsole-promptCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1282, type=DOM-API, prop=.jp-mod-searchable, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1292, type=DOM-API, prop=.jp-DirListing-content .jp-DirListing-itemText, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1302, type=DOM-API, prop=.jp-DirListing:focus, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1312, type=DOM-API, prop=.jp-ImageViewer, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1330, type=DOM-API, prop=body[data-jp-inspector='open'], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1338, type=DOM-API, prop=.jp-Notebook:focus, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1358, type=DOM-API, prop=.jp-Notebook.jp-mod-commandMode, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1368, type=DOM-API, prop=.jp-Notebook.jp-mod-editMode, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1408, type=DOM-API, prop=[data-jp-traversable]:focus, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1414, type=DOM-API, prop=.jp-Notebook:focus.jp-mod-commandMode, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1452, type=DOM-API, prop=.jp-SettingEditor, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1458, type=DOM-API, prop=body.jp-mod-tooltip .jp-CodeConsole-promptCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1462, type=DOM-API, prop=body.jp-mod-tooltip .jp-Notebook, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1466, type=DOM-API, prop=.jp-CodeConsole-promptCell .jp-InputArea-editor:not(.jp-mod-has-primary-selection):not(.jp-mod-in-leading-whitespace), api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1470, type=DOM-API, prop=.jp-FileEditor .jp-CodeMirrorEditor:not(.jp-mod-has-primary-selection):not(.jp-mod-in-leading-whitespace), api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1474, type=DOM-API, prop=.jp-Notebook.jp-mod-editMode .jp-InputArea-editor:not(.jp-mod-has-primary-selection):not(.jp-mod-in-leading-whitespace):not(.jp-mod-completer-active), api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1478, type=DOM-API, prop=.jp-Notebook.jp-mod-commandMode :focus:not(:read-write), api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=1989, type=DOM-API, prop=lm-Menu-content, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1507030 and loc.getEndColumn() >= 1507030
        ) or 
        (   // id=2005, type=DOM-API, prop=lm-MenuBar-content, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1577348 and loc.getEndColumn() >= 1577348
        ) or 
        (   // id=2401, type=DOM-API, prop=[data-jp-undoer], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=2445, type=DOM-API, prop=[data-jp-kernel-user]:focus, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=2553, type=DOM-API, prop=[data-jp-code-runner], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=2664, type=DOM-API, prop=.jp-DirListing-header, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 141558 and loc.getEndColumn() >= 141558
        ) or 
        (   // id=2678, type=DOM-API, prop=.jp-DirListing-headerItemIcon, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 141558 and loc.getEndColumn() >= 141558
        ) or 
        (   // id=4412, type=DOM-API, prop=jp-NotebookExtension-sideBySideMargins, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 828744 and loc.getEndColumn() >= 828744
        ) or 
        (   // id=4493, type=DOM-API, prop=.jp-OutputArea-child, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=4499, type=DOM-API, prop=.jp-Notebook .jp-mod-completer-active, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=4517, type=DOM-API, prop=file-upload-button, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 591381 and loc.getEndColumn() >= 591381
        ) or 
        (   // id=4526, type=DOM-API, prop=.jp-ConsolePanel .jp-mod-completer-active, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=5082, type=DOM-API, prop=.jp-FileEditor .jp-mod-completer-active, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6429, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1467657 and loc.getEndColumn() >= 1467657
        ) or 
        (   // id=6430, type=DOM-API, prop=.jp-DirListing-content, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 141558 and loc.getEndColumn() >= 141558
        ) or 
        (   // id=6442, type=DOM-API, prop=.jp-RunningSessions-item.jp-mod-kernel, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6444, type=DOM-API, prop=.jp-Notebook .jp-Cell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6446, type=DOM-API, prop=.jp-DirListing-content, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6448, type=DOM-API, prop=.jp-FileEditor, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6450, type=DOM-API, prop=.jp-DirListing-item[data-isdir], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6452, type=DOM-API, prop=.jp-DirListing-item[data-isdir="false"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6454, type=DOM-API, prop=#jp-main-dock-panel .lm-DockPanel-tabBar .lm-TabBar-tab, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6456, type=DOM-API, prop=.jp-CodeConsole-promptCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6458, type=DOM-API, prop=[data-type="document-title"].jp-mod-current, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6460, type=DOM-API, prop=.jp-Notebook .jp-CodeCell, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6462, type=DOM-API, prop=.jp-CodeConsole-content, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6464, type=DOM-API, prop=.jp-DirListing-item[data-isdir="false"].jp-mod-running, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6466, type=DOM-API, prop=.MathJax, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6468, type=DOM-API, prop=.jp-Notebook, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6470, type=DOM-API, prop=.jp-DirListing-header, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6472, type=DOM-API, prop=[data-type="document-title"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6474, type=DOM-API, prop=.jp-CodeConsole, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6476, type=DOM-API, prop=.jp-SideBar .lm-TabBar-tab, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6478, type=DOM-API, prop=.jp-TableOfContents-content[data-document-type="notebook"] .jp-tocItem, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=6480, type=DOM-API, prop=.jp-RenderedMarkdown, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1421619 and loc.getEndColumn() >= 1421619
        ) or 
        (   // id=7519, type=DOM-API, prop=button, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1035654 and loc.getEndColumn() >= 1035654
        ) or 
        (   // id=7530, type=DOM-API, prop=lm-TabBar-addButton, api=getElementsByClassName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1524123 and loc.getEndColumn() >= 1524123
        ) or 
        (   // id=7551, type=DOM-API, prop=label, api=getElementsByTagNameNS
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=7562, type=DOM-API, prop=button, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1035561 and loc.getEndColumn() >= 1035561
        ) or 
        (   // id=7573, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 3384 and loc.getEndColumn() >= 3384
        ) or 
        (   // id=7574, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 11254 and loc.getEndColumn() >= 11254
        ) or 
        (   // id=7576, type=DOM-API, prop=picker, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/1542.22098a5.js") and
            loc.getStartLine() = 2 and loc.getEndLine() = 2 and
            loc.getStartColumn() <= 94392 and loc.getEndColumn() >= 94392
        ) or 
        (   // id=8543, type=DOM-API, prop=select, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1362050 and loc.getEndColumn() >= 1362050
        ) or 
        (   // id=8544, type=DOM-API, prop=textarea, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1362050 and loc.getEndColumn() >= 1362050
        ) or 
        (   // id=8545, type=DOM-API, prop=input, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1362050 and loc.getEndColumn() >= 1362050
        ) or 
        (   // id=8546, type=DOM-API, prop=button, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1362050 and loc.getEndColumn() >= 1362050
        ) or 
        (   // id=8555, type=DOM-API, prop=input,select,a[href],textarea,button,[tabindex], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 116737 and loc.getEndColumn() >= 116737
        ) or 
        (   // id=8556, type=DOM-API, prop=input,select,a[href],textarea,button,[tabindex], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 116737 and loc.getEndColumn() >= 116737
        ) or 
        (   // id=8586, type=DOM-API, prop=.jp-DirListing-checkboxWrapper input[type=checkbox], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 574065 and loc.getEndColumn() >= 574065
        ) or 
        (   // id=8588, type=DOM-API, prop=.jp-DirListing-itemText, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 141558 and loc.getEndColumn() >= 141558
        ) or 
        (   // id=8602, type=DOM-API, prop=.jp-DirListing-itemIcon, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 141558 and loc.getEndColumn() >= 141558
        ) or 
        (   // id=8606, type=DOM-API, prop=.jp-DirListing-itemModified, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 141558 and loc.getEndColumn() >= 141558
        ) or 
        (   // id=8608, type=DOM-API, prop=.jp-DirListing-itemFileSize, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 141558 and loc.getEndColumn() >= 141558
        ) or 
        (   // id=8610, type=DOM-API, prop=.jp-DirListing-checkboxWrapper, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 141558 and loc.getEndColumn() >= 141558
        ) or 
        (   // id=9391, type=DOM-API, prop=placeholder, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=9394, type=DOM-API, prop=id-5c44b574-323a-4c0b-af5f-777d1a1a3b9e, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=9395, type=DOM-API, prop=title-key-2-0, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=9396, type=DOM-API, prop=id-9445c3a9-f045-4b03-9f96-a135f16f95ec, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=9397, type=DOM-API, prop=title-key-2-1, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=9398, type=DOM-API, prop=id-1cdd830a-5d29-4bdb-925d-f86933233893, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=9399, type=DOM-API, prop=title-key-2-2, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/lab/index.html") and
            loc.getStartLine() = 0 and loc.getEndLine() = 0 and
            loc.getStartColumn() <= 0 and loc.getEndColumn() >= 0
        ) or 
        (   // id=9691, type=DOM-API, prop=script, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1011019 and loc.getEndColumn() >= 1011019
        ) or 
        (   // id=9692, type=DOM-API, prop=a, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1016921 and loc.getEndColumn() >= 1016921
        ) or 
        (   // id=9693, type=DOM-API, prop=img, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017169 and loc.getEndColumn() >= 1017169
        ) or 
        (   // id=9694, type=DOM-API, prop=*[src], api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017298 and loc.getEndColumn() >= 1017298
        ) or 
        (   // id=9695, type=DOM-API, prop=*[src], api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017298 and loc.getEndColumn() >= 1017298
        ) or 
        (   // id=9696, type=DOM-API, prop=a, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017386 and loc.getEndColumn() >= 1017386
        ) or 
        (   // id=9697, type=DOM-API, prop=link, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017469 and loc.getEndColumn() >= 1017469
        ) or 
        (   // id=9723, type=DOM-API, prop=span.numbering-entry, api=QuerySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1234307 and loc.getEndColumn() >= 1234307
        ) or 
        (   // id=9724, type=DOM-API, prop=span.numbering-entry, api=querySelectorAll
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1234307 and loc.getEndColumn() >= 1234307
        ) or 
        (   // id=9743, type=DOM-API, prop=h1, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017684 and loc.getEndColumn() >= 1017684
        ) or 
        (   // id=9745, type=DOM-API, prop=h2, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017684 and loc.getEndColumn() >= 1017684
        ) or 
        (   // id=9748, type=DOM-API, prop=h3, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017684 and loc.getEndColumn() >= 1017684
        ) or 
        (   // id=9750, type=DOM-API, prop=h4, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017684 and loc.getEndColumn() >= 1017684
        ) or 
        (   // id=9751, type=DOM-API, prop=h5, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017684 and loc.getEndColumn() >= 1017684
        ) or 
        (   // id=9752, type=DOM-API, prop=h6, api=getElementsByTagName
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1017684 and loc.getEndColumn() >= 1017684
        ) or 
        (   // id=9781, type=DOM-API, prop=h1, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1234646 and loc.getEndColumn() >= 1234646
        ) or 
        (   // id=9783, type=DOM-API, prop=h2, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1234646 and loc.getEndColumn() >= 1234646
        ) or 
        (   // id=9787, type=DOM-API, prop=h3, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1234646 and loc.getEndColumn() >= 1234646
        ) or 
        (   // id=9789, type=DOM-API, prop=Try-Jupyter,-powered-by-JupyterLite, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1233704 and loc.getEndColumn() >= 1233704
        ) or 
        (   // id=9790, type=DOM-API, prop=h1[id="Try-Jupyter\,-powered-by-JupyterLite"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1233704 and loc.getEndColumn() >= 1233704
        ) or 
        (   // id=9792, type=DOM-API, prop=span.numbering-entry, api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1233744 and loc.getEndColumn() >= 1233744
        ) or 
        (   // id=9794, type=DOM-API, prop=â¨-Try-it-in-your-browser-â¨, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1233704 and loc.getEndColumn() >= 1233704
        ) or 
        (   // id=9795, type=DOM-API, prop=h2[id="â¨-Try-it-in-your-browser-â¨"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1233704 and loc.getEndColumn() >= 1233704
        ) or 
        (   // id=9799, type=DOM-API, prop=About-this-repository, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1233704 and loc.getEndColumn() >= 1233704
        ) or 
        (   // id=9800, type=DOM-API, prop=h2[id="About-this-repository"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1233704 and loc.getEndColumn() >= 1233704
        ) or 
        (   // id=9804, type=DOM-API, prop=How-to-edit-these-notebooks, api=getElementById
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1233704 and loc.getEndColumn() >= 1233704
        ) or 
        (   // id=9805, type=DOM-API, prop=h3[id="How-to-edit-these-notebooks"], api=QuerySelector
            loc.getFile().getAbsolutePath().matches("%/home/jackfromeast/Desktop/TheHulk/output/websites/random-04-19-21-13/jupyter.org/84070f50e5/source/jupyter.org/try-jupyter/build/jlab_core.cb9a852.js") and
            loc.getStartLine() = 1 and loc.getEndLine() = 1 and
            loc.getStartColumn() <= 1233704 and loc.getEndColumn() >= 1233704
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

DebuggingConfig() { this = "DOM-Clobbering-jupyter.org-84070f50e5" }
    
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
