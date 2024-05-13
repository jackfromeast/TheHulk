const fs = require('fs');

module.exports = {
    compileQLQueryUndefCb
};

/**
 * Given the Undefined lookups, compile the QL query
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function compileQLQueryCb(visitor, _){
    let qlBasePath = visitor.config.others.CODEQL_QUERY_SAVE_PATH;
    let qlCompiler = new QLQueryCompiler(visitor, qlBasePath + `/${visitor.domain}-${visitor.curURLHash}-undef.ql`);
    qlCompiler.compile();
    qlCompiler.save();
}

/**
 * Given the domc-lookups.json file, compile the QL query by
 * Extracting the clobberable sites as sources
 */
class QLQueryCompiler{
    constructor(visitor, outputPath){
        this.visitor = visitor;

        this.domain = visitor.domain;
        this.curURLHash = visitor.curURLHash;

        this.fileMap = visitor.collected.curURLHash.fileMap;

        this.alllookups = visitor.collected.curURLHash.DOMCLookups;

        this.lookupsUndefType1 = [];

        this.outputql = "";

        this.outputPath = outputPath;
    }

    compile(){
        this.extractLookups();

        this.outputql += this.genDescriptionHeader();
        this.outputql += this.genImportHeader();
        this.outputql += this.genIdentifiedClobberableSourceUndefTypeOne();
        this.outputql += this.genDebuggingConfig();

        return this.outputql;
    }

    save(){
        fs.writeFileSync(this.outputPath, this.outputql);
    }

    extractLookups(){
        let seenLookups = new Set();

        for (let i = 0; i < this.alllookups.length; i++){
            let lookup = this.alllookups[i];

            let lookupIdentifier = `${lookup.sourceURL}-${lookup.line_number}-${lookup.column_number}-${lookup.lookup_property}-${lookup.type}`;
            // Check if we've already processed a lookup with these identifiers
            if (seenLookups.has(lookupIdentifier)){
                continue;
            }else{
                seenLookups.add(lookupIdentifier);
            }

            if (lookup.type === "<Undef-TYPE-1>"){
                this.lookupsUndefType1.push(lookup);
            } 
        }
    }

    genIdentifiedClobberableSourceUndefTypeOne(){
        let prefix = `
class IdentifiedClobberableSourceUndefTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceUndefTypeOne() {
        exists(DataFlow::PropRead propRead |
        exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (`
        let suffix = `
        )
        ) and
        this = propRead
      )
    }
}`      
        if (this.lookupsUndefType1.length === 0){
            return this.genEmptyTypeOneLookups();
        }

        let or_operator = " or ";
        let outputFunction = prefix;
        for (let i = 0; i < this.lookupsUndefType1.length; i++){
            try{
                if (!this.fileMap[this.lookupsUndefType1[i].sourceURL.trim()]){
                    continue;
                }
                let resolvedPath = this.fileMap[this.lookupsUndefType1[i].sourceURL.trim()].replace(this.visitor.basedir, "")
                outputFunction += this.genUndefTypeOneLookups(
                    resolvedPath,
                    this.lookupsUndefType1[i].line_number,
                    this.lookupsUndefType1[i].column_number,
                    this.lookupsUndefType1[i].lookup_property,
                    this.lookupsUndefType1[i].id
                );
            }
            catch(e){
                throw e;
            }

            if (i !== this.lookupsUndefType1.length - 1){ outputFunction += or_operator;}
        }
        outputFunction += suffix;
        return outputFunction;
    }

    genUndefTypeOneLookups(filepath, line, column, property, id){
        return `
        (   // id=${id}, type=Undef-TYPE-1, prop=${property} 
            loc.getFile().getAbsolutePath().matches("%${filepath}") and
            loc.getStartLine() = ${line} and loc.getEndLine() = ${line} and
            loc.getStartColumn() <= ${column} and loc.getEndColumn() >= ${column}
        )`
    }

    genEmptyTypeOneLookups(){
        return `
class IdentifiedClobberableSourceUndefTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceUndefTypeOne() {
        none()
    }
}`
    }


    genDescriptionHeader(){
        return `/**
* @name PPGadgets-${this.domain}-${this.curURLHash}
* @description Finding potential prototype pollution gadgets with the identified undefined property lookup sources
* @kind path-problem
* @problem.severity warning
* @security-severity 6.1
* @precision high
* @id js/xss-through-dom
* @tags security
*       external/cwe/cwe-079
*/`
    }

    genImportHeader(){
        return `
import javascript
import DataFlow::PathGraph
import semmle.javascript.security.dataflow.XssThroughDomCustomizations::XssThroughDom
import semmle.javascript.security.dataflow.DomBasedXssCustomizations
import Sinks.TheHulkSink
        `
    }

    genDebuggingConfig(){
        return `
predicate propReadAsTaintStep(DataFlow::Node pred, DataFlow::Node succ){
    exists(DataFlow::PropRead pr | 
        pr.getBase() = pred and
        pr.flowsTo(succ)
    )
}

class DebuggingConfig extends TaintTracking::Configuration {
// Configuration baseConfig;

DebuggingConfig() { this = "PPGagdets-${this.domain}-${this.curURLHash}" }
    
    override predicate isSource(DataFlow::Node source) { 
        source instanceof IdentifiedClobberableSourceUndefTypeOne
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
`
    }

}
