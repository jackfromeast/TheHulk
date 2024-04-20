const fs = require('fs');

module.exports = {
    compileQLQueryCb
};

/**
 * Given the DOMC lookups, compile the QL query
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function compileQLQueryCb(visitor, _){
    let qlBasePath = visitor.config.others.codeql_query_save_path;
    let qlCompiler = new QLQueryCompiler(visitor, qlBasePath + `/${visitor.domain}-${visitor.curURLHash}.ql`);
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

        this.lookupsWinType1 = [];
        this.lookupsDocType1 = [];
        this.lookupsDocType2 = [];
        this.lookupsApiType = [];

        this.outputql = "";

        this.outputPath = outputPath;
    }

    compile(){
        this.extractLookups();

        this.outputql += this.genDescriptionHeader();
        this.outputql += this.genImportHeader();
        this.outputql += this.genIdentifiedClobberableSourceWinTypeOne();
        this.outputql += this.genIdentifiedClobberableSourceDocTypeOne();
        this.outputql += this.genIdentifiedClobberableSourceDocTypeTwo();
        this.outputql += this.genIdentifiedClobberableSourceDOMAPI();
        this.outputql += this.genIdentifiedClobberableSources();
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
            // TODO: Filter out the same lookups

            let lookupIdentifier = `${lookup.sourceURL}-${lookup.line_number}-${lookup.column_number}-${lookup.lookup_property}-${lookup.type}`;
            // Check if we've already processed a lookup with these identifiers
            if (seenLookups.has(lookupIdentifier)){
                continue;
            }else{
                seenLookups.add(lookupIdentifier);
            }

            if (lookup.type === "<WIN-TYPE-1>"){
                this.lookupsWinType1.push(lookup);
            } else if (lookup.type === "<DOC-TYPE-1>"){
                this.lookupsDocType1.push(lookup);
            } else if (lookup.type === "<DOC-TYPE-2>"){
                this.lookupsDocType2.push(lookup);
            } else if (lookup.type.startsWith("<API-TYPE-")){
                this.lookupsApiType.push(lookup);
            }
        }
    }

    genIdentifiedClobberableSourceWinTypeOne(){
        let prefix = `
class IdentifiedClobberableSourceWinTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceWinTypeOne() {
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
        if (this.lookupsWinType1.length === 0){
            return this.genEmptyTypeOneLookups();
        }

        let or_operator = " or ";
        let outputFunction = prefix;
        for (let i = 0; i < this.lookupsWinType1.length; i++){
            try{
                if (!this.fileMap[this.lookupsWinType1[i].sourceURL.trim()]){
                    continue;
                }
                let resolvedPath = this.fileMap[this.lookupsWinType1[i].sourceURL.trim()].replace(this.visitor.basedir, "")
                outputFunction += this.genWinTypeOneLookups(
                    resolvedPath,
                    this.lookupsWinType1[i].line_number,
                    this.lookupsWinType1[i].column_number,
                    this.lookupsWinType1[i].lookup_property,
                    this.lookupsWinType1[i].id
                );
            }
            catch(e){
                throw e;
            }

            if (i !== this.lookupsWinType1.length - 1){ outputFunction += or_operator;}
        }
        outputFunction += suffix;
        return outputFunction;
    }

    genWinTypeOneLookups(filepath, line, column, property, id){
        return `
        (   // id=${id}, type=WIN-TYPE-1, prop=${property} 
            loc.getFile().getAbsolutePath().matches("%${filepath}") and
            loc.getStartLine() = ${line} and loc.getEndLine() = ${line} and
            loc.getStartColumn() <= ${column} and loc.getEndColumn() >= ${column}
        )`
    }

    genEmptyTypeOneLookups(){
        return `
class IdentifiedClobberableSourceWinTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceWinTypeOne() {
        none()
    }
}`
    }


    genIdentifiedClobberableSourceDocTypeOne(){
        let prefix = `
class IdentifiedClobberableSourceDocTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeOne() {
        exists(DataFlow::PropRead propRead |
            exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (`
        let suffix = `)
        ) and
        this = propRead
      )
  }
}`      
        if (this.lookupsDocType1.length === 0){
            return this.genEmptyDocTypeOneLookups();
        }

        let or_operator = " or ";
        let outputFunction = prefix;
        for (let i = 0; i < this.lookupsDocType1.length; i++){
            if (!this.fileMap[this.lookupsDocType1[i].sourceURL.trim()]){
                if (i === this.lookupsApiType.length - 1) {outputFunction = outputFunction.slice(0, -4);}
                continue;
            }
            outputFunction += this.genDocTypeOneLookups(
                this.fileMap[this.lookupsDocType1[i].sourceURL.trim()].replace(this.visitor.basedir, ""), // TODO: Remove the prefix
                parseInt(this.lookupsDocType1[i].line_number)+1,  // V8 will print the line number - 1
                this.lookupsDocType1[i].column_number,
                this.lookupsDocType1[i].lookup_property,
                this.lookupsDocType1[i].id
            );
            if (i !== this.lookupsDocType1.length - 1){ outputFunction += or_operator;}
        }
        outputFunction += suffix;
        return outputFunction;
    }

    genDocTypeOneLookups(filepath, line, column, property, id){
        return `
        (   // id=${id}, type=DOC-TYPE-1, prop=${property} 
            loc.getFile().getAbsolutePath().matches("%${filepath}") and
            loc.getStartLine() = ${line} and loc.getEndLine() = ${line} and
            loc.getStartColumn() <= ${column} and loc.getEndColumn() >= ${column}
        )`
    }

    genEmptyDocTypeOneLookups(){
        return `
class IdentifiedClobberableSourceDocTypeOne extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeOne() {
        none()
    }
}`
    }

    genIdentifiedClobberableSourceDocTypeTwo(){
        let prefix = `
class IdentifiedClobberableSourceDocTypeTwo extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeTwo() {
        exists(DataFlow::PropRead propRead |
            exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (`
        let suffix = `)
        ) and
        this = propRead
      )
  }
}`

        if (this.lookupsDocType2.length === 0){
            return this.genEmptyDocTypeTwoLookups();
        }

        let or_operator = " or ";
        let outputFunction = prefix;
        for (let i = 0; i < this.lookupsDocType2.length; i++){
            if (!this.fileMap[this.lookupsDocType2[i].sourceURL.trim()]){
                if (i === this.lookupsApiType.length - 1) {outputFunction = outputFunction.slice(0, -4);}
                continue;
            }

            outputFunction += this.genDocTypeTwoLookups(
                this.fileMap[this.lookupsDocType2[i].sourceURL.trim()].replace(this.visitor.basedir, ""), // TODO: Remove the prefix
                parseInt(this.lookupsDocType2[i].line_number)+1,  // V8 will print the line number - 1
                this.lookupsDocType2[i].column_number,
                this.lookupsDocType2[i].lookup_property,
                this.lookupsDocType2[i].id
            );
            if (i !== this.lookupsDocType2.length - 1) {outputFunction += or_operator;}
        }
        outputFunction += suffix;
        return outputFunction;
    }

    genDocTypeTwoLookups(filepath, line, column, property, id){
        return `
        (   // id=${id}, type=DOC-TYPE-2, prop=${property} 
            loc.getFile().getAbsolutePath().matches("%${filepath}") and
            loc.getStartLine() = ${line} and loc.getEndLine() = ${line} and
            loc.getStartColumn() <= ${column} and loc.getEndColumn() >= ${column}
        )`
    }

    genEmptyDocTypeTwoLookups(){
        return `
class IdentifiedClobberableSourceDocTypeTwo extends DataFlow::Node {
    IdentifiedClobberableSourceDocTypeTwo() {
        none()
    }
}`
    }

    genIdentifiedClobberableSourceDOMAPI(){
        let prefix = `
class IdentifiedClobberableSourceDOMAPI extends DataFlow::Node {
    IdentifiedClobberableSourceDOMAPI() {
        exists(DataFlow::PropRead propRead |
            exists(Location loc |
            propRead.asExpr().getLocation() = loc and
            (`
        let suffix = `)
        ) and
        this = propRead
      )
  }
}`      
        let or_operator = " or ";
        let outputFunction = prefix;

        if (this.lookupsApiType.length === 0){
            return this.genEmptyAPITypeLookups();
        }

        for (let i = 0; i < this.lookupsApiType.length; i++){
            if (!this.fileMap[this.lookupsApiType[i].sourceURL.trim()]){
                if (i === this.lookupsApiType.length - 1) {outputFunction = outputFunction.slice(0, -4);}
                continue;
            }

            outputFunction += this.genAPITypeLookups(
                this.fileMap[this.lookupsApiType[i].sourceURL.trim()].replace(this.visitor.basedir, ""),
                this.lookupsApiType[i].line_number,
                this.lookupsApiType[i].column_number,
                this.lookupsApiType[i].lookup_property,
                this.lookupsApiType[i].apiName,
                this.lookupsApiType[i].id
            );
            if (i !== this.lookupsApiType.length - 1) {outputFunction += or_operator;}
        }
        outputFunction += suffix;
        return outputFunction;    
    }

    genAPITypeLookups(filepath, line, column, property, api, id){
        return `
        (   // id=${id}, type=DOM-API, prop=${property}, api=${api}
            loc.getFile().getAbsolutePath().matches("%${filepath}") and
            loc.getStartLine() = ${line} and loc.getEndLine() = ${line} and
            loc.getStartColumn() <= ${column} and loc.getEndColumn() >= ${column}
        )`
    }

    genEmptyAPITypeLookups(){
        return `
class IdentifiedClobberableSourceDOMAPI extends DataFlow::Node {
    IdentifiedClobberableSourceDOMAPI() {
        none()
    }
}`
    }
    
    genIdentifiedClobberableSources(){
        return `
class IdentifiedClobberableSource extends DataFlow::Node {
    IdentifiedClobberableSource() {
    this instanceof IdentifiedClobberableSourceWinTypeOne or
    this instanceof IdentifiedClobberableSourceDocTypeOne or
    this instanceof IdentifiedClobberableSourceDocTypeTwo or
    this instanceof IdentifiedClobberableSourceDOMAPI
    }
}`
    }

    genDescriptionHeader(){
        return `/**
* @name DOM-Clobbering-${this.domain}-${this.curURLHash}
* @description Finding potential DOM clobbering vulnerabilities with the identified cloudable sources
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

DebuggingConfig() { this = "DOM-Clobbering-${this.domain}-${this.curURLHash}" }
    
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
`
    }

}
