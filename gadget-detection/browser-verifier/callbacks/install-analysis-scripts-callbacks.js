module.exports = {
  installAnalysisScriptsCb
};

const fs = require('fs').promises;
const path = require('path');

/**
 * [DEPRECATED]
 * @description
 * --------------------------------
 * The callback function will intake the visitor and page objects as the argument,
 * register a listener on every new javascript context and install the Jalangi2 runtime
 * and the analysis scripts.
 * 
 * Here we use the Runtime.executionContextCreated event besides the page.evaluateOnNewDocument,
 * because we need it to be executed in contexts like service workers, etc.
 * 
 * We are injecting the content of the script directly instead of adding a script tag and setting the
 * src because we can guarantee that the script will be installed before any other script on the page.
 * 
 * @TODO
 * --------------------------------
 * 
 * @param {Visitor} visitor 
 * @param {*} page 
 */
async function installAnalysisScriptsCb(visitor, page){
  const analysisScriptPath = path.resolve(visitor.config.others.ANALYSIS_SCRIPT_PATH);
  const analysisScriptContent = await fs.readFile(analysisScriptPath, 'utf8');
  
  // Inject the Jalangi2 runtime and analysis scripts before any other script
  visitor.curCDPsession.on('Runtime.executionContextCreated', async (event) => {
    const context = event.context;
    if (context.origin) {
      
      const evalString = `
        (function() {
          function injectScripts() {
            ${analysisScriptContent}
          }
          if (typeof J$$ !== 'undefined' && !J$$.analysis) injectScripts();
        })();
      `;
      try{
        await visitor.curCDPsession.send('Runtime.evaluate', {
          expression: evalString,
          contextId: context.id,
          awaitPromise: true
        });
      } catch(err){
        visitor.logger.warn(`[installAnalysisScriptsCb] Injecting scripts failed (due to debug context): ${err}`);
      }
    }
  });
};
