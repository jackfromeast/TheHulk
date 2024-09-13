

module.exports = {
  installJalangi2AndAnalysisCb
};

const fs = require('fs').promises;
const path = require('path');

/**
 * @description
 * --------------------------------
 * The callback function will invoked before the visiting the page to guarantee that
 * the Jalangi2 runtime and the analysis scripts are installed before any other script
 * 
 * We uses the Page.addScriptToEvaluateOnNewDocument method to inject the scripts to the page
 * Refer to https://chromedevtools.github.io/devtools-protocol/tot/Page/#method-addScriptToEvaluateOnNewDocument
 * 
 * We haved tried Runtime.executionContextCreated and Debugger.scriptParsed events to inject the scripts
 * but they don't guarantee that the event will be fired before any other script on the page.
 * 
 * @TODO
 * --------------------------------
 * 1. Ensure this is also working for the service workers
 * 
 * @param {Visitor} visitor 
 * @param {*} page 
 */
async function installJalangi2AndAnalysisCb(visitor, page) {
  const analysisScriptPath = path.resolve(visitor.config.others.ANALYSIS_SCRIPT_PATH);
  const jalangi2RuntimePath = path.resolve(visitor.config.others.JALANGI2_RUNTIME_PATH);
  const analysisScriptContent = await fs.readFile(analysisScriptPath, 'utf8');
  const runtimeScriptContent = await fs.readFile(jalangi2RuntimePath, 'utf8');

  // Helper function to get the inject script content
  const getInjectScriptContent = () => `
    (function() {
      if (typeof J$$ === 'undefined') {
        console.log('[installJalangi2AndAnalysis] Injecting Jalangi2 runtime scripts');
        ${runtimeScriptContent};
      }
      if (!J$$.analysis) {
        console.log('[installJalangi2AndAnalysis] Injecting Jalangi2 analysis scripts');
        ${analysisScriptContent};
      }
    })();
  `;

  // Add the script to evaluate on new document
  try {
    await visitor.curCDPsession.send('Page.addScriptToEvaluateOnNewDocument', {
      source: getInjectScriptContent(),
      runImmediately: true
    });
    visitor.logger.info('[installJalangi2AndAnalysis] Added script to evaluate on new document');
  } catch (err) {
    visitor.logger.warn(`[installJalangi2AndAnalysis] Adding script to evaluate on new document failed: ${err}`);
  }
}