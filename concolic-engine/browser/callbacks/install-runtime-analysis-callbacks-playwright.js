

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
  
  // The following way cannot make sure that jalangi2RuntimePath will be fully loaded before analysisScriptPath
  // visitor.context.addInitScript({ path: jalangi2RuntimePath });
  // visitor.context.addInitScript({ path: analysisScriptPath });

  const jalangi2RuntimeContent = await fs.readFile(jalangi2RuntimePath, 'utf8');
  const analysisScriptContent = await fs.readFile(analysisScriptPath, 'utf8');
  
  // Combine the scripts ensuring the correct order
  const combinedScriptContent = `${jalangi2RuntimeContent}\n${analysisScriptContent}`;


  await visitor.context.addInitScript({ content: combinedScriptContent });
  
  await ensureServiceWorkerScripts(visitor, page);
}



/**
 * Inject scripts into all service workers.
 * @param {Visitor} visitor
 * @param {*} page
 */
async function ensureServiceWorkerScripts(visitor, page) {
  const scriptContent = await fs.readFile(visitor.config.others.ANALYSIS_SCRIPT_PATH, 'utf8');
  const runtimeContent = await fs.readFile(visitor.config.others.JALANGI2_RUNTIME_PATH, 'utf8');

  page.on('worker', async worker => {
    try {
      await worker.evaluate(runtimeContent);
      await worker.evaluate(scriptContent);
      console.log('Scripts injected into worker: ' + worker.url());
    } catch (e) {
      console.error('Failed to inject script into worker:', e);
    }

    worker.on('close', () => console.log('Worker destroyed: ' + worker.url()));
  });
}