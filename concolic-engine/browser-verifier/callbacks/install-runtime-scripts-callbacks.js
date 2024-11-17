module.exports = {
  installJalangi2RuntimeScriptsCb
};

const fs = require('fs').promises;
const path = require('path');

/**
 * [DEPRECATED]
 * @description
 * --------------------------------
 * The callback function will intakes the visitor and page objects as the argument,
 * register a listener on every new javascript context and install the Jalani2 runtime
 * and the analysis scripts.
 * 
 * Here we use the Runtime.executionContextCreated event besides the page.evaluateOnNewDocument,
 * because we need it to be executed in the context like sevice workers, etc.
 * 
 * We are injecting the content of the script directly instead of adding a script tag and set the
 * src because we can guarantee that the script will installed before any other script on the page.
 * 
 * @TODO
 * --------------------------------
 * 1/ Add the Jalangi2 runtime bundle script to the page, now we still use the proxy server insturmentation
 * 
 * @param {Visitor} visitor 
 * @param {*} page 
 */
async function installJalangi2RuntimeScriptsCb(visitor, page){
  const jalangi2RuntimePath = path.resolve(visitor.config.others.JALANGI2_RUNTIME_PATH);
  const runtimeScriptContent = await fs.readFile(jalangi2RuntimePath, 'utf8');
  
  // Inject the Jalangi2 runtime scripts before any other script
  visitor.curCDPsession.on('Runtime.executionContextCreated', async (event) => {
    const context = event.context;
    if (context.origin) {
      // Inject the Jalangi2 runtime scripts
      const evalString = `
        (function() {
          function injectRuntimeScripts() {
            ${runtimeScriptContent}
          }
          if (typeof J$$ === 'undefined') injectRuntimeScripts();
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