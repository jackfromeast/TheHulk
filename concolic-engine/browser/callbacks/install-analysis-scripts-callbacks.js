module.exports = {
  installAnalysisScriptsCb
};

const fs = require('fs').promises;
const path = require('path');

/**
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
async function installAnalysisScriptsCb(visitor, page){
  const analysisScriptPath = path.resolve(visitor.config.others.ANALYSIS_SCRIPT_PATH);
  const analysisScriptContent = await fs.readFile(analysisScriptPath, 'utf8');
  
  // Inject the Jalangi2 runtime and analysis scripts before any other script
  visitor.curCDPsession.on('Runtime.executionContextCreated', async (event) => {
    const context = event.context;
    if (context.origin) {
      // Inject the Jalangi2 runtime and analysis scripts
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
        console.warn(`[installAnalysisScriptsCb] Injecting scripts failed (due to debug context): ${err}`);
      }
    }
  });
};

// async function installAnalysisScriptsCb(visitor, page){
//   const analysisScriptPath = path.resolve(visitor.config.others.ANALYSIS_SCRIPT_PATH);
//   const analysisScriptContent = await fs.readFile(analysisScriptPath, 'utf8');

//   // Inject the Jalangi2 runtime and analysis scripts before any other script
//   visitor.curCDPsession.on('Runtime.executionContextCreated', async (event) => {
//     const context = event.context;
//     if (context.origin) {
//       // Inject the Jalangi2 runtime and analysis scripts
//       const evalString = `
//         (function() {
//           function injectScripts() {
//             // const jalangiRuntime = document.createElement('script');
//             // jalangiRuntime.src = '${visitor.config.others.JALANGI_RUNTIME_PATH}';
//             const analysisScript = document.createElement('script');
//             analysisScript.src = '${visitor.config.others.ANALYSIS_SCRIPT_PATH}';
            
//             // const firstScript = document.head.getElementsByTagName('script')[0];
//             // if (firstScript) {
//             //   // document.head.insertBefore(jalangiRuntime, firstScript);
//             //   document.head.insertBefore(analysisScript, firstScript);
//             // } else {
//             //   // document.head.appendChild(jalangiRuntime);
//             //   document.head.appendChild(analysisScript);
//             // }
            
//             // After we can inject Jalangi2 runtime, we can inject the analysis script insertAfter the Jalangi2 runtime
//             document.head.appendChild(analysisScript);
//           }
//           if(J$$ && !J$$.analysis) injectScripts();
//         })();
//       `;
//       try{
//         await visitor.curCDPsession.send('Runtime.evaluate', {
//           expression: evalString,
//           contextId: context.id,
//           awaitPromise: true
//         });
//       } catch(err){
//         console.warn(`[installAnalysisScriptsCb] Injecting scripts failed (due to debug context): ${err}`);
//       }
//     }
//   });
// };