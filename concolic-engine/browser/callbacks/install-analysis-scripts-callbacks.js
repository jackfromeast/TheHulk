module.exports = {
  installAnalysisScriptsCb
};

/**
 * @description:
 * --------------------------------
 * The callback function will intakes the visitor and page objects as the argument,
 * register a listener on every new javascript context and install the Jalani2 runtime
 * and the analysis scripts.
 * 
 * @TODO
 * --------------------------------
 * 1/ Add the Jalangi2 runtime bundle script to the page, now we still use the proxy server insturmentation
 * 
 * @param {Visitor} visitor 
 * @param {*} page 
 */
async function installAnalysisScriptsCb(visitor, page){
  visitor.curCDPsession.on('Runtime.executionContextCreated', async (event) => {
    const context = event.context;
    if (context.origin) {
      // Inject the Jalangi2 runtime and analysis scripts
      const evalString = `
        (function() {
          function injectScripts() {
            // if (!document.head) {
            //   return setTimeout(injectScripts, 0);
            // }
            // const jalangiRuntime = document.createElement('script');
            // jalangiRuntime.src = '${visitor.config.others.JALANGI_RUNTIME_PATH}';
            const analysisScript = document.createElement('script');
            analysisScript.src = '${visitor.config.others.ANALYSIS_SCRIPT_PATH}';
            
            // const firstScript = document.head.getElementsByTagName('script')[0];
            // if (firstScript) {
            //   // document.head.insertBefore(jalangiRuntime, firstScript);
            //   document.head.insertBefore(analysisScript, firstScript);
            // } else {
            //   // document.head.appendChild(jalangiRuntime);
            //   document.head.appendChild(analysisScript);
            // }
            
            // After we can inject Jalangi2 runtime, we can inject the analysis script insertAfter the Jalangi2 runtime
            document.head.appendChild(analysisScript);
          }
          if(J$$ && !J$$.analysis) injectScripts();
        })();
      `;
      await visitor.curCDPsession.send('Runtime.evaluate', {
        expression: evalString,
        contextId: context.id,
        awaitPromise: true
      });
    }
  });
}
