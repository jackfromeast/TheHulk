

module.exports = {
  installJalangi2OnlyCb
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
async function installJalangi2OnlyCb(visitor, page) {
  const jalangi2RuntimePath = path.resolve(visitor.config.others.JALANGI2_RUNTIME_PATH);

  visitor.context.addInitScript({ path: jalangi2RuntimePath });
}



/**
 * Inject scripts into all service workers.
 * @param {Visitor} visitor
 * @param {*} page
 */
async function ensureServiceWorkerScripts(visitor, page) {
  const jalangi2RuntimePath = path.resolve(visitor.config.others.JALANGI2_RUNTIME_PATH);
  const jalangi2RuntimeContent = await fs.readFile(jalangi2RuntimePath, 'utf8');

  // Route all script requests
  await page.route('**', async (route) => {
    const request = route.request();

    // Intercept only Service Worker scripts
    if (request.url().endsWith('service-worker.js')) {
      const response = await fetch(request.url());
      const originalScript = await response.text();

      const modifiedScript = `
        ${jalangi2RuntimeContent}
        ${originalScript}
      `;

      await route.fulfill({
        contentType: 'application/javascript',
        body: modifiedScript,
      });
    } else {
      // Continue with other requests unmodified
      await route.continue();
    }
  });

  console.log('Service Worker route interception set up.');
}