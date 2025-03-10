module.exports = {
  injectHTMLMarkupsCallbacks
};

const fs = require('fs');
const path = require('path');

/**
 * @description
 * --------------------------------
 * The callback function will be invoked before visiting the page
 * 
 * We first extract all the HTML markups from the exploit input file and set them to visitor.collected.curURLHash.exploitInputs
 * Then, we set the visitor.retestCurURL=true, visior.retestMaxTimes=len(visitor.collected.curURLHash.exploitInputs)
 * 
 * Then, we registor to the context to inject the HTML markups to the page on every frame
 * And Set the J$$.analysis.payload to the current exploit input
 * 
 * @param {Visitor} visitor
 * @param {*} page
 */
async function injectHTMLMarkupsCallbacks(visitor, page) {
  // In the first visit, we set the exploit inputs to the visitor
  if (!visitor.verifedURLs) {
    visitor.verifedURLs = {};
    visitor.exploits = [];
  }

  if (visitor.exploits.length === 0 && !visitor.verifedURLs[visitor.curURL]) {

    let exploitInputPath = path.join(visitor.webpageCrawlerFolder, 'exploit.json');
    if (!fs.existsSync(exploitInputPath)) {
      if (!path.isAbsolute(visitor.config.others.EXPLOIT_INPUTS_FOLDER)) {
        visitor.config.others.EXPLOIT_INPUTS_FOLDER = path.join(visitor.hulkdir, visitor.config.others.EXPLOIT_INPUTS_FOLDER);
      }
  
      const exploitInputFolder = path.resolve(visitor.config.others.EXPLOIT_INPUTS_FOLDER, visitor.domain, visitor.curURLHash, "crawler");
      exploitInputPath = path.resolve(exploitInputFolder, 'exploit.json');
    }

    const [exploitInputs, metadata] = parseExploitFile(exploitInputPath, visitor.config.others.EXPLOIT_MAX_TRIES);

    visitor.logger.debug(`Parsed Taint Traces: ${metadata.traces}, Total Payloads: ${metadata.payloads}, Selected Payloads: ${exploitInputs.length}.`);

    visitor.verifedURLs[visitor.curURL] = true;
    visitor.exploits = exploitInputs;
    visitor.retestCurURL = true;
    visitor.retestMaxTimes = visitor.exploits.length;
  }

  const curExploitInput = visitor.exploits.pop();
  visitor.retestMaxTimes = visitor.exploits.length;
  if (visitor.retestMaxTimes === 0) {
    visitor.retestCurURL = false;
  } else {
    visitor.retestCurURL = true;
  }

  visitor.logger.debug(`Injecting HTML markups to the page: ${curExploitInput ? curExploitInput.replace('\n', '') : 'None.'}`);

  await page.addInitScript((markup) => {
    if (typeof J$$ !== 'undefined' && J$$.analysis) {
      J$$.analysis.payload = markup;
    }
  }, curExploitInput);
}

/**
 * Parses the exploit file to extract data
 * 
 * @param {string} filePath - Path to the exploit file
 * @returns {Array} List of all non-empty lines from the exploit file
 */
function parseExploitFile(filePath, maxTries) {
  try {
    if (!fs.existsSync(filePath)) return [[], { traces: 0, payloads: 0, selectedPayloads: 0 }];
    
    const rawData = fs.readFileSync(filePath, 'utf8');
    const traces = JSON.parse(rawData);
    const metadata = {
      traces: traces.length || 0,
      payloads: traces.reduce((acc, trace) => acc + (trace.exploits || []).length, 0)
    };
    
    let uniquePayloads = new Set();

    traces.forEach(trace => {
      const traceExploits = trace.exploits || [];
      const numToSelect = Math.min(traceExploits.length, maxTries);
      const selected = traceExploits.slice(0, numToSelect);
      
      selected.forEach(payload => uniquePayloads.add(payload));
    });

    const payloads = Array.from(uniquePayloads);
    metadata.selectedPayloads = payloads.length;

    return [payloads, metadata];
  } catch (error) {
    console.error(`Error parsing exploit JSON: ${error.message}`);
    return [[], { traces: 0, payloads: 0, selectedPayloads: 0 }];
  }
}

/**
 * Shuffles an array in place using the Fisher-Yates algorithm
 * 
 * @param {Array} array - The array to shuffle
 * @returns {Array} The shuffled array
 */
function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]]; // Swap elements
  }
  return array;
}