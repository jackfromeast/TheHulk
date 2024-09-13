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

  if (visitor.exploits.length===0 && !visitor.verifedURLs[visitor.curURL]) {
    const exploitInputPath = path.resolve(visitor.config.others.EXPLOIT_INPUTS);
    const parsedExploitData = parseExploitFile(exploitInputPath);

    // Find matching exploits based on URL pattern
    const matchedExploit = Object.entries(parsedExploitData).find(([url, _]) => {
      // const pattern = new RegExp(`^${url}\\w*`);  // Regex to match the base URL with any subpath
      // return pattern.test(visitor.curURL);
      return visitor.curURL === url;
    });

    if (!matchedExploit) {
      visitor.logger.error("No matching exploit inputs found for the current URL");
      return;
    }

    const [_, exploitInputs] = matchedExploit;
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

  visitor.logger.debug(`Injecting HTML markups to the page: ${curExploitInput}`);

  await page.addInitScript((markup) => {
    if (typeof J$$ !== 'undefined' && J$$.analysis) {
      J$$.analysis.payload = markup;
    }
  }, curExploitInput);
}


/**
 * Parses the exploit file to extract data
 * 
 * @param {string} filePath
 * @returns {Object} Parsed exploit data
 */
function parseExploitFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    const sections = content.split(/===============URL===============/).filter(Boolean);
    const parsedData = {};

    sections.forEach(section => {
      const [url, exploits] = section.split(/===============EXP===============/).map(part => part.trim());

      if (url && exploits) {
        const exploitArray = exploits.split('\n').filter(exploit => exploit.trim());
        parsedData[url] = exploitArray;
      }
    });

    return parsedData;
  } catch (error) {
    console.error("Error reading or parsing the file:", error);
    throw error;
  }
}