module.exports = {
  earlyStopIfDetected
};

const fs = require('fs').promises;
const path = require('path');

/**
 * @description
 * --------------------------------
 * The callback function helps to prevent the retesting process if the taintflow file is not empty
 *
 * @param {Visitor} visitor 
 * @param {*} page 
 */
async function earlyStopIfDetected(visitor, page) {
  const taintflowsPath = path.join(visitor.webpageCrawlerFolder, 'taintflows.json');

  let existingFlows = [];
  try {
    const fileContent = await fs.readFile(taintflowsPath, 'utf-8');
    existingFlows = JSON.parse(fileContent);

    if (existingFlows.length > 0) {
      visitor.logger.info(`Stop testing the URL ${visitor.curURL} as taint flows are detected.`);
      visitor.retestCurURL = false;
      visitor.retestMaxTimes = -1;
      visitor.generatedExpForCurURL = false;
      visitor.exploits = [];

    }
  } catch (error) { ;
  }
}