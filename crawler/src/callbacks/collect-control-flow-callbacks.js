module.exports = {
  collectControlFlowPerPageCallbacks
};

const fs = require('fs').promises;
const path = require('path');

/**
 * @description
 * --------------------------------
 * The callback function will be invoked after visiting the page
 *
 * @param {Visitor} visitor 
 * @param {*} page 
 */
async function collectControlFlowPerPageCallbacks(visitor, page) {

  let allControlFlowConditions = [];

  const collectFlowsFromFrame = async (frame) => {
    return await frame.evaluate(() => {
      try {
        return window.J$$.analysis.controlFlowConditions || [];
      } catch (e) {
        return [];
      }
    });
  };

  const mainFrameFlows = await collectFlowsFromFrame(page.mainFrame());
  allControlFlowConditions.push(...mainFrameFlows);

  const controlFlowSavePath = path.join(visitor.webpageCrawlerFolder, 'conditions.json');

  try {
    await fs.writeFile(controlFlowSavePath, JSON.stringify(allControlFlowConditions, null, 2));
  } catch (error) {
    visitor.logger.error(`Failed to write control flows to file: ${error.message}`);
    throw error;
  }
}