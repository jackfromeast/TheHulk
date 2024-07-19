module.exports = {
  collectResultPerPageCallbacks
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
async function collectResultPerPageCallbacks(visitor, page) {

  let allDangerousFlows = [];

  const collectFlowsFromFrame = async (frame) => {
    return await frame.evaluate(() => {
      try {
        return window.J$$.analysis.dangerousFlows || [];
      } catch (e) {
        return [];
      }
    });
  };

  const mainFrameFlows = await collectFlowsFromFrame(page.mainFrame());
  allDangerousFlows.push(...mainFrameFlows);

  // We don't have nested frames in test cases
  // const frames = page.frames();
  // for (const frame of frames) {
  //   const frameFlows = await collectFlowsFromFrame(frame);
  //   allDangerousFlows.push(...frameFlows);
  // }

  const taintflowsPath = path.join(visitor.webpageCrawlerFolder, 'taintflows.json');
  await fs.writeFile(taintflowsPath, JSON.stringify(allDangerousFlows, null, 4));

  if (!visitor.recordTaintFlowsAcrossTask) {
    visitor.recordTaintFlowsAcrossTask = {
      success: [],
      failed: []
    }
  }

  if (allDangerousFlows.length > 0) {
    visitor.logger.debug(`Taint flows detected in the URL: ${visitor.curURL}`);
    // Remove URL from failed list if retesting the page
    visitor.recordTaintFlowsAcrossTask.failed = visitor.recordTaintFlowsAcrossTask.failed.filter(url => url !== visitor.curURL);
    visitor.recordTaintFlowsAcrossTask.success.push(visitor.curURL);
  } else {
    visitor.logger.warn(`No taint flows detected in the URL: ${visitor.curURL}`);
    visitor.recordTaintFlowsAcrossTask.failed.push(visitor.curURL);
  }

}