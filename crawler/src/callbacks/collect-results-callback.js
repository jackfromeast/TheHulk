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
        const results =  JSON.stringify(window.J$$.analysis.dangerousFlows || []);
        return results;
      } catch (e) {
        return [];
      }
    });
  };
  
  const intermediate = await collectFlowsFromFrame(page.mainFrame());
  const mainFrameFlows = JSON.parse(intermediate);
  allDangerousFlows.push(...mainFrameFlows);

  // We don't have nested frames in test cases
  // const frames = page.frames();
  // for (const frame of frames) {
  //   const frameFlows = await collectFlowsFromFrame(frame);
  //   allDangerousFlows.push(...frameFlows);
  // }

  const taintflowsPath = path.join(visitor.webpageCrawlerFolder, 'taintflows.json');

  try {
    // Check if the file exists and read its content
    let existingFlows = [];
    try {
      const fileContent = await fs.readFile(taintflowsPath, 'utf-8');
      existingFlows = JSON.parse(fileContent);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }

    const mergedFlows = [...existingFlows, ...allDangerousFlows];
    await fs.writeFile(taintflowsPath, JSON.stringify(mergedFlows, null, 4));
  } catch (error) {
    visitor.logger.error(`Failed to write taint flows to file: ${error.message}`);
    throw error;
  }

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

    // visitor.retestCurURL = false;
    
  } else {
    visitor.logger.warn(`No taint flows detected in the URL: ${visitor.curURL}`);
    visitor.recordTaintFlowsAcrossTask.failed.push(visitor.curURL);
  }

}