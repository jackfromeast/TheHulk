module.exports = {
  retestIfFlowNotFound
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
async function retestIfFlowNotFound(visitor, page) {

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


  if (allDangerousFlows.length === 0) {
    visitor.logger.debug("No taint flow detected, retesting...");
    await visitor.setRetestFlag();
  }

}