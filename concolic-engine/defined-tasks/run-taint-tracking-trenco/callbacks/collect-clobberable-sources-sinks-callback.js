module.exports = {
  collectSourcesSinksPerPageCallbacks
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
async function collectSourcesSinksPerPageCallbacks(visitor, page) {

  // let allDangerousFlows = [];
  let clobberableSources = {};
  let clobberableSourcePool = {};
  let clobberableSinks = {};

  const collectFlowsAndClobberablesFromFrame = async (frame) => {
    return await frame.evaluate(() => {
      try {
        return {
          // dangerousFlows: window.J$$.analysis.dangerousFlows || [],
          clobberableSources: window.J$$.analysis.clobberableSources || {},
          clobberableSourcePool: window.J$$.analysis.clobberableSourcePool || {},
          clobberableSinks: window.J$$.analysis.clobberableSinks || {}
        };
      } catch (e) {
        return {
          // dangerousFlows: [],
          clobberableSources: {},
          clobberableSourcePool: {},
          clobberableSinks: {}
        };
      }
    });
  };

  const { clobberableSources: mainFrameSources, clobberableSourcePool: mainFrameSourcePool, clobberableSinks: mainFrameSinks } = await collectFlowsAndClobberablesFromFrame(page.mainFrame());

  const aggregateClobberables = (target, source) => {
    for (const [key, value] of Object.entries(source)) {
      if (!target[key]) {
        target[key] = 0;
      }
      target[key] += value;
    }
  };

  const aggregateClobberableSourcePool = (target, source) => {
    for (const [key, value] of Object.entries(source)) {
      if (!target[key]) {
        target[key] = new Set();
      }
      value.forEach(prop => target[key].add(prop));
    }
  };

  aggregateClobberables(clobberableSources, mainFrameSources);
  aggregateClobberables(clobberableSinks, mainFrameSinks);
  aggregateClobberableSourcePool(clobberableSourcePool, mainFrameSourcePool);

  // Convert Set to Array for output
  const clobberableSourcePoolOutput = {};
  for (const [key, value] of Object.entries(clobberableSourcePool)) {
    clobberableSourcePoolOutput[key] = Array.from(value);
  }

  // Save the clobberable sources, source pool, and sinks to files
  const clobberableSourcesPath = path.join(visitor.webpageCrawlerFolder, 'clobberableSources.json');
  await fs.writeFile(clobberableSourcesPath, JSON.stringify(clobberableSources, null, 4));

  const clobberableSourcePoolPath = path.join(visitor.webpageCrawlerFolder, 'clobberableSourcePool.json');
  await fs.writeFile(clobberableSourcePoolPath, JSON.stringify(clobberableSourcePoolOutput, null, 4));

  const clobberableSinksPath = path.join(visitor.webpageCrawlerFolder, 'clobberableSinks.json');
  await fs.writeFile(clobberableSinksPath, JSON.stringify(clobberableSinks, null, 4));

}
