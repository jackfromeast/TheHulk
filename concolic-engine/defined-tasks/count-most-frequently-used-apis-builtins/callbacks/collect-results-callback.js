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
  let allBuiltins = {};

  const collectBuiltinsFromFrame = async (frame) => {
    return await frame.evaluate(() => {
      try {
        return window.J$$.analysis.collectBuiltins || {};
      } catch (e) {
        return {};
      }
    });
  };

  const mergeBuiltins = (target, source) => {
    for (const key in source) {
      if (source.hasOwnProperty(key)) {
        if (target[key]) {
          target[key] += source[key];
        } else {
          target[key] = source[key];
        }
      }
    }
  };

  let mainFrameBuiltins = await collectBuiltinsFromFrame(page.mainFrame());
  mainFrameBuiltins = await collectBuiltinsFromFrame(page.mainFrame());
  mergeBuiltins(allBuiltins, mainFrameBuiltins);

  // Collect builtins from all frames
  const frames = page.frames();
  for (const frame of frames) {
    const frameBuiltins = await collectBuiltinsFromFrame(frame);
    mergeBuiltins(allBuiltins, frameBuiltins);
  }

  // Write builtins to builtins.json file
  const builtinsPath = path.join(visitor.webpageCrawlerFolder, 'builtins-api.json');
  await fs.writeFile(builtinsPath, JSON.stringify(allBuiltins, null, 2));
}