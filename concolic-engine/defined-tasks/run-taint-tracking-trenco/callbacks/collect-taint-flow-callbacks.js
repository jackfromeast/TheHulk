module.exports = {
  collectTaintflowsAtRuntimeCb
};

const fs = require('fs').promises;
const path = require('path');

/**
 * @description
 * --------------------------------
 * The callback function will be invoked before visiting the page
 * 
 * Note that, this is better than collect-results-callback.js because it go though all frames before leaving the page
 * And the frames may be destroyed at that time.
 * 
 * @param {Visitor} visitor 
 * @param {*} page 
 */
async function collectTaintflowsAtRuntimeCb(visitor, page) {
 
  visitor.context.exposeBinding("__reportDangerousFlowPlaywright", async function (source, flow) {
    visitor.collected.curURLHash.taintflows.push(flow);
  });

}