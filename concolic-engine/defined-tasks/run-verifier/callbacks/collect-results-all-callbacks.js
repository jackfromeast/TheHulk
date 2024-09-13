module.exports = {
  collectResultsPerTaskCallbacks
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
async function collectResultsPerTaskCallbacks(visitor, page) {
  // Summary of the taint tracking results for all the pages
  if (visitor.recordTaintFlowsAcrossTask) {
    let total = visitor.recordTaintFlowsAcrossTask.success.length + visitor.recordTaintFlowsAcrossTask.failed.length;

    visitor.logger.info(`Test passed: ${visitor.recordTaintFlowsAcrossTask.success.length}/${total}`);
    visitor.logger.info(`Test failed: ${visitor.recordTaintFlowsAcrossTask.failed.length}/${total}`);

    visitor.logger.info("Success cases:");
    visitor.recordTaintFlowsAcrossTask.success.forEach(url => {
      visitor.logger.info(`  - ${url}`);
    });

    visitor.logger.info("Failed cases:");
    visitor.recordTaintFlowsAcrossTask.failed.forEach(url => {
      visitor.logger.error(`  - ${url}`);
    });

    // Write the results to a file
    const summaryPath = path.join(visitor.basedir, 'taintflows_summary.json');
    const summaryData = {
      success: visitor.recordTaintFlowsAcrossTask.success,
      failed: visitor.recordTaintFlowsAcrossTask.failed,
      total: total,
      successCount: visitor.recordTaintFlowsAcrossTask.success.length,
      failedCount: visitor.recordTaintFlowsAcrossTask.failed.length
    };

    await fs.writeFile(summaryPath, JSON.stringify(summaryData, null, 4));
    visitor.logger.info(`Summary of taint flows written to ${summaryPath}`);
  }
}