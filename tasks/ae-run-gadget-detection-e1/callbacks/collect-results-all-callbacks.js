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

    // Filter function to match URLs following the pattern
    const urlPattern = /^http:\/\/127.0.0.1:8080\/.*\/poc\.html/;
    
    let filteredSuccess = visitor.recordTaintFlowsAcrossTask.success.filter(url => urlPattern.test(url));
    let filteredFailed = visitor.recordTaintFlowsAcrossTask.failed.filter(url => urlPattern.test(url));

    // Remove duplicates
    filteredSuccess = [...new Set(filteredSuccess)];
    filteredFailed = [...new Set(filteredFailed)];

    let total = filteredSuccess.length + filteredFailed.length;

    visitor.logger.info(`Test passed: ${filteredSuccess.length}/${total}`);
    visitor.logger.info(`Test failed: ${filteredFailed.length}/${total}`);

    visitor.logger.info("Success cases:");
    filteredSuccess.forEach(url => {
      visitor.logger.info(`  - ${url}`);
    });

    visitor.logger.info("Failed cases:");
    filteredFailed.forEach(url => {
      visitor.logger.error(`  - ${url}`);
    });

    // Write the filtered results to a file
    const summaryPath = path.join(visitor.basedir, 'taintflows_summary.json');
    const summaryData = {
      success: filteredSuccess,
      failed: filteredFailed,
      total: total,
      successCount: filteredSuccess.length,
      failedCount: filteredFailed.length
    };

    await fs.writeFile(summaryPath, JSON.stringify(summaryData, null, 4));
    visitor.logger.info(`Summary of taint flows written to ${summaryPath}`);
  }
}
