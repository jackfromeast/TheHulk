module.exports = {
  retestIfJalangi2NotFound
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
async function retestIfJalangi2NotFound(visitor, page) {

  // Check the console logs for Jalangi2 not found error
  // E.g. [!] ERROR: J$$ is not defined
  const jalangi2ErrorPattern = /J\$\$ is not defined/;
  const consoleLogs = visitor.collected.curURLHash.consoleLogs;
  let jalangi2NotFound = false;

  // Iterate through the console logs to check for the specific error using regex
  for (const log of consoleLogs) {
    if (jalangi2ErrorPattern.test(log)) {
      jalangi2NotFound = true;
      break;
    }
  }

  if (jalangi2NotFound) {
    visitor.logger.debug("Jalangi2 runtime insertion failed, Retesting...");
    await visitor.setRetestFlag();
  }

}