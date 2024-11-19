const fs = require('fs');

module.exports = {
  summaryCrawlerErrors
};

/**
* The callback function will be invoked for every url's crawler directory.
* 
* @param {Object} globalData 
* @param {String} pagePath: the crawler directory path
* @param {String} domain: the domain of the url
* @param {String} urlHash: the hash of the url
*/
async function summaryCrawlerErrors(globalData, pagePath, domain, urlHash) {
  globalData.failedDomains = globalData.failedDomains || {};
  const logFilePath = `${pagePath}/crawler.log`;
  
  try {
    const logFile = fs.readFileSync(logFilePath, 'utf8');
    
    const errorLines = logFile.split('\n').filter(line => line.includes('[ERROR]'));

    if (errorLines.length > 0) {
      if (!globalData.failedDomains[domain]) {
        globalData.failedDomains[domain] = {};
      }
      
      if (!globalData.failedDomains[domain][urlHash]) {
        globalData.failedDomains[domain][urlHash] = [];
      }

      errorLines.forEach(errorLine => {
        globalData.failedDomains[domain][urlHash].push(errorLine);
      });
    }

  } catch (error) {
    ;
  }
}