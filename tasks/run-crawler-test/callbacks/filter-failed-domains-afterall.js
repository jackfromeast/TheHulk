const fs = require('fs');

module.exports = {
  saveCrawlerErrors
};

/**
* The callback function will be invoked for every url's crawler directory.
* 
* @param {Object} globalData 
* @param {String} basedir: the output base directory path
*/
async function saveCrawlerErrors(globalData, basedir) {
  const outputFilePath = `${basedir}/crawler-errors.json`;

  const errorSummary = {
    totalFailedPages: 0,
    errorAttribution: {
      "NS_ERROR_UNKNOWN_HOST": 0,
      "NS_ERROR_CONNECTION_REFUSED": 0,
      "ERR_TIMED_OUT": 0,
      "ERR_HTTP2_PROTOCOL_ERROR": 0,
      "NS_ERROR_NET_TIMEOUT": 0,
      "ERROR_HANDLING_RESPONSE": 0,
      "ERR_CERT_COMMON_NAME_INVALID": 0,
      "UNKNOWN_ERROR": 0
    },
    details: globalData.failedDomains
  };

  // Loop through each domain and its failed pages to categorize the errors
  for (const domain in globalData.failedDomains) {
    for (const urlHash in globalData.failedDomains[domain]) {
      const errorMessages = globalData.failedDomains[domain][urlHash];
      errorSummary.totalFailedPages++;

      errorMessages.forEach(errorMessage => {
        if (errorMessage.includes('NS_ERROR_UNKNOWN_HOST')) {
          errorSummary.errorAttribution["NS_ERROR_UNKNOWN_HOST"]++;
        } else if (errorMessage.includes('NS_ERROR_CONNECTION_REFUSED')) {
          errorSummary.errorAttribution["NS_ERROR_CONNECTION_REFUSED"]++;
        } else if (errorMessage.includes('ERR_TIMED_OUT')) {
          errorSummary.errorAttribution["ERR_TIMED_OUT"]++;
        } else if (errorMessage.includes('ERR_HTTP2_PROTOCOL_ERROR')) {
          errorSummary.errorAttribution["ERR_HTTP2_PROTOCOL_ERROR"]++;
        } else if (errorMessage.includes('NS_ERROR_NET_TIMEOUT')) {
          errorSummary.errorAttribution["NS_ERROR_NET_TIMEOUT"]++;
        } else if (errorMessage.includes('Error handling response')) {
          errorSummary.errorAttribution["ERROR_HANDLING_RESPONSE"]++;
        } else if (errorMessage.includes('ERR_CERT_COMMON_NAME_INVALID')) {
          errorSummary.errorAttribution["ERR_CERT_COMMON_NAME_INVALID"]++;
        } else {
          errorSummary.errorAttribution["UNKNOWN_ERROR"]++;
        }
      });
    }
  }

  // Write the summarized errors to the output file
  fs.writeFileSync(outputFilePath, JSON.stringify(errorSummary, null, 2), 'utf8');
  console.log(`Crawler error summary saved to ${outputFilePath}`);
}