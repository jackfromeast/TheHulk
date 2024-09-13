const fs = require("fs");

// This file is an example of a user-defined callback module.
module.exports = {
    extractUndefCLookupsCb
};

/**
 * The callback function will intakes the visitor and page objects as the argument
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function extractUndefCLookupsCb(visitor){
    let lookups = await extractUndefCLookups(visitor.collected.curURLHash.consoleLogs, startLine);
    visitor.collected.curURLHash.undefinedLookups = lookups;
}

/**
 * Extracts undefined lookups from browser console logs.
 *
 * Parses log entries formatted like:
 * [+] SafeLookup: <Undef-TYPE-1> : pointerType, https://www.gstatic.com/og/_/js/k=og.asy.en_US.87eUZV1aBpo.2019.O/rt=j/m=_ac,_awd,ada,lldp/exm=/d=1/ed=1/rs=AA2YrTun3wmuSP_eW-729q5NbbI8Y5dI1w:48:187
 *
 * and converts them into objects:
 * {
 *    id: 1,
 *    type: "<Undef-TYPE-1>",
 *    sourceURL: "https://www.gstatic.com/og/_/js/k=og.asy.en_US.87eUZV1aBpo.2019.O/rt=j/m=_ac,_awd,ada,lldp/exm=/d=1/ed=1/rs=AA2YrTun3wmuSP_eW-729q5NbbI8Y5dI1w",
 *    line_number: "48",
 *    column_number: "187",
 *    lookup_property: "pointerType"
 * }
 *
 * @param {string} logs - Browser console log as a string or array of lines.
 * @param {string} startLine - Marker after which to start processing logs.
 * @returns {Array} Array of lookup objects.
 */
async function extractUndefCLookups(logs, startLine = '') {
  if (typeof logs === 'string') {
      logs = logs.split('\n');
  }

  const lookups = [];
  let idCounter = 1;
  let processLogs = startLine === '';

  // Regex to parse relevant log entries
  const regex = /\[.*?\] SafeLookup: (<Undef-TYPE-\d+>) ?: (.*?), (https?:\/\/[^\s:]+)(?::(\d+):(\d+))?/;

  logs.forEach(line => {
    if (!processLogs && line.includes(startLine)) {
      processLogs = true;
    }

    if (processLogs) {
      const match = line.match(regex);

      if (match) {
        const [ , type, lookupProperty, sourceURL, line_number = '0', column_number = '0'] = match;
        lookups.push({
          id: idCounter++,
          type,
          lookup_property: lookupProperty,
          sourceURL,
          line_number,
          column_number
        });
      }
    }
  });

  return lookups;
}

// let raw_stdout = `
// [+] SafeLookup: <Undef-TYPE-1> : pointerType, https://www.gstatic.com/og/_/js/k=og.asy.en_US.87eUZV1aBpo.2019.O/rt=j/m=_ac,_awd,ada,lldp/exm=/d=1/ed=1/rs=AA2YrTun3wmuSP_eW-729q5NbbI8Y5dI1w:48:187
// [+] SafeLookup: <Undef-TYPE-1> : pointerType, https://www.gstatic.com/og/_/js/k=og.asy.en_US.87eUZV1aBpo.2019.O/rt=j/m=_ac,_awd,ada,lldp/exm=/d=1/ed=1/rs=AA2YrTun3wmuSP_eW-729q5NbbI8Y5dI1w:48:187
// `

// let lookups = extractUndefCLookups(raw_stdout);
// console.log(lookups);



// let rawLog = JSON.parse(fs.readFileSync("/home/xxxxxxxxxxxx/Desktop/TheHulk/output/jupyter-widgets-05-05-22-25/ipywidgets.readthedocs.io/db1b70993e/crawler/console-logs.json", { encoding: 'utf8', flag: 'r' }));
// let startLine = "[extractDOMCLookupsCb] Start.";

// extractDOMCLookups(rawLog, startLine).then((lookups) => {
//     console.log(lookups);
// });