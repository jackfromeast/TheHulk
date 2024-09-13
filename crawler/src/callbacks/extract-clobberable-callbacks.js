const fs = require("fs");

// This file is an example of a user-defined callback module.
module.exports = {
    extractDOMCLookupsCb
};

/**
 * The callback function will intakes the visitor and page objects as the argument
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function extractDOMCLookupsCb(visitor){
    let startLine = visitor.config.others.COLLECT_DOM_LOOKUP_HINTS
    let lookups = await extractDOMCLookups(visitor.collected.curURLHash.consoleLogs, startLine);
    visitor.collected.curURLHash.DOMCLookups = lookups;
}


/**
 * @function extractDOMCLookups
 * @description Extract the DOMC lookups from the raw stdout from the browser process.
 * 
 * E.g.
 * 
 * From the browser console logs:
 * [+] SafeLookup: <WIN-TYPE-1> Catched: shindig, Location: https://apis.google.com/_/scs/abc-static/_/js/k=gapi.gapi.en.uvrmm4sgViM.O/m=gapi_iframes,googleapis_client/rt=j/sv=1/d=1/ed=1/am=AAAC/rs=AHpOoo_AfeXEgP9UD-iQrKiwqZLadQ_cBg/cb=gapi.loaded_0:41:461
 * [+] SafeLookup: <API-TYPE-1> <getElementsByTagNameNS> Catched Undefined: iframe, Location: https://s1.hdslb.com/bfs/seed/jinkela/short/leader-election/iframe.html?iframeID=npZ8BwrfjU&leaderID=watchlaterpipwindow:0:0
 * [+] SafeLookup: <DOC-TYPE-2> Catched HTMLElement: documentElement, https://stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js:16:80472
 * [+] SafeLookup: <API-TYPE-2> <QuerySelector> Catched Non-Undefined: #app, Location: https://stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js:6:57857
 * [+] SafeLookup: <API-TYPE-3> <forms> Catched Undefined, Location: https://stackedit.io/app#:0:0
 * 
 * 
 * We extract the following:
 * {
 *    id: 1,
 *    type: "<WIN-TYPE-1>",
 *    sourceURL: "https://apis.google.com/_/scs/abc-static/_/js/k=gapi.gapi.en.uvrmm4sgViM.O/m=gapi_iframes,googleapis_client/rt=j/sv=1/d=1/ed=1/am=AAAC/rs=AHpOoo_AfeXEgP9UD-iQrKiwqZLadQ_cBg/cb=gapi.loaded_0",
 *    line_number: "41",
 *    column_number: "461",
 *    lookup_property" "shindig"
 * },
 * {
 *   id: 2,
 *   type: "<API-TYPE-1>",
 *   apiName: "getElementsByTagNameNS",
 *   sourceURL: "https://s1.hdslb.com/bfs/seed/jinkela/short/leader-election/iframe.html?iframeID=npZ8BwrfjU&leaderID=watchlater",
 *   line_number: "0",
 *  column_number: "0",
 * }
*/

async function extractDOMCLookups(logs, startLine='') {
  if (logs instanceof String || typeof logs === 'string') {
      logs = logs.split("\n");
  }

  const lookups = [];
  let idCounter = 1; // Initialize ID counter

  // Fiter out the logs until the line from COLLECT_DOM_LOOKUP_HINTS
  let startProcessLogs = startLine == '' ? true : false;

  // General regex to match the log entry format
  const regex = /\[.*?\] SafeLookup: (<(WIN|API|DOC)-TYPE-\d+>)(?: <(.*?)>)? Catched.*?: (.*?), (?:Location:)?\s?(.*?):(\d+):(\d+)/;
  const regex_api_type_3 = /\[.*?\] SafeLookup: (<(WIN|API|DOC)-TYPE-\d+>)(?: <(.*?)>)? Catched (.*?), (?:Location:)?\s?(.*?):(\d+):(\d+)/;

  logs.forEach(line => {
    
    if (!startProcessLogs && line.includes(startLine)) {
      startProcessLogs = true;
    }

    if (startProcessLogs){
        let match = line.match(regex);

        if (!match){
            match = line.match(regex_api_type_3);
        }

        if (match) {
            const type = match[1];
            const apiName = match[3]; // This captures the API name for API-TYPE logs
            const lookupProperty = match[4];
            const sourceURL = match[5];
            const line_number = match[6] || "0"; // Default to "0" if not provided
            const column_number = match[7] || "0"; // Default to "0" if not provided

            let logEntry = {
                id: idCounter++,
                type: type,
                sourceURL: sourceURL,
                line_number: line_number,
                column_number: column_number,
                lookup_property: lookupProperty
            };

            // If the log entry is of API-TYPE, include the apiName
            if (apiName) {
                logEntry.apiName = apiName;
            }

            lookups.push(logEntry);
        }
    }
  });

  return lookups;
}

// let raw_stdout = `
// * [+] SafeLookup: <WIN-TYPE-1> Catched: shindig, Location: https://apis.google.com/_/scs/abc-static/_/js/k=gapi.gapi.en.uvrmm4sgViM.O/m=gapi_iframes,googleapis_client/rt=j/sv=1/d=1/ed=1/am=AAAC/rs=AHpOoo_AfeXEgP9UD-iQrKiwqZLadQ_cBg/cb=gapi.loaded_0:41:461
// * [+] SafeLookup: <API-TYPE-1> <getElementsByTagNameNS> Catched Undefined: iframe, Location: https://s1.hdslb.com/bfs/seed/jinkela/short/leader-election/iframe.html?iframeID=npZ8BwrfjU&leaderID=watchlaterpipwindow:0:0
// * [+] SafeLookup: <DOC-TYPE-2> Catched HTMLElement: documentElement, https://stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js:16:80472
// * [+] SafeLookup: <API-TYPE-2> <QuerySelector> Catched Non-Undefined: #app, Location: https://stackedit.io/static/js/vendor.bc2ba2c5746645190c07.js:6:57857
// * [+] SafeLookup: <API-TYPE-3> <forms> Catched Undefined, Location: https://stackedit.io/app#:0:0
// * `

// let lookups = extractDOMCLookups(raw_stdout);
// console.log(lookups);



// let rawLog = JSON.parse(fs.readFileSync("/home/xxxxxxxxxxxx/Desktop/TheHulk/output/jupyter-widgets-05-05-22-25/ipywidgets.readthedocs.io/db1b70993e/crawler/console-logs.json", { encoding: 'utf8', flag: 'r' }));
// let startLine = "[extractDOMCLookupsCb] Start.";

// extractDOMCLookups(rawLog, startLine).then((lookups) => {
//     console.log(lookups);
// });


// let rawLog = JSON.parse(fs.readFileSync("/home/xxxxxxxxxxxx/Desktop/TheHulk/output/cocalc.com-06-11-21-46/cocalc.com/c0ce088e18/crawler/console-logs.json", { encoding: 'utf8', flag: 'r' }));
// let startLine = "Collect Start.";

// extractDOMCLookups(rawLog, startLine).then((lookups) => {
//     console.log(lookups);
// })