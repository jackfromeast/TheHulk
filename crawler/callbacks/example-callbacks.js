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
function extractDOMCLookupsCb(visitor, page){
    let raw_stdout = visitor.collected.curURLHash.consoleLogs.join("\n");
    let lookups = extractDOMCLookups(raw_stdout);

    visitor.collected.DOMCLookups = lookups;
}


/**
 * @function extractDOMCLookups
 * @description Extract the DOMC lookups from the raw stdout from the browser process.
 * 
 * E.g.
 * 
 * From the following stdout:
 * [+] SafeLookup: Found a legitimate use of window/document object to load DOM element.
 * [+] SafeLookup: ORIGIN @http://127.0.0.1:8080
 * [+] SafeLookup: SOURCEURL/FILENAME @ __puppeteer_evaluation_script__
 * [+] SafeLookup: Lookup Site @5:25
        if (document.documentElement)
 * 
 * We extract the following:
 * {
 *    id: 1,
 *    origin: "http://127.0.0.1:8080",
 *    sourceURL: "__puppeteer_evaluation_script__",
 *    lookupSite: "5:25",
 *    text: "if (document.documentElement)"
 * }
*/
function extractDOMCLookups(raw_stdout){
    // Split the stdout into separate lookup entries
    let delimiter = ""
    for (let i = 0; i < 86; i++) {
      delimiter += "="
    }
    
    const entries = raw_stdout.split(delimiter);
  
    // delete empty entries
    for (let i = 0; i < entries.length; i++) {
      if (entries[i] === '') {
        entries.splice(i, 1);
      }
    }
  
    const lookups = [];
    let count = 0;
    entries.forEach((entry, index) => {
      entry = entry.trim();
      // Regular expressions to match each line's relevant part
      const originRegex = /\[\+\] SafeLookup: ORIGIN @(.+)/;
      const sourceURLRegex = /\[\+\] SafeLookup: SOURCEURL\/FILENAME @ (.+)/;
      const lookupSiteRegex = /\[\+\] SafeLookup: Lookup Site @(.+)/;
  
      // Extracting the information using the regular expressions
      const originMatch = entry.match(originRegex);
      const sourceURLMatch = entry.match(sourceURLRegex);
      const lookupSiteMatch = entry.match(lookupSiteRegex);
      const textMatch = entry.split('\n').slice(-1)[0];
  
      // Building the object if all parts are found
      if (originMatch && sourceURLMatch && lookupSiteMatch && textMatch) {
        const lookup = {
          id: count++,
          origin: originMatch[1].trim(),
          sourceURL: sourceURLMatch[1].trim(),
          lookupSite: lookupSiteMatch[1].trim(),
          text: textMatch.trim()
        };
        lookups.push(lookup);
      }
    });
  
    return lookups;
  }