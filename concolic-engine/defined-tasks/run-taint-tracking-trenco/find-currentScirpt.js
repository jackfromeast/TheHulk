const fs = require('fs');
const path = require('path');

// Flatten and parse the taint trace to generate the effective clobberable source code
function parseTaintTrace(taintFlow) {
  let taintFlowSegments = [];

  function flattenTaintFlow(flow, segment) {
    for (let i = 0; i < flow.length; i++) {
      segment.push(flow[i]);
      if (flow[i].taintPropOperations) {
        for (let j = 0; j < flow[i].taintPropOperations.length; j++) {
          let newSegment = [];
          flattenTaintFlow(flow[i].taintPropOperations[j], newSegment);
          taintFlowSegments.push(newSegment);
        }
      }
    }
  }

  let initialSegment = [];
  flattenTaintFlow(taintFlow, initialSegment);
  taintFlowSegments.push(initialSegment);

  let results = [];
  taintFlowSegments.forEach(segment => {
    let codeChain = '';
    let baseObject = '';

    // Check if the taint flow starts with document.currentScript
    if (
      segment.length > 0 &&
      segment[segment.length - 1].operation === 'getField' &&
      segment[segment.length - 1].base === '[object HTMLDocument]' &&
      segment[segment.length - 1].arguments[0] === 'currentScript'
    ) {
      baseObject = 'document';
      codeChain = 'currentScript';
    } else {
      // Skip this segment if it doesn't start with document.currentScript
      return;
    }

    for (let i = segment.length - 2; i >= 0; i--) {
      const operation = segment[i];
      
      if (operation.operation === 'getField') {
        codeChain = `${codeChain}.${operation.arguments[0]}`;
      }
    }

    if (baseObject && codeChain) {
      results.push(codeChain);
    }
  });

  return results;
}

// Read the taint flows from the given file path
function readTaintFlows(filepath){
  let taintFlows = [];
  try {
    const data = fs.readFileSync(filepath, 'utf8');
    const rawFlows = JSON.parse(data);

    // Extract the taint operations from the raw data
    for (let i = 0; i < rawFlows.length; i++) {
      const taintFlow = rawFlows[i].taintedValue;
      if (taintFlow.taintInfo) {
        taintFlows.push({ flow: taintFlow.taintInfo.taintPropOperations, sinkReason: rawFlows[i].sinkReason });
      }
    }

    return taintFlows;
  } catch (err) {
    console.error('Error reading or parsing the file:', err);
    return taintFlows;
  }
}

// Find taint flows with different sink locations (iids) and track sink reasons
function findTaintFlowsWithDifferentSinkLocs(taintFlows) {
  let uniqueFlows = {};
  let sinkReasonCount = {};
  
  taintFlows.forEach(({ flow, sinkReason }) => {
    let flowCodeChains = parseTaintTrace(flow);
    
    flowCodeChains.forEach(codeChain => {
      const sinkLoc = flow[flow.length - 1].location;

      if (!uniqueFlows[codeChain]) {
        uniqueFlows[codeChain] = sinkLoc;

        // Ensure the sinkReason is initialized to 0 if not already present
        if (!sinkReasonCount[sinkReason]) {
          sinkReasonCount[sinkReason] = 0;
        }

        sinkReasonCount[sinkReason] += 1;
      } else if (uniqueFlows[codeChain] !== sinkLoc) {
        // Again, ensure the sinkReason is initialized to 0 if not already present
        if (!sinkReasonCount[sinkReason]) {
          sinkReasonCount[sinkReason] = 0;
        }

        sinkReasonCount[sinkReason] += 1;
      }
    });
  });

  return sinkReasonCount;
}


function getUniqueCurrentScriptFlows(filepath) {
  const taintFlows = readTaintFlows(filepath);

  if (taintFlows.length > 0) {
    const sinkReasonCount = findTaintFlowsWithDifferentSinkLocs(taintFlows);

    if (Object.keys(sinkReasonCount).length > 0) {
      console.log(`Taint flows with different sink locations found:`, sinkReasonCount);
    } else {
      console.log('No taint flows with different sink locations found.');
    }

    return sinkReasonCount;
  } else {
    console.log('No taint flows found.');

    return {};
  }
}

/**
 * @description
 * -------------------
 * Go through all the crawl folders and generate the exploit HTML for each.
 * 
 * crawlFolderRootPath
 * -- Domain1
 *    -- Page1  
 *      -- crawler
 *        -- taintflows.json
 *        -- clobberableSourcePool.json
 *    -- Page2
 * 
 * @param {String} crawlFolderRootPath
 */
function main(crawlFolderRootPath) {
  let totalSinkReasons = {};

  // Recursively traverse the crawlFolderRootPath to find all crawler directories
  function traverseDirectory(directoryPath) {
    const filesAndDirs = fs.readdirSync(directoryPath);

    filesAndDirs.forEach(item => {
      const fullPath = path.join(directoryPath, item);
      if (fs.statSync(fullPath).isDirectory()) {
        if (fs.existsSync(path.join(fullPath, 'crawler'))) {
          const taintflowPath = path.join(fullPath, 'crawler', 'taintflows.json');
          if (fs.existsSync(taintflowPath)){
            const sinkReasonCount = getUniqueCurrentScriptFlows(taintflowPath);
            for (let reason in sinkReasonCount) {
              totalSinkReasons[reason] = (totalSinkReasons[reason] || 0) + sinkReasonCount[reason];
            }
          }
          console.log(`[+] Processing directory: ${taintflowPath}`);
        } else {
          traverseDirectory(fullPath);
        }
      }
    });
  }

  traverseDirectory(crawlFolderRootPath);

  console.log(`[+] Total sink reason counts:`, totalSinkReasons);
  return totalSinkReasons;
}


const filepath = '/home/xxxxxxxxxxxx/Desktop/TheHulk/concolic-engine/defined-tasks/run-taint-tracking-trenco/output/TAINT-TRACKING-Trenco-09-02-01-21-Last3K';
main(filepath);
