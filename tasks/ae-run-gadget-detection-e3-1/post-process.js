const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function summarizeCrawlerResults(outputPaths) {
  const domainSummary = {};
  let domainNumber = 0;
  let globalTaintFlowCount = 0;
  const vulnerableDomainsSet = new Set();

  outputPaths.forEach(outputPath => {
    const domains = fs.readdirSync(outputPath);

    domains.forEach(domain => {
      const domainPath = path.join(outputPath, domain);
      let flagged = false;

      if (fs.statSync(domainPath).isDirectory()) {
        if (!domainSummary[domain]) {
          domainSummary[domain] = {
            total: 0,
            taintflows: []
          };
        }

        const urlhashes = fs.readdirSync(domainPath);
        urlhashes.forEach(urlhash => {
          const urlhashPath = path.join(domainPath, urlhash, "crawler", "taintflows.json");
          if (fs.existsSync(urlhashPath)) {
            try {
              const taintflows = JSON.parse(fs.readFileSync(urlhashPath, 'utf8'));

              taintflows.forEach(taintflow => {
                try {
                  const propOps = taintflow?.taintedValue?.taintInfo?.taintPropOperations;
                  if (propOps) {
                    domainSummary[domain].total += 1;
                    globalTaintFlowCount += 1;
                    flagged = true;

                    const hash = crypto.createHash('sha256')
                                  .update(taintflow.sourceReason + taintflow.sinkReason)
                                  .digest('hex');

                    const flowEntry = {
                      source: taintflow.sourceReason,
                      sink: taintflow.sinkReason,
                      hash: hash
                    };

                    domainSummary[domain].taintflows.push(flowEntry);
                  }
                } catch (error) {
                  console.error(`Error parsing taintflow from ${urlhashPath}: ${error.message}`);
                }
              });
            } catch (error) {
              console.log(`Error reading JSON from ${urlhashPath}: ${error.message}`);
            }
          }
        });
      }

      if (flagged) {
        domainNumber += 1;
        vulnerableDomainsSet.add(domain);
      }
    });
  });

  return { domainSummary, domainNumber, globalTaintFlowCount, vulnerableDomains: Array.from(vulnerableDomainsSet) };
}

function saveSummaryToJson(summary, outputFile) {
  fs.writeFileSync(outputFile, JSON.stringify(summary, null, 4), 'utf8');
}

function getLatestDirectory(basePath) {
  const directories = fs.readdirSync(basePath)
    .map(file => path.join(basePath, file))
    .filter(filePath => fs.statSync(filePath).isDirectory())
    .sort((a, b) => fs.statSync(b).mtime.getTime() - fs.statSync(a).mtime.getTime());

  return directories.length > 0 ? directories[0] : null;
}

(function main() {
  let outputDirectories;

  if (process.argv.length > 2) {
    outputDirectories = process.argv.slice(2);
  } else {
    const basePath = path.join(__dirname, 'output');
    const latestDirectory = getLatestDirectory(basePath);

    if (!latestDirectory) {
      console.error("No directories found in the specified path.");
      process.exit(1);
    }

    outputDirectories = [latestDirectory];
  }

  const summaryOutputFile = "./report.json";

  const summary = summarizeCrawlerResults(outputDirectories);
  saveSummaryToJson(summary, summaryOutputFile);

  console.log("Summary report and vulnerable domains list generated successfully.");
})();