const fs = require('fs');
const path = require('path');

function summarizeCrawlerResults(outputPath) {
  // Object to store summary for each domain
  const domainSummary = {};
  const globalSinkCounts = {};
  const globalSourceCounts = {};
  let globalTaintFlowCount = 0;

  // Traverse the output directory
  const domains = fs.readdirSync(outputPath);

  domains.forEach(domain => {
    const domainPath = path.join(outputPath, domain);

    if (fs.statSync(domainPath).isDirectory()) {
      domainSummary[domain] = {
        total: 0,
        taintflows: []
      };

      const urlhashes = fs.readdirSync(domainPath);
      urlhashes.forEach(urlhash => {
        const urlhashPath = path.join(domainPath, urlhash, "crawler", "taintflows.json");
        if (fs.existsSync(urlhashPath)) {
          try {
            const taintflows = JSON.parse(fs.readFileSync(urlhashPath, 'utf8'));

            taintflows.forEach(taintflow => {
              try {
                domainSummary[domain].total += 1;
                globalTaintFlowCount += 1;

                domainSummary[domain].taintflows.push({
                  source: taintflow.sourceReason,
                  sink: taintflow.sinkReason,
                  value: taintflow.taintedValue.concrete
                });

                // Count the number of taintflows for each different sink globally
                const sink = taintflow.sinkReason;
                if (!globalSinkCounts[sink]) {
                  globalSinkCounts[sink] = 0;
                }
                globalSinkCounts[sink] += 1;

                // Count the number of taintflows for each different source globally
                const source = taintflow.sourceReason;
                if (!globalSourceCounts[source]) {
                  globalSourceCounts[source] = 0;
                }
                globalSourceCounts[source] += 1;
              } catch (error) {
                console.error(`Error parsing taintflow from ${urlhashPath}`);
              }
            });
          } catch (error) {
            console.log(`Error reading JSON from ${urlhashPath}.`);
          }
        }
      });
    }
  });

  return { domainSummary, globalSinkCounts, globalSourceCounts, globalTaintFlowCount };
}

function saveSummaryToJson(summary, outputFile) {
  fs.writeFileSync(outputFile, JSON.stringify(summary, null, 4), 'utf8');
}

const outputDirectory = "/home/jackfromeast/Desktop/TheHulk/concolic-engine/defined-tasks/run-taint-tracking-trenco/output/TAINT-TRACKING-Trenco-TEST-08-05-00-03";
const summaryOutputFile = "./report.json";

const summary = summarizeCrawlerResults(outputDirectory);
saveSummaryToJson(summary, summaryOutputFile);

console.log("Summary report generated successfully.");
