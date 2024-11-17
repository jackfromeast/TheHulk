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

                domainSummary[domain].taintflows.push(taintflow);

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

  return { domainSummary};
}

function saveSummaryToJson(summary, outputFile) {
  fs.writeFileSync(outputFile, JSON.stringify(summary, null, 4), 'utf8');
}

const outputDirectory = "/home/xxxxxxxxxxxx/Desktop/TheHulk/concolic-engine/defined-tasks/run-verifier/output/VERIFIER-TEST-09-02-00-32";
const summaryOutputFile = "./report.json";

const summary = summarizeCrawlerResults(outputDirectory);
saveSummaryToJson(summary, summaryOutputFile);

console.log("Summary report generated successfully.");
