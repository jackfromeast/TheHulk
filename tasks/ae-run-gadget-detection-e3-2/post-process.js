const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function summarizeCrawlerResults(outputPaths) {
  const domainSummary = {};
  let domainCount = 0;
  let globalTaintFlowCount = 0;
  const vulnerableDomainsSet = new Set();

  outputPaths.forEach(outputPath => {
    const domains = fs.readdirSync(outputPath);

    domains.forEach(domain => {
      const domainPath = path.join(outputPath, domain);
      let flagged = false;

      if (fs.statSync(domainPath).isDirectory()) {
        domainSummary[domain] = {
          total: 0,
          taintflows: new Set()
        };

        const urlhashes = fs.readdirSync(domainPath);
        urlhashes.forEach(urlhash => {
          const urlhashPath = path.join(domainPath, urlhash, "crawler", "taintflows.json");
          if (fs.existsSync(urlhashPath)) {
            try {
              const taintflows = JSON.parse(fs.readFileSync(urlhashPath, 'utf8'));

              taintflows.forEach(taintflow => {
                try {
                  const sink = taintflow.sink ? String(taintflow.sink) : '';

                  const hash = crypto.createHash('sha256')
                    .update(sink)
                    .digest('hex');

                  if (!domainSummary[domain].taintflows.has(hash)) {
                    domainSummary[domain].taintflows.add(hash);
                    globalTaintFlowCount += 1;
                    flagged = true;
                  }
                } catch (error) {
                  console.error(`Error processing taintflow from ${urlhashPath}: ${error.message}`);
                }
              });
            } catch (error) {
              console.log(`Error reading JSON from ${urlhashPath}: ${error.message}`);
            }
          }
        });

        // Convert Set to array for final summary
        domainSummary[domain].taintflows = Array.from(domainSummary[domain].taintflows);
        domainSummary[domain].total = domainSummary[domain].taintflows.length;
      }

      if (flagged) {
        domainCount += 1;
        vulnerableDomainsSet.add(domain);
      }
    });
  });

  return { domainSummary, domainCount, globalTaintFlowCount, vulnerableDomains: Array.from(vulnerableDomainsSet) };
}

function saveSummaryToJson(summary, outputFile) {
  fs.writeFileSync(outputFile, JSON.stringify(summary, null, 4), 'utf8');
}

function saveVulnerableDomains(vulnerableDomains, outputFile) {
  const domainList = vulnerableDomains.map((domain, index) => `${index + 1},${domain}`).join('\n');
  fs.writeFileSync(outputFile, domainList, 'utf8');
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