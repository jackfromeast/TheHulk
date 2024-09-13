const fs = require('fs');
const path = require('path');

function summarizeCrawlerResults(outputPath) {
  // Object to store summary for each domain
  const domainSummary = {};
  const globalTaintFlowSourceCounts = {};
  const globalTaintFlowSinkCounts = {};
  const globalClobberableSourceCounts = {};
  const globalClobberablePoolSourceCounts = {};
  const globalClobberableSinkCounts = {};
  let globalTaintFlowCount = 0;

  // Traverse the output directory
  const domains = fs.readdirSync(outputPath);

  domains.forEach(domain => {
    const domainPath = path.join(outputPath, domain);

    if (fs.statSync(domainPath).isDirectory()) {
      domainSummary[domain] = {
        total: 0,
        taintflows: [],
        clobberableSources: {},
        clobberableSourcePool: {},
        clobberableSinks: {}
      };

      const urlhashes = fs.readdirSync(domainPath);
      urlhashes.forEach(urlhash => {
        const taintflowsPath = path.join(domainPath, urlhash, "crawler", "taintflows.json");
        const clobberableSourcesPath = path.join(domainPath, urlhash, "crawler", "clobberableSources.json");
        const clobberableSourcePoolPath = path.join(domainPath, urlhash, "crawler", "clobberableSourcePool.json");
        const clobberableSinksPath = path.join(domainPath, urlhash, "crawler", "clobberableSinks.json");

        // Process taintflows.json
        if (fs.existsSync(taintflowsPath)) {
          try {
            const taintflows = JSON.parse(fs.readFileSync(taintflowsPath, 'utf8'));

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
                if (!globalTaintFlowSinkCounts[sink]) {
                  globalTaintFlowSinkCounts[sink] = 0;
                }
                globalTaintFlowSinkCounts[sink] += 1;

                // Count the number of taintflows for each different source globally
                const source = taintflow.sourceReason;
                if (!globalTaintFlowSourceCounts[source]) {
                  globalTaintFlowSourceCounts[source] = 0;
                }
                globalTaintFlowSourceCounts[source] += 1;
              } catch (error) {
                console.error(`Error parsing taintflow from ${taintflowsPath}`);
              }
            });
          } catch (error) {
            console.log(`Error reading JSON from ${taintflowsPath}.`);
          }
        }

        // Process clobberableSources.json
        if (fs.existsSync(clobberableSourcesPath)) {
          try {
            const clobberableSources = JSON.parse(fs.readFileSync(clobberableSourcesPath, 'utf8'));

            for (const [key, value] of Object.entries(clobberableSources)) {
              if (!domainSummary[domain].clobberableSources[key]) {
                domainSummary[domain].clobberableSources[key] = 0;
              }
              domainSummary[domain].clobberableSources[key] += value;

              if (!globalClobberableSourceCounts[key]) {
                globalClobberableSourceCounts[key] = 0;
              }
              globalClobberableSourceCounts[key] += value;
            }
          } catch (error) {
            console.log(`Error reading JSON from ${clobberableSourcesPath}.`);
          }
        }

        // Process clobberableSourcePool.json
        if (fs.existsSync(clobberableSourcePoolPath)) {
          try {
            const clobberableSourcePool = JSON.parse(fs.readFileSync(clobberableSourcePoolPath, 'utf8'));

            for (const [key, value] of Object.entries(clobberableSourcePool)) {
              if (!domainSummary[domain].clobberableSourcePool[key]) {
                domainSummary[domain].clobberableSourcePool[key] = 0;
              }
              domainSummary[domain].clobberableSourcePool[key] += value.length;

              if (!globalClobberablePoolSourceCounts[key]) {
                globalClobberablePoolSourceCounts[key] = 0;
              }
              globalClobberablePoolSourceCounts[key] += value.length;
            }
          } catch (error) {
            console.log(`Error reading JSON from ${clobberableSourcePoolPath}.`);
          }
        }

        // Process clobberableSinks.json
        if (fs.existsSync(clobberableSinksPath)) {
          try {
            const clobberableSinks = JSON.parse(fs.readFileSync(clobberableSinksPath, 'utf8'));

            for (const [key, value] of Object.entries(clobberableSinks)) {
              if (!domainSummary[domain].clobberableSinks[key]) {
                domainSummary[domain].clobberableSinks[key] = 0;
              }
              domainSummary[domain].clobberableSinks[key] += value;

              if (!globalClobberableSinkCounts[key]) {
                globalClobberableSinkCounts[key] = 0;
              }
              globalClobberableSinkCounts[key] += value;
            }
          } catch (error) {
            console.log(`Error reading JSON from ${clobberableSinksPath}.`);
          }
        }
      });
    }
  });

  return {
    domainSummary,
    globalTaintFlowSourceCounts,
    globalTaintFlowSinkCounts,
    globalClobberableSourceCounts,
    globalClobberablePoolSourceCounts,
    globalClobberableSinkCounts,
    globalTaintFlowCount
  };
}

function saveSummaryToJson(summary, outputFile) {
  fs.writeFileSync(outputFile, JSON.stringify(summary, null, 4), 'utf8');
}

const outputDirectory = "/home/xxxxxxxxxxxx/Desktop/TheHulk/concolic-engine/defined-tasks/run-taint-tracking-trenco/output/TAINT-TRACKING-Trenco-09-02-12-54-Top500";
const summaryOutputFile = "./report-top500.json";

const summary = summarizeCrawlerResults(outputDirectory);
saveSummaryToJson(summary, summaryOutputFile);

console.log("Summary report generated successfully.");
