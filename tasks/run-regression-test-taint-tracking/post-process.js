const fs = require('fs');
const path = require('path');

function findLatestOutputFolder(outputDir, type) {
    const folders = fs.readdirSync(outputDir).filter(f => f.includes(type));
    return folders.sort().reverse()[0];
}

function readJsonFile(filePath) {
    if (fs.existsSync(filePath)) {
        try {
            const content = fs.readFileSync(filePath);
            return JSON.parse(content);
        } catch (error) {
            console.error(`Could not read ${filePath}: ${error}`);
        }
    }
    return null;
}

function compareConsoleLogs(normalLog, analysisLog) {
    const report = [];
    const analysisErrors = analysisLog.filter(log => log.startsWith('[!] ERROR:'));

    analysisErrors.forEach(error => {
        if (!normalLog.includes(error)) {
            report.push(error);
        }
    });

    return report;
}

function isDirectory(path) {
  return fs.statSync(path).isDirectory();
}

function processOutputs() {
  const outputDir = path.join(__dirname, 'output');
  const normalFolder = findLatestOutputFolder(outputDir, 'REGRESSION-TEST-TAINT-TRACKING-NORMAL');
  const analysisFolder = findLatestOutputFolder(outputDir, 'REGRESSION-TEST-TAINT-TRACKING-ANALYSIS');

  if (!normalFolder || !analysisFolder) {
      console.error('Could not find the necessary output folders.');
      return;
  }

  const normalFolderPath = path.join(outputDir, normalFolder);
  const domains = fs.readdirSync(normalFolderPath).filter(domain => isDirectory(path.join(normalFolderPath, domain)));

  const report = {};

  domains.forEach(domain => {
      const domainPath = path.join(outputDir, normalFolder, domain);
      const urlHashes = fs.readdirSync(domainPath).filter(urlHash => isDirectory(path.join(domainPath, urlHash)));

      urlHashes.forEach(urlHash => {
          const normalLogPath = path.join(outputDir, normalFolder, domain, urlHash, 'crawler', 'console-logs.json');
          const analysisLogPath = path.join(outputDir, analysisFolder, domain, urlHash, 'crawler', 'console-logs.json');

          const normalLog = readJsonFile(normalLogPath);
          const analysisLog = readJsonFile(analysisLogPath);

          if (normalLog && analysisLog) {
              const differences = compareConsoleLogs(normalLog, analysisLog);
              if (differences.length > 0) {
                  const key = `${domain}/${urlHash}`;
                  report[key] = differences;
              }
          } else {
              console.error(`Could not read logs for ${domain}/${urlHash}.`);
          }
      });
  });

  const reportPath = path.join(__dirname, 'report.json');
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`Report generated at ${reportPath}`);
}

// Run the main function
processOutputs();
