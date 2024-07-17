const fs = require('fs');
const path = require('path');

function aggregateBuiltinsAPI(outputFolder) {
  const apiCount = {};

  function walkSync(dir) {
    fs.readdirSync(dir).forEach(file => {
      const filePath = path.join(dir, file);
      if (fs.statSync(filePath).isDirectory()) {
        walkSync(filePath);
      } else if (file === 'builtins-api.json') {
        const apiData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        for (const [api, count] of Object.entries(apiData)) {
          if (apiCount[api]) {
            apiCount[api] += count;
          } else {
            apiCount[api] = count;
          }
        }
      }
    });
  }

  walkSync(outputFolder);

  return apiCount;
}

function postSummary(outputFolder, workspaceFolder) {
  const apiCount = aggregateBuiltinsAPI(outputFolder);

  const apiCountArray = Object.entries(apiCount);
  apiCountArray.sort((a, b) => b[1] - a[1]);
  const sortedApiCount = Object.fromEntries(apiCountArray);

  const outputPath = path.join(workspaceFolder, 'builtin-api-ranking.json');
  fs.writeFileSync(outputPath, JSON.stringify(sortedApiCount, null, 2));
}

// Define the paths
const outputFolder = '/home/jackfromeast/Desktop/TheHulk/concolic-engine/defined-tasks/count-most-frequently-used-apis-builtins/output/MOST-FREQUENTLY-USED-APIS-BUILTINS-07-17-14-41'; // Replace with actual path
const workspaceFolder = '/home/jackfromeast/Desktop/TheHulk/concolic-engine/defined-tasks/count-most-frequently-used-apis-builtins'; // Replace with actual path

// Run the script
postSummary(outputFolder, workspaceFolder);