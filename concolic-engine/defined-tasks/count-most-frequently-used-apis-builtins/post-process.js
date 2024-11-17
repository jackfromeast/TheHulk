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
        let apiData = {};
        try{
          apiData = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        }
        catch(e){
          console.log('Error parsing file: ' + filePath);
        }
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

function collectRawData(outputFolder) {
  const apiCount = aggregateBuiltinsAPI(outputFolder);

  const apiCountArray = Object.entries(apiCount);
  apiCountArray.sort((a, b) => b[1] - a[1]);
  const sortedApiCount = Object.fromEntries(apiCountArray);

  return sortedApiCount
}

function summary(outputFolder) {
  const rawBuiltins = collectRawData(outputFolder);
  const groupedBuiltins = {};

  for (const [key, value] of Object.entries(rawBuiltins)) {
    // Barrier-1: We only consider the apis that have been called more than 100 times in Top 500
    if (value < 100) { continue; }

    // Barrier-2: No bound function
    if (key.includes('bound')) { continue; }

    const [baseObject, method] = key.split('.');
    if (!groupedBuiltins[baseObject]) {
      groupedBuiltins[baseObject] = {};
    }
    groupedBuiltins[baseObject][method] = value;
  }

  return { rawBuiltins, groupedBuiltins };
}

function save(workspaceFolder, rawBuiltins, groupedBuiltins) {
  const rawOutputPath = path.join(workspaceFolder, 'sorted-raw-api-count.json');
  fs.writeFileSync(rawOutputPath, JSON.stringify(rawBuiltins, null, 2));

  const groupedOutputPath = path.join(workspaceFolder, 'grouped-api-count.json');
  fs.writeFileSync(groupedOutputPath, JSON.stringify(groupedBuiltins, null, 2));
}

(function main(){
  const outputFolder = '/home/xxxxxxxxxxxx/Desktop/TheHulk/concolic-engine/defined-tasks/count-most-frequently-used-apis-builtins/output/MOST-FREQUENTLY-USED-APIS-BUILTINS-07-24-21-14';
  const workspaceFolder = '/home/xxxxxxxxxxxx/Desktop/TheHulk/concolic-engine/defined-tasks/count-most-frequently-used-apis-builtins/summarized-output'; // Replace with actual path

  const { rawBuiltins, groupedBuiltins } = summary(outputFolder);
  save(workspaceFolder, rawBuiltins, groupedBuiltins);
})()