/**
 * Description:
 * --------------------------------
 * This script is used to merge the crawler result of multiple probes.
 * 
 * 1/ Read the contentEditableElements.json files from the directories
 * 2/ Filter out the contenteditable elements with same domain and url hash
 * 3/ Merge the contenteditable elements
 * 4/ Sort the elements based on the domain ranking in the Trenco top 5k list
 * 4/ Save the merged contenteditable elements to the file
 * 
 * Usage:
 * --------------------------------
 * 
 * node merge-crawler-result.js
 * 
 */

const fs = require('fs');
const path = require('path');
const { parse } = require('csv-parse');


const outputFile = "/home/xxxxxxxxxxxx/Desktop/TheHulk/html-injection/probe-contenteditable/results/bug-bounty-contenteditable-html-elements.json";
const csvFilePath = "/home/xxxxxxxxxxxx/Desktop/TheHulk/html-injection/probe-contenteditable/dataset/tranco-5k-05-03.csv";
const filePaths = [
  "/home/xxxxxxxxxxxx/Desktop/TheHulk/output/probe-contenteditable-bug-bounty/probe-contenteditable-bug-bounty-05-07-19-24-1/contentEditableEleSiteMap.json",
  "/home/xxxxxxxxxxxx/Desktop/TheHulk/output/probe-contenteditable-bug-bounty/probe-contenteditable-bug-bounty-05-07-21-01-2/contentEditableEleSiteMap.json"
]
// const filePaths = [
//   "/home/xxxxxxxxxxxx/Desktop/TheHulk/output/probe-contenteditable-top5k/probe-contenteditable-top5k-200-60-05-05-11-31-2/contentEditableEleSiteMap.json",
//   "/home/xxxxxxxxxxxx/Desktop/TheHulk/output/probe-contenteditable-top5k/probe-contenteditable-top5k-200-60-05-04-20-35-1/contentEditableEleSiteMap.json",
//   "/home/xxxxxxxxxxxx/Desktop/TheHulk/output/probe-contenteditable-top5k/probe-contenteditable-top5k-200-60-2145--05-05-19-23-3/contentEditableEleSiteMap.json",
//   "/home/xxxxxxxxxxxx/Desktop/TheHulk/output/probe-contenteditable-top5k/probe-contenteditable-top5k-200-60-2145--05-06-23-30-4/contentEditableEleSiteMap.json",
//   "/home/xxxxxxxxxxxx/Desktop/TheHulk/output/probe-contenteditable-top5k/probe-contenteditable-top5k-200-60-2145--05-06-23-30-5/contentEditableEleSiteMap.json"
// ]

function readCsvFile(filePath, callback) {
  const domainRanking = {};
  fs.createReadStream(filePath)
      .pipe(parse({
          skip_empty_lines: true,
          trim: true,  // Automatically trim values
          from_line: 2  // If your CSV has a header line, start from line 2
      }))
      .on('data', (row) => {
          const rank = parseInt(row[0], 10);  // First column is rank
          const domain = row[1];  // Second column is domain
          domainRanking[domain] = rank;
      })
      .on('end', () => {
          callback(domainRanking);
      })
      .on('error', (err) => {
          console.error('Error reading CSV file:', err);
      });
}

const readJsonFile = (filePath) => {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
};

const writeJsonFile = (filePath, data) => {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 4));
};

const consolidateJsonFiles = (filePaths, domainRanking) => {
  const allData = [];
  const seen = new Set();

  filePaths.forEach(filePath => {
      const data = readJsonFile(filePath);
      data.forEach(item => {
          const key = `${item.domain}-${item.hash}`;
          if (!seen.has(key)) {
              seen.add(key);
              allData.push(item);
          }
      });
  });

  // Sort by domain rank
  allData.sort((a, b) => {
      const rankA = domainRanking[a.domain] || Infinity; // Default to a large number if not found
      const rankB = domainRanking[b.domain] || Infinity;
      return rankA - rankB;
  });

  // Renumber IDs
  allData.forEach((item, index) => {
      item.id = index + 1;
  });

  return allData;
};

// Initiate CSV reading and processing
readCsvFile(csvFilePath, (domainRanking) => {
  const consolidatedData = consolidateJsonFiles(filePaths, domainRanking);

  // Count the number of unique domains
  const uniqueDomains = new Set();
  consolidatedData.forEach(item => uniqueDomains.add(item.domain));
  console.log(`Number of unique domains: ${uniqueDomains.size}`);

  // Count the total number of unique URL in the consolidated data
  console.log(`Total number of unique URL : ${consolidatedData.length}`);

  writeJsonFile(outputFile, consolidatedData);
  console.log("JSON files have been consolidated, sorted by domain, duplicates removed, and IDs renumbered.");
});