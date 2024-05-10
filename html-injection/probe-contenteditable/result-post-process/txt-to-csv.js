const fs = require('fs'); // Import the 'fs' module for file system access

function convertTxtToCsv(inputFile, outputFile) {
  const txtData = fs.readFileSync(inputFile, 'utf-8');

  // Split the data into lines, removing empty lines
  const lines = txtData.split(/\r?\n/).filter(line => line.trim() !== '');

  // Counter to keep track of row numbers in the CSV
  let rowCount = 1;

  // Create the CSV content string
  let csvContent = '';

  // Iterate through each line in the TXT file
  lines.forEach(line => {
    // Create a new CSV row with the current row number and remove leading/trailing whitespace
    csvContent += `${rowCount},${line.trim()}\n`;
    rowCount++;
  });

  // Write the CSV content to the output file synchronously
  fs.writeFileSync(outputFile, csvContent, 'utf-8');

  console.log(`TXT file converted to CSV: ${outputFile}`);
}

// Specify the input and output file paths
const inputFile = './dataset/bug-bounty-domain.txt'; // Replace with your actual file name
const outputFile = './dataset/bug-bounty-domain.csv';

// Call the function to perform the conversion
convertTxtToCsv(inputFile, outputFile);