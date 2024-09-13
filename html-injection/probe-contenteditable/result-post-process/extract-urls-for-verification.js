const fs = require('fs');
const path = require('path');

// Path to your JSON file
const jsonFilePath = path.join("/home/xxxxxxxxxxxx/Desktop/TheHulk/html-injection/probe-contenteditable/results/top-5k-contenteditable-html-elements.json");
// Output CSV file path
const csvFilePath = path.join("/home/xxxxxxxxxxxx/Desktop/TheHulk/html-injection/probe-contenteditable/dataset/top-5k-urls-contenteditable-elements.csv");

// Read JSON data from file
fs.readFile(jsonFilePath, 'utf8', (err, data) => {
    if (err) {
        console.error("Error reading JSON file:", err);
        return;
    }

    // Parse JSON data
    const jsonData = JSON.parse(data);

    // Prepare CSV content
    const csvContent = jsonData.map(item => `${item.id},${item.url}`).join('\n');

    // Write CSV data to file
    fs.writeFile(csvFilePath, csvContent, (err) => {
        if (err) {
            console.error("Error writing CSV file:", err);
            return;
        }
        console.log('CSV file has been generated successfully!');
    });
});
