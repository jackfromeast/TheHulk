const fs = require('fs');

// Path to your JSON file
const jsonFilePath = '/home/xxxxxxxxxxxx/Desktop/TheHulk/html-injection/probe-contenteditable/results/top-5k-contenteditable-html-elements-verifed.json';

// Read JSON data from file
fs.readFile(jsonFilePath, 'utf8', (err, data) => {
    if (err) {
        console.error('Error reading file:', err);
        return;
    }

    // Parse JSON data
    const jsonData = JSON.parse(data);

    // Initialize sets for unique domains and URLs
    const uniqueDomains = new Set();
    const uniqueUrls = new Set();

    // Iterate over each item in the JSON array
    jsonData.forEach(item => {
        uniqueDomains.add(item.domain); // Add domain to set
        uniqueUrls.add(item.url);       // Add URL to set
    });

    // Output the results
    console.log(`Unique domains count: ${uniqueDomains.size}`);
    console.log(`Unique URLs count: ${uniqueUrls.size}`);
});