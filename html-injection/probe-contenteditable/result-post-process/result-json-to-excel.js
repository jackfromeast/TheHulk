const fs = require("fs");
const xlsx = require("xlsx");

// Load JSON data
const jsonData = JSON.parse(fs.readFileSync("/home/jackfromeast/Desktop/TheHulk/html-injection/probe-contenteditable/results/top-5k-contenteditable-html-elements-verifed.json", { encoding: 'utf8', flag: 'r' }));

// Group by domain
const groupedByDomain = jsonData.reduce((acc, item) => {
    if (!acc[item.domain]) {
        acc[item.domain] = [];
    }
    acc[item.domain].push(item);
    return acc;
}, {});

// Create an array to hold the processed data
const processedData = [];

Object.keys(groupedByDomain).forEach(domain => {
    groupedByDomain[domain].forEach((item, index) => {
        processedData.push({
            domain: index === 0 ? domain : "",
            url: item.url,
            contentEditableNum: item.contentEditableNum
        });
    });
});

// Create a new workbook and add the data
const worksheet = xlsx.utils.json_to_sheet(processedData);
const workbook = xlsx.utils.book_new();
xlsx.utils.book_append_sheet(workbook, worksheet, "Sheet1");

// Write the Excel file
xlsx.writeFile(workbook, "/home/jackfromeast/Desktop/TheHulk/html-injection/probe-contenteditable/results/top-5k-contenteditable-html-elements-verifed.xlsx");

console.log("Excel file has been generated as output_collapsed.xlsx");