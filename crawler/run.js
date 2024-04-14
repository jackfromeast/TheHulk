/**
 * This file is used to run the multiple instances of the crawler in parallel.
 * 
 * Usage:
 * 
 * node run.js --max-worker 1 --urllist /home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/domain.csv --basedir /home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler/ --maxurls 1 --chromeExecutablePath=/home/jackfromeast/Desktop/SafeLookup/tools/Chromes/chrome-clobber/src/out/x64.debug.clobber/chrome --chromeFlags --enable-blink-features=RecordDOMClobberingSitesAny,RecordDOMAccessAPIAny+--js-flags=\"--trace-document-lookup\" --browser=chrome --dirname test-crawler --callbacksFile ./callbacks/trace-clobberable-callbacks.js
 * 
 * node run.js --max-worker 32 --urllist tools/JAW/input/tranco_Y3JG_unique.csv --basedir /home/jackfromeast/Desktop/SafeLookup/tmp/test-crawler-top5k-normal-chrome --maxurls 1 --chromeExecutablePath=/home/jackfromeast/Desktop/SafeLookup/tools/Chromes/chrome-clobber/src/out/x64.debug.clobber/chrome --chromeFlags --enable-blink-features=RecordDOMClobberingSitesAny,RecordDOMAccessAPIAny&--js-flags=\"--allow-natives-syntax\" --browser=chrome --dirname test-crawler
 * 
 * urllist.csv format:
 *  1,google.com
    2,facebook.com
    3,amazonaws.com
    4,microsoft.com
    5,apple.com
    6,googleapis.com
    7,akamaiedge.net
    8,youtube.com
    9,a-msedge.net
    10,twitter.com
 */


const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const fastcsv = require('fast-csv');
const { program } = require('commander');
const { log } = require('console');
const elapsed = require("elapsed-time-logger");

const log4js = require('log4js');
log4js.configure({
	appenders: { out: { type: "stdout" } },
	categories: { default: { appenders: ["out"], level: "debug" } },
  });
const logger = log4js.getLogger('Scheduler');
logger.level = 'debug';

program
    .requiredOption('--max-worker <number>', 'Maximum number of concurrent workers')
    .requiredOption('--urllist <path>', 'Path to the URL list file')
    .requiredOption('--basedir <path>', 'Base directory for the output')
    .requiredOption('--maxurls <number>', 'Maximum number of URLs for each worker')
    // .requiredOption('--chromeExecutablePath <path>', 'Path to the Chrome executable')
    .option('--callbacksFile <path>', 'Path to the JavaScript file containing callback functions')
    // .option('--chromeFlags <flags>', 'Chrome flags separated by commas', '--js-flags="--allow-natives-syntax"')
    .option('--browser <name>', 'Browser to use, defaults to chrome', 'chrome')
    // .option('--headless', 'Run in headless mode', true)
    .option('--dirname <dirname>', 'description for the crawling task', "top-5k")
    .option('--timeoutPerCrawler <number>', 'Timeout for each crawler in seconds', 1800000); // 30 minutes

program.parse(process.argv);

const options = program.opts();
let completeURL = 0;
let totalURL = 0;
let queue = [];

let dirName = `${options.dirname}-${getTimeStamp()}`;

function getTimeStamp() {
    const now = new Date();

    // Extract year, month, day, hour, and minute
    const month = now.getMonth() + 1; // Note: Months are 0-indexed, so +1 to get the correct month
    const day = now.getDate();
    const hour = now.getHours();
    const minute = now.getMinutes();

    // Format the date and time string
    return `${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}-${hour.toString().padStart(2, '0')}-${minute.toString().padStart(2, '0')}`;
}

// Function to read CSV file and return a promise that resolves to an array of URLs
function readCSVFile(filePath) {
    const urls = [];
    return new Promise((resolve, reject) => {
      fs.createReadStream(path.resolve(filePath))
        .pipe(fastcsv.parse({ headers: false }))
        .on('error', error => reject(error))
        .on('data', row => urls.push(row[1])) // Assuming the URL is in the second column
        .on('end', rowCount => resolve(urls));
    });
  }
  
// Function to spawn a new crawler process
function spawnCrawler(url) {
    const crawlerArgs = [
    `--seedurl=${url}`,
    `--maxurls=${options.maxurls}`,
    `--basedir=${options.basedir}/${dirName}`,
    `--configFile=${options.configFile ? options.configFile : './config.yaml'}`
    ];
    
    const timeoutId = setTimeout(() => {
        logger.error(`Crawler process for ${url} timed out`);
        crawlerProcess.kill();
    }, options.timeoutPerCrawler);

    // const crawlerProcess = spawn('node', ['--inspect-brk=9229', 'crawler.js', ...crawlerArgs]);
    const crawlerProcess = spawn('node', ['crawler.js', ...crawlerArgs]);

    crawlerProcess.stdout.on('data', (data) => {
        const output = data.toString().replace(/\n$/, '');
        console.log(`${output}`);
    });

    crawlerProcess.stderr.on('data', (data) => {
        const output = data.toString().replace(/\n$/, '');
        console.log(`${output}`);
    });

    crawlerProcess.on('exit', (code) => {
        // console.log(`Crawler process exited with code ${code}`);
        // If there are more URLs to crawl, spawn the next crawler
        clearTimeout(timeoutId);
        if (queue.length > 0) {
            spawnCrawler(queue.shift());
            logger.info(`Current progress: ${completeURL}/${totalURL}`);
            completeURL++;
        }
    });
}

(async function main() {

    const domains = await readCSVFile(options.urllist);
    const urls = [];
    for (let i = 0; i < domains.length; i++) {
        if (domains[i].startsWith('http://')||domains[i].startsWith('https://')) {
           urls.push(domains[i]);
        }else{
           urls.push('https://'+domains[i]);
        }
    }

    completeURL = 0;
    totalURL = urls.length;
    queue = [...urls];

    // make sure the output directory exists
    if (!fs.existsSync(`${options.basedir}/${dirName}`)) {
        fs.mkdirSync(`${options.basedir}/${dirName}`, { recursive: true });
    }

    const globalTimer = elapsed.start('global_crawling_timer');

    // Start the initial batch of crawlers
    for (let i = 0; i < Math.min(options.maxWorker, queue.length); i++) {
        spawnCrawler(queue.shift());
        logger.info(`Current progress: ${completeURL}/${totalURL}`);
        completeURL++;
    }
})();