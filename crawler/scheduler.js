/**
 * This file is used to run the multiple instances of the crawler in parallel.
 * 
 * TODO: Try to use a class to encapsulate the crawler process
 * 
 * Usage:
 * --------------------------------
 * 
 * node scheduler.js --sheduler-config ./config.scheduler.yml --crawler-config ./config.crawler.yml
 * 
 */
const yaml = require('js-yaml');
const fs = require('fs');
const elapsed = require("elapsed-time-logger");
const { spawn } = require('child_process');
const { program } = require('commander');
const { getTimeStamp, readCSVFile } = require('./utils');

const log4js = require('log4js');
log4js.configure({
	appenders: { out: { type: "stdout" } },
	categories: { default: { appenders: ["out"], level: "debug" } },
  });
const logger = log4js.getLogger('Scheduler');
logger.level = 'debug';

program
    .requiredOption('--sheduler-config <path>', 'Configuration file for the scheduler')
    .requiredOption('--crawler-config <path>', 'Configuration file for the crawler');

program.parse(process.argv);
const shedulerConfigFilePath = program.opts().shedulerConfig;
const crawlerConfigFilePath = program.opts().crawlerConfig;

var config = {};
try {
    const configFile = fs.readFileSync(shedulerConfigFilePath, 'utf8');
    config = yaml.load(configFile);  
} catch (error) {
    logger.error('Error reading or parsing config file:', error.message);
}

let completeURL = 0;
let totalURL = 0;
let queue = [];

let dirName = `${config.scheduler.TEST_NAME}-${getTimeStamp()}`;
  
// Function to spawn a new crawler process
function spawnCrawler(url) {
    const crawlerArgs = [
    `--seedurl=${url}`,
    `--maxurls=${config.scheduler.MAX_URL}`,
    `--basedir=${config.scheduler.WORKSPACE}/${dirName}`,
    `--configFile=${crawlerConfigFilePath}`
    ];
    
    const timeoutId = setTimeout(() => {
        logger.error(`Crawler process for ${url} timed out`);
        crawlerProcess.kill();
    }, config.scheduler.TIMEOUT_PER_DOMAIN);

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

    let urls = [];
    if (config.scheduler.MODE !== 'seed'){
        const domains = await readCSVFile(config.scheduler.URL_LIST);
        for (let i = 0; i < domains.length; i++) {
            if (domains[i].startsWith('http://')||domains[i].startsWith('https://')) {
                urls.push(domains[i]);
            }else{
                urls.push('https://'+domains[i]);
            }
        }
    } else {
        urls = [config.scheduler.SEED_URL];
    }

    completeURL = 0;
    totalURL = urls.length;
    queue = [...urls];

    // make sure the output directory exists
    if (!fs.existsSync(`${config.scheduler.WORKSPACE}/${dirName}`)) {
        fs.mkdirSync(`${config.scheduler.WORKSPACE}/${dirName}`, { recursive: true });
    }


    // Start the initial batch of crawlers
    for (let i = 0; i < Math.min(config.scheduler.MAX_WORKER, queue.length); i++) {
        spawnCrawler(queue.shift());
        logger.info(`Current progress: ${completeURL}/${totalURL}`);
        completeURL++;
    }
})();