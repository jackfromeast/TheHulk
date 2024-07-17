/**
 * This file is used to run the multiple instances of the crawler in parallel.
 * 
 * TODO: Try to use a class to encapsulate the crawler process
 * 
 * Usage:
 * --------------------------------
 * 
 * node scheduler.js --scheduler-config ../config.scheduler.yml --crawler-config ../config.crawler.yml
 * 
 */
const yaml = require('js-yaml');
const fs = require('fs');
const Logger = require('./logger');
const pathModule = require('path');
const { spawn } = require('child_process');
const { program } = require('commander');
const { getTimeStamp, readCSVFile } = require('./utils');
const { info } = require('console');

program
  .requiredOption('--scheduler-config <path>', 'Configuration file for the scheduler')
  .requiredOption('--crawler-config <path>', 'Configuration file for the crawler');

program.parse(process.argv);
const schedulerConfigFilePath = program.opts().schedulerConfig;
const crawlerConfigFilePath = program.opts().crawlerConfig;

var config = {};
var logger = undefined;
try {
  const configFile = fs.readFileSync(schedulerConfigFilePath, 'utf8');
  config = yaml.load(configFile);  
} catch (error) {
  console.log('Error reading or parsing config file:', error.message);
}

let completeURL = 0;
let totalURL = 0;
let queue = [];

let dirName = `${config.scheduler.TEST_NAME}-${getTimeStamp()}`;

// Function to spawn a new crawler process
async function spawnCrawler(url) {
  return new Promise((resolve, reject) => {
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
  
    const crawlerProcess = spawn('node', ['crawler.js', ...crawlerArgs], {
      stdio: ['pipe', 'pipe', 'pipe'] // Ensure streams are properly handled
    });

    crawlerProcess.stdout.on('data', (data) => {
      const output = data.toString().replace(/\n$/, '');
      console.log(`${output}`);
    });

    crawlerProcess.stderr.on('data', (data) => {
      const output = data.toString().replace(/\n$/, '');
      console.error(`${output}`);
    });

    const cleanupAndContinue = () => {
      clearTimeout(timeoutId);
      if (crawlerProcess.stdin) crawlerProcess.stdin.end();
      if (crawlerProcess.stdout) crawlerProcess.stdout.destroy();
      if (crawlerProcess.stderr) crawlerProcess.stderr.destroy();

      if (queue.length > 0) {
        logger.info(`Current progress: ${completeURL}/${totalURL}`);
        spawnCrawler(queue.shift()).then(resolve).catch(reject);
      } else {

        // Ensure there are no remaining handles
        setTimeout(() => {
          console.log('Node is still running for the following reasons:');
          import('why-is-node-running').then((whyIsNodeRunning) => {
            whyIsNodeRunning.default();
            process.exit(0);
          });
        }, 5000);  // Adjust the timeout as necessary
        logger.info(`No more URLs to process. Resolving the crawler promise.`);

        resolve();
      }
    };

    crawlerProcess.on('error', (code) => {
      completeURL++;
      cleanupAndContinue();
    });

    crawlerProcess.on('exit', (code) => {
      completeURL++;
      cleanupAndContinue();
    });
  }); 
}


(async function main() {
  let urls = [];
  if (config.scheduler.MODE !== 'seed') {
    const domains = await readCSVFile(config.scheduler.URL_LIST);
    
    let urlStartPos = config.scheduler.URL_LIST_FROM != 0 ? config.scheduler.URL_LIST_FROM : 0;
    let urlEndPos = config.scheduler.URL_LIST_TO != -1 ? config.scheduler.URL_LIST_TO : domains.length;

    for (let i = urlStartPos; i < urlEndPos; i++) {
      if (domains[i].startsWith('http://') || domains[i].startsWith('https://')) {
        urls.push(domains[i]);
      } else {
        urls.push('https://' + domains[i]);
      }
    }
  } else {
    urls = [config.scheduler.SEED_URL];
  }

  completeURL = 0;
  totalURL = urls.length;
  queue = [...urls];

  // Make sure the output directory exists
  if (!fs.existsSync(`${config.scheduler.WORKSPACE}/${dirName}`)) {
    fs.mkdirSync(`${config.scheduler.WORKSPACE}/${dirName}`, { recursive: true });
  }

  logger = await new Logger('debug', 'Scheduler', pathModule.join(
                            `${config.scheduler.WORKSPACE}/${dirName}`, 'scheduler.log'));

  // Start the initial batch of crawlers
  const initialCrawlers = [];
  for (let i = 0; i < Math.min(config.scheduler.MAX_WORKER, queue.length); i++) {
    initialCrawlers.push(spawnCrawler(queue.shift()));
    logger.info(`Current progress: ${completeURL}/${totalURL}`);
    completeURL++;
  }

  await Promise.all(initialCrawlers);
  logger.info('Done. All crawlers have finished.');

  // Ensure there are no remaining handles
  setTimeout(() => {
    console.log('Node is still running for the following reasons:');
    import('why-is-node-running').then((whyIsNodeRunning) => {
      whyIsNodeRunning.default();
      process.exit(0);
    });
  }, 1000);  // Adjust the timeout as necessary

  process.exit(0);
})();


// Global handler for unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Global handler for uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
  process.exit(1);
});