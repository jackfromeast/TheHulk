/**
 * Description:
 * --------------------------------
 * Our crawler is partially based on the following code: JAW/crawler/crawler.js. 
 * We use puppeteer + chromeDev protocol (CDP) + customed chrome (V8) to crawl the webpages. 
 * This file is modified to add the following features:
 * 
 * 1/ Use the puppeteer + chromeDev protocol (CDP) to driven the chrome browser to visit/interact with the webpages.
 * 2/ Use the customed chrome (V8) to log the DOMC function calls (window.x, document.x, etc.)
 * 3/ Process the raw output and save the results to the log file.
 * 
 *
 * Limitation:
 * --------------------------------
 * 1/ cannot dynamically trigger the events and expend the code coverage
 * 
 * Usage:
 * --------------------------------
 * node crawler.js --seedurl https://hackmd.io/ --configFile /home/jackfromeast/Desktop/TheHulk/crawler/config.yaml --maxurls 1 --browser chrome --basedir /home/jackfromeast/Desktop/TheHulk/tmp/test-webpage
 *
 */

const fs = require('fs');
const pathModule = require('path');
const utils = require('./utils.js');
const yaml = require('js-yaml');
const Visitor = require('./visitor.js');
const Logger = require('./logger.js');
const { program } = require('commander');
const { URL } = require('url');

/**
 * Command line arguments
 */
program
  .requiredOption('--seedurl <url>', 'The starting URL for the crawler')
  .requiredOption('--basedir <path>', 'Base directory for data storage')
  .option('--configFile <path>', 'Path to the yaml config file', '')
  .option('--maxurls <number>', 'Maximum number of URLs per website', 1)
  .option('--browser <name>', 'Browser to use', 'chrome')

program.parse(process.argv);
const options = program.opts();

// directory where the data of the crawling will be saved
const url = options.seedurl;
const dataStorageDirectory = options.basedir || pathModule.resolve(__dirname, '../tmp');
const maxVisitedUrls = options.maxurls; // maximum number of URLs per website by default

function getConfigs() {
  if (!options.configFile) {
    throw new Error('No config file provided');
  }

  const configs_raw = fs.readFileSync(options.configFile, 'utf8');
  return yaml.load(configs_raw);
}

function parseUserCallbacks(configs) {
  var userCallbacks = {};

  try {
    if (configs.callbacks.BEFORE_LOAD_CBS) {
      userCallbacks.before = [];
      for (let cb of configs.callbacks.BEFORE_LOAD_CBS) {
          userCallbacks.before.push(require(cb.file)[cb.function_name]);
      }
    }

    if (configs.callbacks.PAGE_ACTIONS_CBS) {
      userCallbacks.action = [];
      for (let cb of configs.callbacks.PAGE_ACTIONS_CBS) {
          userCallbacks.action.push(require(cb.file)[cb.function_name]);
      }
    }

    if (configs.callbacks.AFTER_LOAD_CBS) {
        userCallbacks.after = [];
        for (let cb of configs.callbacks.AFTER_LOAD_CBS) {
            userCallbacks.after.push(require(cb.file)[cb.function_name]);
        }
    }

    if (configs.callbacks.POST_VISIT_CBS) {
      userCallbacks.post = [];
      for (let cb of configs.callbacks.POST_VISIT_CBS) {
          userCallbacks.post.push(require(cb.file)[cb.function_name]);
      }
    }
  } catch (error) {
      console.error('Failed to load user callbacks:', error);
  }

  return userCallbacks;
}


(async function Crawler() {
    const logger = await new Logger('debug', 'Crawler');
    let configs = getConfigs();
    let userCallbacks = parseUserCallbacks(configs);

    let domain = new URL(url).hostname;

    let basedir = `${dataStorageDirectory}/${domain}`;
    if (!fs.existsSync(basedir)) {
        fs.mkdirSync(basedir, { recursive: true });
    }

    if(utils.directoryExists(url, dataStorageDirectory)){
      logger.warn(`[+] ${url} is already crawled`);
    }

    let visitor = await new Visitor(configs, url, domain, basedir, maxVisitedUrls, userCallbacks.before,
                                    userCallbacks.action, userCallbacks.after, userCallbacks.post);

    await visitor.visit();
})();



