/**
 * Description:
 * --------------------------------
 * This script is used to start the client-side browser for the concolic execution.
 * Ideally, the proxy server should be setted up before running this script. And all
 * the response in the type of javascript and html should be instrumented by the proxy
 * and ready for the concolic execution.
 * 
 * Usage:
 * --------------------------------
 * node browser.js --conf=config.browser.yml
 */


const fs = require('fs');
const pathModule = require('path');
const yaml = require('js-yaml');
const Visitor = require('../../crawler/src/visitor-playwright.js');
const Logger = require('../../crawler/src/logger.js');
const utils = require('../../crawler/src/utils.js');
const { program } = require('commander');
const { URL } = require('url');

const logger = new Logger('debug', 'Browser');


program
  .requiredOption('--conf <path>', 'Path to the yaml config file', '')

program.parse(process.argv);
const options = program.opts();


(async function Browser() {
  let configs = utils.getConfigs(options.conf);
  let userCallbacks = utils.parseUserCallbacks(configs);

  let url = configs.navigator.INITIAL_URL;
  let dataStorageDirectory = configs.WORKSPACE || pathModule.resolve(__dirname, '../tmp');

  let domain = new URL(url).hostname;

  let basedir = `${dataStorageDirectory}/${domain}`;
  if (!fs.existsSync(basedir)) {
      fs.mkdirSync(basedir, { recursive: true });
  }

  // Add the proxy server for config
  // if (configs.navigator.PROXY_SERVER) {
  //   configs.chrome.CHROME_FLAGS.push(`--proxy-server=${configs.navigator.PROXY_SERVER}:${configs.navigator.PROXY_PORT}`);
  // }

  let visitor = await new Visitor(configs, url, domain, basedir, 1, userCallbacks.before, userCallbacks.action, userCallbacks.after, userCallbacks.post);

  await visitor.visit();
})();





