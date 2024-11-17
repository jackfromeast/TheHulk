/**
 * Description:
 * --------------------------------
 * Post-processer is used to process the raw output folder and summary the results.
 */

const fs = require('fs');
const yaml = require('js-yaml');

function Processer(cralerConfigPath, basedir) {
  this.config = this.readConfigs(cralerConfigPath);
  this.callbacks = this.readCallbacks();
  this.basedir = basedir;

  this.data = {};
}

Processer.prototype.readConfigs = function(cralerConfigPath) {
  const configs_raw = fs.readFileSync(cralerConfigPath, 'utf8');
  return yaml.load(configs_raw);
}

Processer.prototype.readCallbacks = function() {
  let userCallbacks = {
    perPage: [],
    afterAllDomains: []
  };

  this.config.callbacks.POST_PROCESS_CBS.PER_PAGE.forEach(cb => {
    userCallbacks.perPage.push(require(cb.file)[cb.function_name]);
  });
  this.config.callbacks.POST_PROCESS_CBS.AFTER_ALL_DOMAINS.forEach(cb => {
    userCallbacks.afterAllDomains.push(require(cb.file)[cb.function_name]);
  });

  return userCallbacks;
}

Processer.prototype.process = async function () {
  const domains = fs.readdirSync(this.basedir);

  for (const domain of domains) {
    if (!fs.lstatSync(`${this.basedir}/${domain}`).isDirectory()) {
      continue;
    }

    const domainPath = `${this.basedir}/${domain}`;
    const urlHashPaths = fs.readdirSync(domainPath);

    for (const urlHash of urlHashPaths) {
      if (!fs.lstatSync(`${domainPath}/${urlHash}`).isDirectory()) {
        continue;
      }
      const pagePath = `${domainPath}/${urlHash}`;
      const crawlerPath = `${pagePath}/crawler`;

      for (const cb of this.callbacks.perPage) {
        await cb(this.data, crawlerPath, domain, urlHash);
      }
    }
  }

  for (const cb of this.callbacks.afterAllDomains) {
    await cb(this.data, this.basedir);
  }
};

module.exports = Processer;