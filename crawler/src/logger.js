const log4js = require('log4js');

/**
 * This class is a wrapper around the log4js logger
 * which support logging to the file system at the same time
 */
class Logger {
  constructor(level, name, logFile) {
    this.name = name;
    this.logger = this.initLogger();
  
    if (level) {
    this.logger.level = level;
    }
  
    if (logFile) {
    log4js.configure({
      appenders: {
        out: { type: 'stdout' },
        app: { type: 'file', filename: logFile }
      },
      categories: { default: { appenders: ['out', 'app'], level: 'debug' } }
    });
    }
  }
  
  async initLogger() {
    if (this.name) {
      this.logger = await log4js.getLogger(this.name);
    }else{
      this.logger = await log4js.getLogger();
    }
  }
  
  debug(message) {
    this.logger.debug(message);
  }
  
  info(message) {
    this.logger.info(message);
  }
  
  warn(message) {
    this.logger.warn(message);
  }
  
  error(message) {
    this.logger.error(message);
  }

  close() {
    log4js.shutdown();
  }
}
  
module.exports = Logger;