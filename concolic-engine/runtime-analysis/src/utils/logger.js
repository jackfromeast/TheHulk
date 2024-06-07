// JALANGI DO NOT INSTRUMENT
/**
 * @description:
 * --------------------------------
 * This class implements a logger to replace the log4js module which
 * is not compatible with webpack bundle.
 */
export class Logger {
  constructor(level = 'info', name = 'default') {
    this.name = name;
    this.level = level;
    this.levels = ['debug', 'info', 'warn', 'error'];
    this.levelIndex = this.levels.indexOf(level);
  }

  log(level, message) {
    const levelIndex = this.levels.indexOf(level);
    if (levelIndex >= this.levelIndex) {
      const logMessage = `[${new Date().toISOString()}] [${level.toUpperCase()}] [${this.name}] ${message}`;
      switch (level) {
        case 'debug':
          console.log(`\x1b[34m%s\x1b[0m`, logMessage);
          break;
        case 'info':
          console.log(`\x1b[32m%s\x1b[0m`, logMessage);
          break;
        case 'warn':
          console.log(`\x1b[33m%s\x1b[0m`, logMessage);
          break;
        case 'error':
          console.log(`\x1b[31m%s\x1b[0m`, logMessage);
          break;
      }
    }
  }

  debug(message) {
    this.log('debug', message);
  }

  info(message) {
    this.log('info', message);
  }

  warn(message) {
    this.log('warn', message);
  }

  error(message) {
    this.log('error', message);
  }

  alertSink(msg) {
    console.log("\x1b[31m%s\x1b[0m", `[!] ${msg}`);
  }
}