// JALANGI DO NOT INSTRUMENT
/**
 * @description:
 * --------------------------------
 * This class implements a logger to replace the log4js module which
 * is not compatible with webpack bundle.
 */
export class Logger {
  constructor(config={level: 'info', name: 'TheHulk'}) {
    this.name = config.name;
    this.level = config.level;
    this.logUnsupportBuiltin = config.logUnsupportBuiltin;
    this.logTaintInstall = config.logTaintInstall;
    this.logClobberableSource = config.logClobberableSource;
    this.logClobberableSink = config.logClobberableSink;

    this.exposeToPlaywright = config.exposeToPlaywright;

    this.levels = ['debug', 'info', 'warn', 'error'];
    this.levelIndex = this.levels.indexOf(this.level);
  }

  log(level, message) {
    const levelIndex = this.levels.indexOf(level);
    if (levelIndex >= this.levelIndex) {
      const logMessage = `[${new Date().toISOString()}]-[${this.name}]-[${level.toUpperCase()}]-${message}`;
      switch (level) {
        case 'debug':
          console.log(logMessage);
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

  debug(...args) {
    this.log('debug', args.map(Logger.safeToString).join(' '));
  }

  info(...args) {
    this.log('info', args.map(Logger.safeToString).join(' '));
  }

  warn(...args) {
    this.log('warn', args.map(Logger.safeToString).join(' '));
  }

  error(...args) {
    this.log('error', args.map(Logger.safeToString).join(' '));
  }

  reportVulnFlow(sourceReason, sinkReason, taintedValue) {
    console.log("%c[TheHulk] Found a dangerous flow from %s to %s: \n%o",
                'background: #222; color: #bada55',            
                sourceReason, sinkReason, taintedValue);
  }

  reportVerifedFlow(sinkReason, payload, url) {
    console.log("%c[TheHulk] Verified a dangerous flow to %s: %o",
                'background: #222; color: #bada55',            
                sinkReason, payload);
  }

  /**
   * We assume the f has been checked to be a native function already
   * @param {Function} f 
   * @param {*} base 
   */
  reportUnsupportedBuiltin(f, base) {
    if (!this.logUnsupportBuiltin) {
      return;
    }

    let fullName = "unknown";

    // If base is a object, e.g. "hello"
    if (base && base.constructor && base.constructor.name) {
      fullName = `${base.constructor.name}.${f.name}`;
    }
    // If base is a function, e.g. String()
    if (base && typeof base === "function") {
      fullName = `${base.name}.${f.name}`;
    }

    this.debug(`Unsupported builtin ${fullName}`);
  }

  reportTaintInstall(value) {
    if (!this.logTaintInstall) {
      return;
    }

    this.debug("Taint installed to:", value);
  }

  static safeToString(value) {
    try {
      return value != null? value.toString() : 'null';
    } catch (e) {
      return '[Unable to convert to string]';
    }
  }
}