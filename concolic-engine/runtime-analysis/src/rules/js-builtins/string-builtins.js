import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js'
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js'
import { RuleBuilder } from '../rule-builder.js'
import { TaintPropRules } from '../rules.js'
import { TaintHelper } from '../../taint-helper.js'

export class StringBuiltinsTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();
  }

  supportedStringBuiltins = {
    'fromCharCode': [String.fromCharCode, this.fromCharCodeStringModel],
    'at': [String.prototype.at, this.atStringModel],
    'fromCodePoint': [String.fromCodePoint, this.fromCodePointStringModel],
    'raw': [String.raw, this.rawStringModel],
    'charAt': [String.prototype.charAt, this.charAtStringModel],
    'charCodeAt': [String.prototype.charCodeAt, this.charCodeAtStringModel],
    'codePointAt': [String.prototype.codePointAt, this.codePointAtStringModel],
    'concat': [String.prototype.concat, this.concatStringModel],
    'endsWith': [String.prototype.endsWith, this.endsWithStringModel],
    'includes': [String.prototype.includes, this.includesStringModel],
    'indexOf': [String.prototype.indexOf, this.indexOfStringModel],
    'isWellFormed': [String.prototype.isWellFormed, this.isWellFormedStringModel],
    'lastIndexOf': [String.prototype.lastIndexOf, this.lastIndexOfStringModel],
    'localeCompare': [String.prototype.localeCompare, this.localeCompareStringModel],
    'match': [String.prototype.match, this.matchStringModel],
    'matchAll': [String.prototype.matchAll, this.matchAllStringModel],
    'normalize': [String.prototype.normalize, this.normalizeStringModel],
    'padEnd': [String.prototype.padEnd, this.padEndStringModel],
    'padStart': [String.prototype.padStart, this.padStartStringModel],
    'repeat': [String.prototype.repeat, this.repeatStringModel],
    'replace': [String.prototype.replace, this.replaceStringModel],
    'replaceAll': [String.prototype.replaceAll, this.replaceAllStringModel],
    'search': [String.prototype.search, this.searchStringModel],
    'slice': [String.prototype.slice, this.sliceStringModel],
    'split': [String.prototype.split, this.splitStringModel],
    'startsWith': [String.prototype.startsWith, this.startsWithStringModel],
    'toLocaleLowerCase': [String.prototype.toLocaleLowerCase, this.toLocaleLowerCaseStringModel],
    'toLocaleUpperCase': [String.prototype.toLocaleUpperCase, this.toLocaleUpperCaseStringModel],
    'toLowerCase': [String.prototype.toLowerCase, this.toLowerCaseStringModel],
    'toString': [String.prototype.toString, this.toStringStringModel],
    'toUpperCase': [String.prototype.toUpperCase, this.toUpperCaseStringModel],
    'toWellFormed': [String.prototype.toWellFormed, this.toWellFormedStringModel],
    'trim': [String.prototype.trim, this.trimStringModel],
    'trimEnd': [String.prototype.trimEnd, this.trimEndStringModel],
    'trimStart': [String.prototype.trimStart, this.trimStartStringModel],
    'valueOf': [String.prototype.valueOf, this.valueOfStringModel]
  };

  /**
   * @description
   * --------------------------------
   * Build rules for each String builtin functions.
   * Add the rule functions to the ruleDict.
   */
  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedStringBuiltins)) {
      // Condition check function: ANY
      const condition = (base, args) => Array.from(args).filter(arg => arg instanceof TaintValue).length > 0;
      const rule = RuleBuilder.makeRule(fGroup[0], condition, fGroup[1]);
      this.addRule(fGroup[0], rule);
    }
  }

  /**
   * @description
   * --------------------------------
   * Adds a rule to the rule dictionary.
   * 
   * @param {Function} function - The builtin function.
   * @param {Function} rule - The rule function to be added.
   */
  addRule(func, rule) {
    this.ruleDict.push({func, rule});
  }

  /**
   * @description
   * --------------------------------
   * Retrieves a rule for the specified putField operator.
   * 
   * Currently, we propagate all the property lookups all the from a TaintValue
   * Therefore, we return the rule with the key ('all', 'all')
   * 
   * @param {string} operator - The unary operator.
   * @returns {Function|null} The rule function if found, otherwise null.
   */
  getRule(func) {
    const found = this.ruleDict.find(x => x.func === func);
    return found ? found.rule : null;
  }


  /**
   * Apply the taint propagation rule for the fromCharCode function.
   * At least one of the arguments must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  fromCharCodeStringModel(base, args, result, iid) {
    let taintInfo;

    for (let arg of Array.from(args)) {
      if (arg instanceof TaintValue) {
        taintInfo = arg.getTaintInfo();
        break;
      }
    }

    if (taintInfo) {
      taintInfo.addTaintPropOperation('fromCharCode', args, iid);
      return new TaintValue(result, taintInfo);
    } else {
      return result;
    }
  }

  ifAnyArgTainted(args) {
    if (args.toString === "[Object Arguments]"){
      args = Array.from(args);
    }
    return args.some(arg => arg instanceof TaintValue);
  }

  /**
   * Apply the taint propagation rule for the at function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  atStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('at', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the fromCodePoint function.
   * At least one of the arguments must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  fromCodePointStringModel(base, args, result, iid) {
    let taintInfo;
    for (let arg of Array.from(args)) {
      if (arg instanceof TaintValue) {
        taintInfo = arg.getTaintInfo();
        break;
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('fromCodePoint', args, iid);
      return new TaintValue(result, taintInfo);
    } else {
      return result;
    }
  }

  /**
   * Apply the taint propagation rule for the raw function.
   * At least one of the arguments must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  rawStringModel(base, args, result, iid) {
    let taintInfo;
    if (args.length > 0 && args[0] instanceof TaintValue) {
      taintInfo = args[0].getTaintInfo();
    }
    for (let i = 1; i < args.length && !taintInfo; i++) {
      if (args[i] instanceof TaintValue) {
        taintInfo = args[i].getTaintInfo();
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('raw', args, iid);
      return new TaintValue(result, taintInfo);
    } else {
      return result;
    }
  }

  /**
   * Apply the taint propagation rule for the charAt function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  charAtStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('charAt', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the charCodeAt function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  charCodeAtStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('charCodeAt', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the at function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  atStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('at', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the fromCodePoint function.
   * At least one of the arguments must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  fromCodePointStringModel(base, args, result, iid) {
    let taintInfo;
    for (let arg of Array.from(args)) {
      if (arg instanceof TaintValue) {
        taintInfo = arg.getTaintInfo();
        break;
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('fromCodePoint', args, iid);
      return new TaintValue(result, taintInfo);
    } else {
      return result;
    }
  }

  /**
   * Apply the taint propagation rule for the raw function.
   * At least one of the arguments must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  rawStringModel(base, args, result, iid) {
    let taintInfo;
    if (args.length > 0 && args[0] instanceof TaintValue) {
      taintInfo = args[0].getTaintInfo();
    }
    for (let i = 1; i < args.length && !taintInfo; i++) {
      if (args[i] instanceof TaintValue) {
        taintInfo = args[i].getTaintInfo();
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('raw', args, iid);
      return new TaintValue(result, taintInfo);
    } else {
      return result;
    }
  }

  /**
   * Apply the taint propagation rule for the charAt function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  charAtStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('charAt', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the charCodeAt function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  charCodeAtStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('charCodeAt', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the codePointAt function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  codePointAtStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('codePointAt', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the concat function.
   * The base or at least one of the arguments must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  concatStringModel(base, args, result, iid) {
    let taintInfo = base instanceof TaintValue ? base.getTaintInfo() : null;
    if (!taintInfo) {
      for (let arg of Array.from(args)) {
        if (arg instanceof TaintValue) {
          taintInfo = arg.getTaintInfo();
          break;
        }
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('concat', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the endsWith function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  endsWithStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('endsWith', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the includes function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  includesStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('includes', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the indexOf function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  indexOfStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('indexOf', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the isWellFormed function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  isWellFormedStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('isWellFormed', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the lastIndexOf function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  lastIndexOfStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('lastIndexOf', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the localeCompare function.
   * The base or the first argument must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  localeCompareStringModel(base, args, result, iid) {
    if (base instanceof TaintValue || args[0] instanceof TaintValue) {
      const taintInfo = base instanceof TaintValue ? base.getTaintInfo() : args[0].getTaintInfo();
      taintInfo.addTaintPropOperation('localeCompare', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the match function.
   * The base or the first argument must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  matchStringModel(base, args, result, iid) {
    if (base instanceof TaintValue || args[0] instanceof TaintValue) {
      const taintInfo = base instanceof TaintValue ? base.getTaintInfo() : args[0].getTaintInfo();
      taintInfo.addTaintPropOperation('match', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the matchAll function.
   * The base or the first argument must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  matchAllStringModel(base, args, result, iid) {
    if (base instanceof TaintValue || args[0] instanceof TaintValue) {
      const taintInfo = base instanceof TaintValue ? base.getTaintInfo() : args[0].getTaintInfo();
      taintInfo.addTaintPropOperation('matchAll', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the normalize function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  normalizeStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('normalize', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the padEnd function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  padEndStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('padEnd', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the padStart function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  padStartStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('padStart', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the repeat function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  repeatStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('repeat', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the replace function.
   * The base or at least one of the arguments must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  replaceStringModel(base, args, result, iid) {
    let taintInfo = base instanceof TaintValue ? base.getTaintInfo() : null;
    if (!taintInfo) {
      for (let arg of Array.from(args)) {
        if (arg instanceof TaintValue) {
          taintInfo = arg.getTaintInfo();
          break;
        }
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('replace', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the replaceAll function.
   * The base or at least one of the arguments must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  replaceAllStringModel(base, args, result, iid) {
    let taintInfo = base instanceof TaintValue ? base.getTaintInfo() : null;
    if (!taintInfo) {
      for (let arg of args) {
        if (arg instanceof TaintValue) {
          taintInfo = arg.getTaintInfo();
          break;
        }
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('replaceAll', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the search function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  searchStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('search', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the slice function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  sliceStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('slice', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the split function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  splitStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('split', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the startsWith function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  startsWithStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('startsWith', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the toLocaleLowerCase function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLocaleLowerCaseStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('toLocaleLowerCase', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the toLocaleUpperCase function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLocaleUpperCaseStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('toLocaleUpperCase', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the toLowerCase function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLowerCaseStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('toLowerCase', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the toString function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toStringStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('toString', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the toUpperCase function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toUpperCaseStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('toUpperCase', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the toWellFormed function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toWellFormedStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('toWellFormed', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the trim function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  trimStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('trim', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the trimEnd function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  trimEndStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('trimEnd', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the trimStart function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  trimStartStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('trimStart', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

  /**
   * Apply the taint propagation rule for the valueOf function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  valueOfStringModel(base, args, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      taintInfo.addTaintPropOperation('valueOf', args, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }
}