import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js'
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js'
import { RuleBuilder } from '../rule-builder.js'
import { TaintPropRules } from '../rules.js'
import { TaintHelper } from '../../taint-helper.js'
import { Utils } from '../../utils/util.js'

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
      // TODO: Some of builtins need to check the arguments while others need to check the base
      // Condition check function: ANY_ARGS_TAINTED OR BASE_TAINTED
      const condition = (base, args, reflected) => {
        return TaintHelper.isAnyArgumentsTainted(args, reflected) || base instanceof TaintValue };
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  fromCharCodeStringModel(base, args, reflected, result, iid) {
    let taintInfo;

    let argsArray = Utils.getArrayLikeArguements(args, reflected);

    for (let arg of argsArray) {
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


  /**
   * Apply the taint propagation rule for the at function.
   * The base must be tainted for the result to be tainted.
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  atStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('at', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  fromCodePointStringModel(base, args, reflected, result, iid) {
    let taintInfo;
    let argsArray = Utils.getArrayLikeArguements(args, reflected);
    for (let arg of argsArray) {
      if (arg instanceof TaintValue) {
        taintInfo = arg.getTaintInfo();
        break;
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('fromCodePoint', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  rawStringModel(base, args, reflected, result, iid) {
    let taintInfo;
    let argsArray = Utils.getArrayLikeArguements(args, reflected);
    for (let arg of argsArray) {
      if (arg instanceof TaintValue) {
        taintInfo = arg.getTaintInfo();
        break;
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('raw', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  charAtStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('charAt', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  charCodeAtStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('charCodeAt', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  codePointAtStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('codePointAt', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  concatStringModel(base, args, reflected, result, iid) {
    let taintInfo = base instanceof TaintValue ? base.getTaintInfo() : null;
    let argsArray = Utils.getArrayLikeArguements(args, reflected);
    if (!taintInfo) {
      for (let arg of argsArray) {
        if (arg instanceof TaintValue) {
          taintInfo = arg.getTaintInfo();
          break;
        }
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('concat', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  endsWithStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('endsWith', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  includesStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('includes', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  indexOfStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('indexOf', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  isWellFormedStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('isWellFormed', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  lastIndexOfStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('lastIndexOf', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  localeCompareStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue || args[0] instanceof TaintValue) {
      const taintInfo = base instanceof TaintValue ? base.getTaintInfo() : args[0].getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('localeCompare', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  matchStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue || args[0] instanceof TaintValue) {
      const taintInfo = base instanceof TaintValue ? base.getTaintInfo() : args[0].getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('match', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  matchAllStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue || args[0] instanceof TaintValue) {
      const taintInfo = base instanceof TaintValue ? base.getTaintInfo() : args[0].getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('matchAll', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  normalizeStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('normalize', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  padEndStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('padEnd', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  padStartStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('padStart', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  repeatStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('repeat', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  replaceStringModel(base, args, reflected, result, iid) {
    let taintInfo = base instanceof TaintValue ? base.getTaintInfo() : null;
    let argsArray = Utils.getArrayLikeArguements(args, reflected);
    if (!taintInfo) {
      for (let arg of argsArray) {
        if (arg instanceof TaintValue) {
          taintInfo = arg.getTaintInfo();
          break;
        }
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('replace', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  replaceAllStringModel(base, args, reflected, result, iid) {
    let taintInfo = base instanceof TaintValue ? base.getTaintInfo() : null;
    let argsArray = Utils.getArrayLikeArguements(args, reflected);
    if (!taintInfo) {
      for (let arg of argsArray) {
        if (arg instanceof TaintValue) {
          taintInfo = arg.getTaintInfo();
          break;
        }
      }
    }
    if (taintInfo) {
      taintInfo.addTaintPropOperation('replaceAll', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  searchStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('search', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  sliceStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('slice', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  splitStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('split', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  startsWithStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('startsWith', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLocaleLowerCaseStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('toLocaleLowerCase', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLocaleUpperCaseStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('toLocaleUpperCase', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLowerCaseStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('toLowerCase', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toStringStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('toString', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toUpperCaseStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('toUpperCase', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toWellFormedStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('toWellFormed', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  trimStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('trim', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  trimEndStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('trimEnd', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  trimStartStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('trimStart', argsArray, iid);
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
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  valueOfStringModel(base, args, reflected, result, iid) {
    if (base instanceof TaintValue) {
      const taintInfo = base.getTaintInfo();
      let argsArray = Utils.getArrayLikeArguements(args, reflected);
      taintInfo.addTaintPropOperation('valueOf', argsArray, iid);
      return new TaintValue(result, taintInfo);
    }
    return result;
  }

}