import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js'
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js'
import { RuleBuilder } from '../rule-builder.js'
import { ConditionBuilder } from '../rule-condition.js'
import { TaintPropRules } from '../rules.js'
import { TaintHelper } from '../../taint-helper.js'
import { Utils } from '../../utils/util.js'

export class StringBuiltinsTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();

    if (!Utils) {
      J$$.analysis.logger.error('Utils is not defined');
    }
  }

  supportedStringBuiltins = {
    'String': [String, this.StringConstructorModel, 'FIRST_ARG_TAINTED'],

    // Base or any argument is tainted
    'at': [String.prototype.at, this.atStringModel, 'BASE_TAINTED || ANY_ARGS_TAINTED'],
    'charAt': [String.prototype.charAt, this.charAtStringModel, 'BASE_TAINTED || ANY_ARGS_TAINTED'],
    'replace': [String.prototype.replace, this.replaceStringModel, 'BASE_TAINTED || ANY_ARGS_TAINTED'],
    'replaceAll': [String.prototype.replaceAll, this.replaceAllStringModel, 'BASE_TAINTED || ANY_ARGS_TAINTED'],
    'concat': [String.prototype.concat, this.concatStringModel, 'BASE_TAINTED || ANY_ARGS_TAINTED'],

    // Only base must be tainted
    'charCodeAt': [String.prototype.charCodeAt, this.charCodeAtStringModel, 'BASE_TAINTED'],
    'codePointAt': [String.prototype.codePointAt, this.codePointAtStringModel, 'BASE_TAINTED'],
    'localeCompare': [String.prototype.localeCompare, this.localeCompareStringModel, 'BASE_TAINTED'],
    'match': [String.prototype.match, this.matchStringModel, 'BASE_TAINTED'],
    'matchAll': [String.prototype.matchAll, this.matchAllStringModel, 'BASE_TAINTED'],
    'replace': [String.prototype.replace, this.replaceStringModel, 'BASE_TAINTED'],
    'replaceAll': [String.prototype.replaceAll, this.replaceAllStringModel, 'BASE_TAINTED'],
    'search': [String.prototype.search, this.searchStringModel, 'BASE_TAINTED'],
    'slice': [String.prototype.slice, this.sliceStringModel, 'BASE_TAINTED'],
    'substr':  [String.prototype.substr, this.substrStringModel, 'BASE_TAINTED'],
    'substring': [String.prototype.substring, this.substringStringModel, 'BASE_TAINTED'],
    'split': [String.prototype.split, this.splitStringModel, 'BASE_TAINTED'],
    'startsWith': [String.prototype.startsWith, this.startsWithStringModel, 'BASE_TAINTED'],
    'toLocaleLowerCase': [String.prototype.toLocaleLowerCase, this.toLocaleLowerCaseStringModel, 'BASE_TAINTED'],
    'toLocaleUpperCase': [String.prototype.toLocaleUpperCase, this.toLocaleUpperCaseStringModel, 'BASE_TAINTED'],
    'toLowerCase': [String.prototype.toLowerCase, this.toLowerCaseStringModel, 'BASE_TAINTED'],
    'toString': [String.prototype.toString, this.toStringStringModel, 'BASE_TAINTED'],
    'toUpperCase': [String.prototype.toUpperCase, this.toUpperCaseStringModel, 'BASE_TAINTED'],
    'toWellFormed': [String.prototype.toWellFormed, this.toWellFormedStringModel, 'BASE_TAINTED'],
    'endsWith': [String.prototype.endsWith, this.endsWithStringModel, 'BASE_TAINTED'],
    'includes': [String.prototype.includes, this.includesStringModel, 'BASE_TAINTED'],
    'indexOf': [String.prototype.indexOf, this.indexOfStringModel, 'BASE_TAINTED'],
    'isWellFormed': [String.prototype.isWellFormed, this.isWellFormedStringModel, 'BASE_TAINTED'],
    'lastIndexOf': [String.prototype.lastIndexOf, this.lastIndexOfStringModel, 'BASE_TAINTED'],
    'trim': [String.prototype.trim, this.trimStringModel, 'BASE_TAINTED'],
    'trimEnd': [String.prototype.trimEnd, this.trimEndStringModel, 'BASE_TAINTED'],
    'trimStart': [String.prototype.trimStart, this.trimStartStringModel, 'BASE_TAINTED'],
    'valueOf': [String.prototype.valueOf, this.valueOfStringModel, 'BASE_TAINTED'],
    'normalize': [String.prototype.normalize, this.normalizeStringModel, 'BASE_TAINTED'],
    'padEnd': [String.prototype.padEnd, this.padEndStringModel, 'BASE_TAINTED'],
    'padStart': [String.prototype.padStart, this.padStartStringModel, 'BASE_TAINTED'],
    'repeat': [String.prototype.repeat, this.repeatStringModel, 'BASE_TAINTED'],

    // Arguments only
    // 'String': [String, this.StringModel, 'FIRST_ARGS_TAINTED'],
    'raw': [String.raw, this.rawStringModel, 'ANY_ARGS_TAINTED'],
    'fromCharCode': [String.fromCharCode, this.fromCharCodeStringModel, 'ANY_ARGS_TAINTED'],
    'fromCodePoint': [String.fromCodePoint, this.fromCodePointStringModel, 'ANY_ARGS_TAINTED'],
  };

  /**
   * @description
   * --------------------------------
   * Build rules for each String builtin functions.
   * Add the rule functions to the ruleDict.
   */
  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedStringBuiltins)) {
      // Make two rules for the String constructor
      if (fName === 'String') {
        const condition = ConditionBuilder.makeCondition(fGroup[2]);
        const rule = RuleBuilder.makeRuleForConstructor(fGroup[0], condition, fGroup[1]);
        this.addRule(fGroup[0], rule, true);
      }

      const condition = ConditionBuilder.makeCondition(fGroup[2]);
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
  addRule(func, rule, isConstructor=false) {
    if (isConstructor) {
      this.ruleDict.push({constructor: func, rule: rule});
    } else {
      this.ruleDict.push({func, rule});
    }
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

  getRuleForConstructor(func) {
    const found = this.ruleDict.find(x => x.constructor === func);
    return found ? found.rule : null;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the String constructor.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: FIRST_ARG_TAINTED
   * 
   * @usage
   * --------------------------------
   * new String(value)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * new String(TAINTED("Hello"))
   * -> TAINTED("Hello")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  StringConstructorModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(args[0]);
    let taintInfoPairs = [];
    taintInfo ? taintInfoPairs.push(['arg0', taintInfo]) : null;

    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:constructor', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the fromCharCode function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: ANY_ARGS_TAINTED
   * 
   * @usage
   * --------------------------------
   * String.fromCharCode(num1, num2, ..., numN)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * String.fromCharCode(TAINTED(65), 66)
   * -> TAINTED("AB")
   * 
   * TYPE-2:
   * String.fromCharCode.call(this, T([65,65,66]))
   * -> TAINTED("AAB")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  fromCharCodeStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];

    // TYPE-2: String.fromCharCode.call(this, T([65,65,66]))
    if (TaintHelper.isTainted(args[1])) {
      let taintInfo = TaintHelper.getTaintInfo(args[1]);
      taintInfo ? taintInfoPairs.push([`arg_1`, taintInfo]): null;
    }

    for (let i = 0; i < argsArray.length; i++) {
      let taintInfo = TaintHelper.getTaintInfo(argsArray[i]);
      taintInfo ? taintInfoPairs.push([`arg${i}`, taintInfo]): null;
    }

    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:fromCharCode', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }


  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the at function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED or ANY_ARGS_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.at(index)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("abcdef").at(2)
   * -> TAINTED("c")
   * 
   * TYPE-2:
   * "abcdef".at(TAINTED(2))
   * -> TAINTED("c")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  atStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];

    let taintInfo = TaintHelper.getTaintInfo(base);
    taintInfo ? taintInfoPairs.push(['base', taintInfo]) : null;

    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:at', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the fromCodePoint function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: ANY_ARGS_TAINTED
   * 
   * @usage
   * --------------------------------
   * String.fromCodePoint(num1, num2, ..., numN)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * String.fromCodePoint(TAINTED(65), 66)
   * -> TAINTED("AB")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  fromCodePointStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];

    // TYPE-2: String.fromCodePoint.call(this, T([65,65,66]))
    if (TaintHelper.isTainted(args[1])) {
      let taintInfo = TaintHelper.getTaintInfo(args[1]);
      taintInfo ? taintInfoPairs.push([`arg_1`, taintInfo]): null;
    }

    for (let i = 0; i < argsArray.length; i++) {
      let taintInfo = TaintHelper.getTaintInfo(argsArray[i]);
      taintInfo ? taintInfoPairs.push([`arg${i}`, taintInfo]): null;
    }

    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:fromCodePoint', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the raw function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: ANY_ARGS_TAINTED
   * 
   * @usage
   * --------------------------------
   * String.raw(template, ...substitutions)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED(String.raw`Hello ${'world'}`)
   * -> TAINTED("Hello world")
   * 
   * TYPE-2:
   * String.raw`Hello ${TAINTED('world')}`
   * -> TAINTED("Hello world")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  rawStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];

    for (let i = 0; i < argsArray.length; i++) {
      let taintInfo = TaintHelper.getTaintInfo(argsArray[i]);
      taintInfo ? taintInfoPairs.push([`arg${i}`, taintInfo]): null;
    }

    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:raw', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the charAt function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED or ANY_ARGS_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.charAt(index)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("abcdef").charAt(2)
   * -> TAINTED("c")
   * 
   * TYPE-2:
   * "abcdef".charAt(TAINTED(2))
   * -> TAINTED("c")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  charAtStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];

    let taintInfo = TaintHelper.getTaintInfo(base);
    taintInfo ? taintInfoPairs.push(['base', taintInfo]) : null;

    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:charAt', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the charCodeAt function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.charCodeAt(index)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("abcdef").charCodeAt(2)
   * -> TAINTED(99)
   * 
   * TYPE-2:
   * "abcdef".charCodeAt(2)
   * -> 99
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  charCodeAtStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:charCodeAt', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the codePointAt function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.codePointAt(pos)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("abc").codePointAt(1)
   * -> TAINTED(98)
   * 
   * TYPE-2:
   * "abc".codePointAt(1)
   * -> 98
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  codePointAtStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:codePointAt', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the concat function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED or ANY_ARGS_TAINTED
   * 
   * @usage
   * --------------------------------
   * concat(str1, str2, ..., strN)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("a").concat("b", "c")
   * -> TAINTED("a,b,c")
   * 
   * TYPE-2:
   * "a".concat(TAINTED("b"), "c")
   * -> TAINTED("a,b,c")
   * 
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  concatStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];
  
    let baseTaintInfo = TaintHelper.getTaintInfo(base);
    if (baseTaintInfo) taintInfoPairs.push(['base', baseTaintInfo]);
  
    for (let i = 0; i < argsArray.length; i++) {
      let argTaintInfo = TaintHelper.getTaintInfo(argsArray[i]);
      if (argTaintInfo) taintInfoPairs.push([`arg${i}`, argTaintInfo]);
    }
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:concat', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the endsWith function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.endsWith(searchString, [position])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").endsWith("world")
   * -> TAINTED(true)
   * 
   * TYPE-2:
   * "Hello world".endsWith(TAINTED("world"))
   * -> true
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  endsWithStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:endsWith', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the includes function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.includes(searchString, [position])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").includes("world")
   * -> TAINTED(true)
   * 
   * TYPE-2:
   * "Hello world".includes(TAINTED("world"))
   * -> true
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  includesStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:includes', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the indexOf function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.indexOf(searchValue, [fromIndex])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").indexOf("world")
   * -> TAINTED(6)
   * 
   * TYPE-2:
   * "Hello world".indexOf(TAINTED("world"))
   * -> 6
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  indexOfStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:indexOf', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the isWellFormed function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.isWellFormed()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").isWellFormed()
   * -> TAINTED(true)
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  isWellFormedStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:isWellFormed', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the lastIndexOf function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.lastIndexOf(searchValue, [fromIndex])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").lastIndexOf("world")
   * -> TAINTED(6)
   * 
   * TYPE-2:
   * "Hello world".lastIndexOf(TAINTED("world"))
   * -> 6
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  lastIndexOfStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:lastIndexOf', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the localeCompare function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED or FIRST_ARG_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.localeCompare(compareString, locales, options)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("a").localeCompare("b")
   * -> TAINTED(-1)
   * 
   * TYPE-2:
   * "a".localeCompare(TAINTED("b"))
   * -> TAINTED(-1)
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  localeCompareStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];
  
    let baseTaintInfo = TaintHelper.getTaintInfo(base);
    if (baseTaintInfo) taintInfoPairs.push(['base', baseTaintInfo]);
  
    let argTaintInfo = TaintHelper.getTaintInfo(argsArray[0]);
    if (argTaintInfo) taintInfoPairs.push(['arg0', argTaintInfo]);
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:localeCompare', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the match function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED or FIRST_ARG_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.match(regexp)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("hello world").match(/world/)
   * -> TAINTED(["world"])
   * 
   * TYPE-2:
   * "hello world".match(TAINTED(/world/))
   * -> TAINTED(["world"])
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  matchStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];
  
    let baseTaintInfo = TaintHelper.getTaintInfo(base);
    if (baseTaintInfo) taintInfoPairs.push(['base', baseTaintInfo]);
  
    let argTaintInfo = TaintHelper.getTaintInfo(argsArray[0]);
    if (argTaintInfo) taintInfoPairs.push(['arg0', argTaintInfo]);
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:match', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the matchAll function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED or FIRST_ARG_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.matchAll(regexp)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("hello world").matchAll(/world/)
   * -> TAINTED(["world"])
   * 
   * TYPE-2:
   * "hello world".matchAll(TAINTED(/world/))
   * -> TAINTED(["world"])
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  matchAllStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];
  
    let baseTaintInfo = TaintHelper.getTaintInfo(base);
    if (baseTaintInfo) taintInfoPairs.push(['base', baseTaintInfo]);
  
    let argTaintInfo = TaintHelper.getTaintInfo(argsArray[0]);
    if (argTaintInfo) taintInfoPairs.push(['arg0', argTaintInfo]);
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:matchAll', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the normalize function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.normalize([form])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").normalize()
   * -> TAINTED("Hello world")
   * 
   * TYPE-2:
   * "Hello world".normalize()
   * -> "Hello world"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  normalizeStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:normalize', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the padEnd function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.padEnd(targetLength, [padString])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("abc").padEnd(6)
   * -> TAINTED("abc   ")
   * 
   * TYPE-2:
   * "abc".padEnd(6, TAINTED(" "))
   * -> "abc   "
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  padEndStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:padEnd', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the padStart function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.padStart(targetLength, [padString])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("abc").padStart(6)
   * -> TAINTED("   abc")
   * 
   * TYPE-2:
   * "abc".padStart(6, TAINTED(" "))
   * -> "   abc"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  padStartStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];

    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:padStart', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the repeat function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.repeat(count)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("abc").repeat(2)
   * -> TAINTED("abcabc")
   * 
   * TYPE-2:
   * "abc".repeat(TAINTED(2))
   * -> "abcabc"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  repeatStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:repeat', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the replace function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED or ANY_ARGS_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.replace(regexp|substr, newSubstr|function)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").replace("world", "universe")
   * -> TAINTED("Hello universe")
   * 
   * TYPE-2:
   * "Hello world".replace(TAINTED("world"), "universe")
   * -> TAINTED("Hello universe")
   * 
   * TYPE-3:
   * "Hello world".replace("world", TAINTED("universe"))
   * -> TAINTED("Hello universe")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  replaceStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];
  
    let baseTaintInfo = TaintHelper.getTaintInfo(base);
    if (baseTaintInfo) taintInfoPairs.push(['base', baseTaintInfo]);
  
    for (let i = 0; i < argsArray.length; i++) {
      let argTaintInfo = TaintHelper.getTaintInfo(argsArray[i]);
      if (argTaintInfo) taintInfoPairs.push([`arg${i}`, argTaintInfo]);
    }
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:replace', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }


  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the replaceAll function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED or ANY_ARGS_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.replaceAll(regexp|substr, newSubstr|function)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world world").replaceAll("world", "universe")
   * -> TAINTED("Hello universe universe")
   * 
   * TYPE-2:
   * "Hello world world".replaceAll(TAINTED("world"), "universe")
   * -> TAINTED("Hello universe universe")
   * 
   * TYPE-3:
   * "Hello world world".replaceAll("world", TAINTED("universe"))
   * -> TAINTED("Hello universe universe")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  replaceAllStringModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];

    let baseTaintInfo = TaintHelper.getTaintInfo(base);
    if (baseTaintInfo) taintInfoPairs.push(['base', baseTaintInfo]);

    for (let i = 0; i < argsArray.length; i++) {
      let argTaintInfo = TaintHelper.getTaintInfo(argsArray[i]);
      if (argTaintInfo) taintInfoPairs.push([`arg${i}`, argTaintInfo]);
    }

    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:replaceAll', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the search function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.search(regexp)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").search(/world/)
   * -> TAINTED(6)
   * 
   * TYPE-2:
   * "Hello world".search(TAINTED(/world/))
   * -> 6
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  searchStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:search', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the slice function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.slice(beginIndex, [endIndex])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").slice(0, 5)
   * -> TAINTED("Hello")
   * 
   * TYPE-2:
   * "Hello world".slice(TAINTED(0), 5)
   * -> "Hello"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  sliceStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:slice', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the slice function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * substr(start)
   * substr(start, length)
   * 
   * @example
   * --------------------------------
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  substrStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:substr', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the slice function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * substring(start)
   * substring(start, length)
   * 
   * @example
   * --------------------------------
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  substringStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:substring', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }
  

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the split function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.split([separator], [limit])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").split(" ")
   * -> TAINTED(["Hello", "world"])
   * 
   * TYPE-2:
   * "Hello world".split(TAINTED(" "), 1)
   * -> ["Hello"]
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  splitStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:split', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the startsWith function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.startsWith(searchString, [position])
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").startsWith("Hello")
   * -> TAINTED(true)
   * 
   * TYPE-2:
   * "Hello world".startsWith(TAINTED("Hello"))
   * -> true
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  startsWithStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:startsWith', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the toLocaleLowerCase function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.toLocaleLowerCase()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello World").toLocaleLowerCase()
   * -> TAINTED("hello world")
   * 
   * TYPE-2:
   * "Hello World".toLocaleLowerCase()
   * -> "hello world"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLocaleLowerCaseStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:toLocaleLowerCase', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the toLocaleUpperCase function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.toLocaleUpperCase()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello World").toLocaleUpperCase()
   * -> TAINTED("HELLO WORLD")
   * 
   * TYPE-2:
   * "Hello World".toLocaleUpperCase()
   * -> "HELLO WORLD"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLocaleUpperCaseStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:toLocaleUpperCase', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the toLowerCase function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.toLowerCase()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello World").toLowerCase()
   * -> TAINTED("hello world")
   * 
   * TYPE-2:
   * "Hello World".toLowerCase()
   * -> "hello world"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLowerCaseStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:toLowerCase', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the toString function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.toString()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello World").toString()
   * -> TAINTED("Hello World")
   * 
   * TYPE-2:
   * "Hello World".toString()
   * -> "Hello World"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toStringStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:toString', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the toUpperCase function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.toUpperCase()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello World").toUpperCase()
   * -> TAINTED("HELLO WORLD")
   * 
   * TYPE-2:
   * "Hello World".toUpperCase()
   * -> "HELLO WORLD"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toUpperCaseStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let argsArray = Utils.getArrayLikeArguments(args, reflected);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:toUpperCase', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the toWellFormed function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.toWellFormed()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello World").toWellFormed()
   * -> TAINTED("Hello World")
   * 
   * TYPE-2:
   * "Hello World".toWellFormed()
   * -> "Hello World"
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toWellFormedStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:toWellFormed', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the trim function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.trim()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("  Hello world  ").trim()
   * -> TAINTED("Hello world")
   * 
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  trimStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:trim', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the trimEnd function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.trimEnd()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("  Hello world  ").trimEnd()
   * -> TAINTED("  Hello world")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  trimEndStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:trimEnd', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the trimStart function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.trimStart()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("  Hello world  ").trimStart()
   * -> TAINTED("Hello world  ")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  trimStartStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:trimStart', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }
  

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the valueOf function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * str.valueOf()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED("Hello world").valueOf()
   * -> TAINTED("Hello world")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  valueOfStringModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);
    let taintInfoPairs = taintInfo ? [['base', taintInfo]] : [];
  
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:valueOf', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }
}