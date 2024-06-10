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
    'fromCharCode': [String.fromCharCode, this.fromCharCodeStringModel]
  };

  /**
   * @description
   * --------------------------------
   * Build rules for each String builtin functions.
   * Add the rule functions to the ruleDict.
   */
  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedStringBuiltins)) {
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
  static fromCharCodeStringModel(base, args, result, iid) {
    let taintInfo;

    for (let arg of args) {
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

}