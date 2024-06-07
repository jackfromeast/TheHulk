import {WrappedValue, _, TaintValue} from '../values/wrapped-values.js'
import {TaintInfo, TaintPropOperation} from '../values/taint-info.js'

export class StringBuiltinTaintPropRules {
  constructor() {
    this.jumpTable = {
      'fromCharCode': this.fromCharCodeTaintRule
    };
  }

  /**
   * Apply the string built-in operation taint propagation rule to the result.
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {*} - The tainted result or the original result if no taint is present.
   */
  applyStringBuiltinTaintPropRule(f, args, result, iid) {
    const ruleFunction = this.jumpTable[f.name];
    if (ruleFunction) {
      return ruleFunction.call(this, f, args, result, iid);
    } else {
      return result;
    }
  }

  /**
   * Apply the taint propagation rule for the fromCharCode function.
   * If any of the args is tainted, get the first tainted value's taintInfo.
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  static fromCharCodeTaintRule(f, args, result, iid) {
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