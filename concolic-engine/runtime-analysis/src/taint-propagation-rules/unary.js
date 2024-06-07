import {WrappedValue, _, TaintValue} from '../values/wrapped-values.js'
import {TaintInfo, TaintPropOperation} from '../values/taint-info.js'

/**
 * @description
 * --------------------------------
 * Apply the unary operation taint propagation rule to the result
 * 1/ If the left operator is TaintValue, we wrap the result with the TaintValue
 * 
 * @TODO
 * Currently, we taint propagate all the unary operations
 */
class UnaryOpsTaintPropRules {
  constructor() {
    this.jumpTable = {
      // Add specific unary operations here if needed
    };
  }

  /**
   * Apply the unary operation taint propagation rule to the result.
   * @param {string} ops - The unary operation.
   * @param {*} left - The operand.
   * @param {*} result - The result of the operation.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  applyUnaryOpsTaintPropRule(ops, left, result, iid) {
    let taintInfo;

    if (left instanceof TaintValue) {
      taintInfo = left.getTaintInfo();
    }

    if (taintInfo) {
      taintInfo.addTaintPropOperation(`UnaryOps: ${ops}`, [left], iid);
      return new TaintValue(result, taintInfo);
    } else {
      return result;
    }
  }
}

export { UnaryOpsTaintPropRules };