import {WrappedValue, _, TaintValue} from '../values/wrapped-values.js'
import {TaintInfo, TaintPropOperation} from '../values/taint-info.js'

/**
 * @description
 * --------------------------------
 * Apply the binary operation taint propagation rule to the result
 * 1/ If left and right are both TaintValue, we currently use the left's taintID
 * 2/ If one of the left or right operator is TaintValue, we wrap the result with the TaintValue
 * 
 * @TODO
 * Currently, we taint propagate all the binary operations
 */
class BinaryOpsTaintPropRules {
  constructor() {
    this.jumpTable = {
      // Add specific binary operations here if needed
    };
  }

  /**
   * Apply the binary operation taint propagation rule to the result.
   * @param {string} ops - The binary operation.
   * @param {*} left - The left operand.
   * @param {*} right - The right operand.
   * @param {*} result - The result of the operation.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  applyBinaryOpsTaintPropRule(ops, left, right, result, iid) {
    let taintInfo;

    if (left instanceof TaintValue && right instanceof TaintValue) {
      taintInfo = left.getTaintInfo();
    } else if (left instanceof TaintValue) {
      taintInfo = left.getTaintInfo();
    } else if (right instanceof TaintValue) {
      taintInfo = right.getTaintInfo();
    }

    if (taintInfo) {
      taintInfo.addTaintPropOperation(`BinaryOps: ${ops}`, [left, right], iid);
      return new TaintValue(result, taintInfo);
    } else {
      return result;
    }
  }
}