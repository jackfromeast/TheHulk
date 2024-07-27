import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';

/**
 * @description
 * --------------------------------
 * Class to manage taint propagation rules for binary operations.
 */
export class BinaryOpsTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();
    this.BinaryJumpTable = BinaryOpsTaintPropRules.BinaryJumpTable;
  }

  /**
   * @description
   * --------------------------------
   * Build rules for each binary operator by iterating over BinaryJumpTable.
   * Add the rule functions to the ruleDict.
   */
  buildRules() {
    for (const operator in BinaryOpsTaintPropRules.BinaryJumpTable) {
      const condition = (left, right) => TaintHelper.isTainted(left) || TaintHelper.isTainted(right);
      const rule = RuleBuilder.makeRuleBinary(operator, condition, this.defaultBinaryModel);
      this.addRule(operator, rule);
    }
  }

  /**
   * @description
   * --------------------------------
   * Adds a rule to the rule dictionary.
   * 
   * @param {string} operator - The binary operator.
   * @param {Function} rule - The rule function to be added.
   */
  addRule(operator, rule) {
    this.ruleDict.push({ operator, rule });
  }

  /**
   * @description
   * --------------------------------
   * Retrieves a rule for the specified binary operator.
   * 
   * @param {string} operator - The binary operator.
   * @returns {Function|null} The rule function if found, otherwise null.
   */
  getRule(operator) {
    const found = this.ruleDict.find(x => x.operator === operator);
    return found ? found.rule : null;
  }


  /**
   * Table of binary operations and their corresponding functions.
   */
  static BinaryJumpTable = {
    "==": function(left, right) { return left == right; },
    "===": function(left, right) { return left === right; },
    "!=": function(left, right) { return left != right; },
    "!==": function(left, right) { return left !== right; },
    "<": function(left, right) { return left < right; },
    ">": function(left, right) { return left > right; },
    "<=": function(left, right) { return left <= right; },
    ">=": function(left, right) { return left >= right; },
    "+": function(left, right) { return left + right; },
    "-": function(left, right) { return left - right; },
    "*": function(left, right) { return left * right; },
    "/": function(left, right) { return left / right; },
    "%": function(left, right) { return left % right; },
    ">>": function(left, right) { return left >> right; },
    "<<": function(left, right) { return left << right; },
    ">>>": function(left, right) { return left >>> right; },
    "&": function(left, right) { return left & right; },
    "&&": function(left, right) { return left && right; },
    "|": function(left, right) { return left | right; },
    "||": function(left, right) { return left || right; },
    "^": function(left, right) { return left ^ right; },
    "instanceof": function(left, right) { return left instanceof right; },
    "in": function(left, right) { return left in right; },
    "delete": function(left, right) { return left[right] && delete left[right] }
  };


  /**
   * @description
   * --------------------------------
   * Rule to propagate taint for binary operations.
   * 
   * @TODO
   * --------------------------------
   * Need to handle the condition that both operands are taint value
   * 
   * @param {*} base 
   * @param {*} offset 
   * @param {*} val 
   */
  defaultBinaryModel(operator, left, right, result, iid) {
    let taintInfo;

    if (TaintHelper.isTainted(left) || TaintHelper.isTainted(right)) {
      if (TaintHelper.isTainted(left)) taintInfo = TaintHelper.getTaintInfo(left);
      if (TaintHelper.isTainted(right)) taintInfo = TaintHelper.getTaintInfo(right);
    }
    
    if (taintInfo) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, `BinaryOps: ${operator}`, [left, right], iid);
      result = TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }

}