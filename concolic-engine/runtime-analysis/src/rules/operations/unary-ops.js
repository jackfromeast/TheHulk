import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js'
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js'
import { RuleBuilder } from '../rule-builder.js'
import { TaintPropRules } from '../rules.js'
import { TaintHelper } from '../../taint-helper.js'

/**
 * @description
 * --------------------------------
 * Class to manage taint propagation rules for unary operations.
 */
export class UnaryOpsTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();
    this.UnaryJumpTable = UnaryOpsTaintPropRules.UnaryJumpTable;
  }

  /**
   * @description
   * --------------------------------
   * Build rules for each unary operator by iterating over UnaryJumpTable.
   * Add the rule functions to the ruleDict.
   */
  buildRules() {
    for (const operator in UnaryOpsTaintPropRules.UnaryJumpTable) {
      const condition = (left) => TaintHelper.isTainted(left);
      const rule = RuleBuilder.makeRuleUnary(operator, condition, this.defaultUnaryModel);
      this.addRule(operator, rule);
    }
  }

  /**
   * @description
   * --------------------------------
   * Adds a rule to the rule dictionary.
   * 
   * @param {string} operator - The unary operator.
   * @param {Function} rule - The rule function to be added.
   */
  addRule(operator, rule) {
    this.ruleDict.push({operator, rule});
  }

  /**
   * @description
   * --------------------------------
   * Retrieves a rule for the specified unary operator.
   * 
   * @param {string} operator - The unary operator.
   * @returns {Function|null} The rule function if found, otherwise null.
   */
  getRule(operator) {
    const found = this.ruleDict.find(x => x.operator === operator);
    return found ? found.rule : null;
  }

  static UnaryJumpTable = {
    "!": function(v) { return !v; },
    "~": function(v) { return ~v; },
    "-": function(v) { return -v; },
    "+": function(v) { return +v; },
    "typeof": function(v) { return typeof v; },
    "void": function(v) { return void v; },
  };

  // TODO: need to handle typeof and void separately
  // typeof and void that has been applied on a tainted value should return a normal value

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
  defaultUnaryModel(operator, left, result, iid) {
    let taintInfo;

    if (TaintHelper.isTainted(left)) {
      taintInfo = TaintHelper.getTaintInfo(left);
    }
    
    if (taintInfo) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, `UnaryOps: ${operator}`, [left], iid);
      result = TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }
}