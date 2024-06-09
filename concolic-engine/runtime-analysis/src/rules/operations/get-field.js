import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js'
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js'
import { RuleBuilder } from '../rule-builder.js'
import { TaintPropRules } from '../rules.js'
import { TaintHelper } from '../../taint-helper.js'


/**
 * @description
 * --------------------------------
 * Class to manage taint propagation rules for property lookup operations.
 */
export class GetFieldTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();
  }

  /**
   * @description
   * --------------------------------
   * Function to build rules for property lookup operations.
   * 
   * Currently, we propagate all the property lookups all the from a TaintValue
   * However, we can overwrite the rules afterwards
   */
  buildRules() {
    const condition = (base, offset) => base instanceof TaintValue;
    const rule = RuleBuilder.makeRuleGetField(condition);
    this.addRule('default', 'default', rule);
  }

  /**
   * @description
   * --------------------------------
   * Adds a rule to the rule dictionary.
   * 
   * @param {string} operator - The unary operator.
   * @param {Function} rule - The rule function to be added.
   */
  addRule(base, offset, rule) {
    this.ruleDict.push({base, offset, rule});
  }

  /**
   * @description
   * --------------------------------
   * Retrieves a rule for the specified unary operator.
   * 
   * Currently, we propagate all the property lookups all the from a TaintValue
   * Therefore, we return the rule with the key ('all', 'all')
   * 
   * @param {string} operator - The unary operator.
   * @returns {Function|null} The rule function if found, otherwise null.
   */
  getRule(base, offset) {
    const found = this.ruleDict.find(x => x.base === 'default');
    return found ? found.rule : null;
  } 
}