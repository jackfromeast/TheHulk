// import StringBuiltinTaintPropRules from './string.js'
import { BinaryOpsTaintPropRules } from './operations/binary-ops.js'
import { UnaryOpsTaintPropRules } from './operations/unary-ops.js'
import { GetFieldTaintPropRules } from './operations/get-field.js'

export class TaintPropRules {
  constructor() {
    this.getFieldRules = new GetFieldTaintPropRules();
    this.binaryRules = new BinaryOpsTaintPropRules();
    this.unaryRules = new UnaryOpsTaintPropRules();
  }

  /**
   * Adds a rule to the rule dictionary.
   * 
   * @param {Function} fn - The function to which the rule applies.
   * @param {Function} rule - The rule to be applied.
   */
  addRule(fn, rule) {
    this.ruleDict.push({ fn, rule });
  }

  /**
   * Retrieves a rule for the specified function.
   * 
   * @param {Function} fn - The function for which the rule is retrieved.
   * @returns {Function|null} The rule if found, otherwise null.
   */
  getRule(fn) {
    const found = this.ruleDict.find(x => x.fn === fn);
    return found ? found.rule : null;
  }
}


export default TaintPropRules;