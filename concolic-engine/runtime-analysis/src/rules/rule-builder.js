/**
 * RuleBuilder class
 * 
 * @description
 * --------------------------------
 * A helper class for building rules for concolic execution.
 * 
 * What is a rule?
 * --------------------------------
 * Rule is a function that is used to introduce/update/delete the symbolic information
 * associated with the arguments and results of operation (e.g., function call, binary operation, etc.), 
 * based on the given context conditions.
 * 
 * Therefore, a rule consists of the following components:
 * 1/ Built-in function or Operator, 
 * 2/ Condition check function (verifies context conditions),
 * 3/ Modeling function
 * 
 * All the rules should be built from the RuleBuilder class, while the modeling function
 * are coming from the corresponding rule classes.
 *
 */

import { TaintHelper } from '../taint-helper.js';
import { WrappedValue, _, TaintValue } from '../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../values/taint-info.js';
import { BinaryOpsTaintPropRules } from './operations/binary-ops.js';

/**
 * @description
 * --------------------------------
 * The RuleFunctionPrototype constructor.
 * 
 * All the rule functions should inherit this prototype for type checking.
 * That said, all the rule function's prototype should be the prototype of 
 * RuleFunctionPrototype function.
 */
function RuleFunctionPrototype() {
  this.type = 'RuleFunction';
}

export class RuleBuilder {

  /**
   * @description
   * --------------------------------
   * Given the unary operator name, condition check function
   * makeRule returns a function (rule) that intake the operand (left),
   * and applies the rule to the function call.
   * 
   * Currently, we generally adopt the following rule:
   * If the left operator is TaintValue, we wrap the result with the TaintValue
   * 
   * @param {string} operator - The unary operator.
   * @param {Function} condition - The condition check function.
   * @param {boolean} [concretize=true] - Whether to concretize the operand.
   * @param {boolean} [featureDisabled=false] - Whether the feature is disabled.
   * @returns {Function} The rule function.
   */
  static makeRuleUnary(operator, condition, concretize = true, featureDisabled = false) {
    return (left, iid) => {
      let result = UnaryJumpTable[operator](TaintHelper.concrete(left));

      if (!featureDisabled && condition(left)) {
        let taintInfo;
        taintInfo = left.getTaintInfo();
        taintInfo.addTaintPropOperation(`UnaryOps: ${ops}`, [left], iid);
        result = new TaintValue(result, taintInfo);
      }

      return result;
    };
  }

  /**
   * @description
   * --------------------------------
   * Given the binary operator name, condition check function
   * makeRule returns a function (rule) that takes the operands (left, right),
   * and applies the rule to the function call.
   * 
   * Currently, we generally adopt the following rule:
   * If either operand is a TaintValue, we wrap the result with the TaintValue
   * 
   * @param {string} operator - The binary operator.
   * @param {Function} condition - The condition check function.
   * @param {boolean} [concretize=true] - Whether to concretize the operands.
   * @param {boolean} [featureDisabled=false] - Whether the feature is disabled.
   * @returns {Function} The rule function.
   */
  static makeRuleBinary(operator, condition, concretize = true, featureDisabled = false) {
    return (left, right, iid) => {
      let leftValue = TaintHelper.concrete(left);
      let rightValue = TaintHelper.concrete(right);
      let result = BinaryOpsTaintPropRules.BinaryJumpTable[operator](leftValue, rightValue);

      if (!featureDisabled && condition(left, right)) {
        let taintInfo;

        if (left instanceof TaintValue || right instanceof TaintValue) {
          taintInfo = new TaintInfo();
          if (left instanceof TaintValue) taintInfo = left.getTaintInfo();
          if (right instanceof TaintValue) taintInfo = right.getTaintInfo();

          /**
           * @TODO
           * Need to handle the condition that both operands are taint value
           */
          
          taintInfo.addTaintPropOperation(`BinaryOps: ${operator}`, [left, right], iid);
          result = new TaintValue(result, taintInfo);
        }
      }

      return result;
    };
  }

  /**
   * @description
   * --------------------------------
   * Creates a new rule.
   * 
   * Given the （base object, offset name), condition check function,
   * makeRule returns a function (rule) that intake the base object and arguments of the function call,
   * and applies the rule to the function call.
   * 
   * @param {Function} f - The function to apply the rule to.
   * @param {Function} condition - The condition check function.
   * @param {Function} model - The modeling function.
   * @returns {Object} The rule object.
   */
    static makeRuleGetField(condition, concretize = true, featureDisabled = false) {
      return (base, offset, iid) => {
        let base_c = TaintHelper.concrete(base);
        let offset_c = TaintHelper.concrete(offset);
        let result = base_c[offset_c];
        
        // We don't taint function
        if (!featureDisabled && condition(base) &&
            !(result instanceof Function)) {
          let taintInfo;
          taintInfo = new TaintInfo(iid, base.taintInfo.taintSource.reason);
          taintInfo.addTaintPropOperation('getField', [base, offset], iid);
          result = new TaintValue(result, taintInfo);
        }
  
        return result;
      };
  }

  /**
   * @description
   * --------------------------------
   * Creates a new rule.
   * 
   * The makeRule function for the putField operation is *different* from the other operations.
   * Because, for other operations, in the makeRule stage, we handle the behavior of the concrete field.
   * But for the putField operation, the concrete field is handled in the modeling function.
   * Because, it depends on whether the base object is a DOM Node or not.
   * 
   * @param {Function} f - The function to apply the rule to.
   * @param {Function} condition - The condition check function.
   * @param {Function} model - The modeling function.
   * @returns {Object} The rule object.
   */
    static makeRulePutField(condition, modelF, concretize = true, featureDisabled = false) {
      return (base, offset, val, iid) => {

        if (!featureDisabled && condition(val)) {
          val = modelF(base, offset, val);
        }

        return val;
      };
  }



  /**
   * @description
   * --------------------------------
   * Creates a new rule.
   * 
   * Given the function, condition check function, and modeling function,
   * makeRule returns a function (rule) that intake the base object and arguments of the function call,
   * and applies the rule to the function call.
   * 
   * @param {Function} f - The function to apply the rule to.
   * @param {Function} condition - The condition check function.
   * @param {Function} model - The modeling function.
   * @returns {Object} The rule object.
   */
  static makeRule(f, condition, modelF, concretize = true, featureDisabled = false) {
    let newRule = (base, args, iid) => {
      let [result, thrown] = this.runOriginFunc(f, base, args, concretize);

      if (!featureDisabled && condition(base, args)) {
          result = modelF(base, args, result, iid);
      }

      if (thrown) {
          throw thrown;
      }

      return result;
    };
    Object.setPrototypeOf(newRule, new RuleFunctionPrototype());
    return newRule;
  }

  /**
   * @description
   * --------------------------------
   * Executes a function with the provided base and arguments, optionally concretizing them.
   * 
   * @param {Function} f - The function to execute.
   * @param {Object} base - The base object for the function call.
   * @param {Arguments} args - The arguments for the function call.
   * @param {boolean} [concretize=true] - Whether to concretize the base and arguments.
   * @returns {Array} An array containing the result of the function and any thrown error.
   */
  static runOriginFunc(f, base, args, concretize = true) {
    let result, thrown;

    try {
      const c_base = concretize && base !== null ? TaintHelper.concrete(base) : base;
      const c_args = Array.from(args).map(arg => TaintHelper.concrete(arg));

      // result = f.apply(c_base, c_args);
      result = Function.prototype.apply.call(f, c_base, c_args);
    } catch (e) {
      thrown = e;
    }

    return [result, thrown];
  }

}
