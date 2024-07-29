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
import { UnaryOpsTaintPropRules } from './operations/unary-ops.js';
import { Utils } from '../utils/util.js';

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
  static makeRuleUnary(operator, condition, modelF, concretize = true, featureDisabled = false) {
    let newRule = (left, iid) => {
      function unaryOpsOrigin(operator, left_c) {
        return UnaryOpsTaintPropRules.UnaryJumpTable[operator](left_c);
      }

      let [result, thrown] = this.runOriginFunc(unaryOpsOrigin, null, [operator, left], true);

      if (!featureDisabled && condition(left)) {
        result = modelF(operator, left, result, iid);
      }

      return result;
    };

    Object.setPrototypeOf(newRule, new RuleFunctionPrototype());
    return newRule;
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
  static makeRuleBinary(operator, condition, modelF, concretize = true, featureDisabled = false) {
    let newRule = (left, right, iid) => {

      function binaryOpsOrigin(operator, left_c, right_c) {
        return BinaryOpsTaintPropRules.BinaryJumpTable[operator](left_c, right_c);
      }

      let [result, thrown] = this.runOriginFunc(binaryOpsOrigin, null, [operator, left, right], true);

      if (!featureDisabled && condition(left, right)) {
        result = modelF(operator, left, right, result, iid);
      }

      return result;
    };

    Object.setPrototypeOf(newRule, new RuleFunctionPrototype());
    return newRule;
  }

  /**
   * @description
   * --------------------------------
   * Creates a new rule.
   * 
   * GetField operation is handle based on the base object type.
   * 
   * The offset should always get concretized.
   * Regarding the base object,
   * 1/ If the base object is tainted and is primitive type (wrapped), 
   *    we concretize the base object and do the taint propagation.
   * 2/ If the base object is tainted and is not primitive type (object, array, etc.),
   *    we don't need to concretize the base object,
   *    but it is also fine to concretize it in one layer.
   * 
   * @TODO
   * --------------------------------
   * Currently, we don't do the taint propagation. No model function will be applied here
   * 
   * @param {Function} f - The function to apply the rule to.
   * @param {Function} condition - The condition check function.
   * @param {Function} model - The modeling function.
   * @returns {Object} The rule object.
   */
  static makeRuleGetField(condition, modelF, concretize = true, featureDisabled = false) {
    let newRule = (base, offset, iid) => {

      function getFieldOriginal(base, offset) {
        return base[offset];
      }

      let [result, thrown] = this.runOriginFunc(getFieldOriginal, null, [base, offset], true);
      
      if (!featureDisabled && condition(base) && !(result instanceof Function)) {
        result = modelF(base, offset, result, iid);
      }

      return result;
    };

    Object.setPrototypeOf(newRule, new RuleFunctionPrototype());
    return newRule;
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
    let newRule = (base, offset, val, iid) => {

      function putFieldOriginal(base, offset, val) {
        base[offset] = val;
      }

      let [result, thrown] = this.runOriginFunc(putFieldOriginal, null, [base, offset, val], concretize);

      if (!featureDisabled && condition(val)) {
        val = modelF(base, offset, val);
      }

      return val;
    };

    Object.setPrototypeOf(newRule, new RuleFunctionPrototype());
    return newRule;
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
   * For the invokeFun rule, it has additional parameter `reflected` which indicates whether the function is reflected.
   * This is because during the makeRule stage, we pass `f` as the real function, e.g. `String.fromCharCode`.
   * However, in the program, when the rule has been called, it might used the reflected function, e.g. `String.fromCharCode.call`.
   * The arguments of the reflected function are different from the real function, that the first argument is the base object.
   * 
   * @param {Function} f - The function to apply the rule to.
   * @param {Function} condition - The condition check function.
   * @param {Function} model - The modeling function.
   * @returns {Object} The rule object.
   */
  static makeRule(f, condition, modelF, concretize = true, featureDisabled = false) {
    let newRule = (base, args, iid, reflected) => {
      let [result, thrown] = this.runOriginFunc(f, base, args, concretize, reflected);

      if (!featureDisabled && condition(base, args, reflected)) {
        result = modelF(base, args, reflected, result, iid);
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
   * Creates a new none-affect rule.
   * 
   * The none-affect rule is rule that will not do anything but run the original function.
   * This means, even the arguments are tainted or the return value is tainted,
   * we don't do anything but call the original function without even concretization.
   * 
   * There are builtins that you want to use this rule, e.g. `Array.prototype.push`. As you
   * don't want to propagate the taint to the return array while you also don't want to lose the
   * taint information of its elements.
   * 
   * @param {Function} f - The function to apply the rule to.
   */
  static makeNoneRule(f) {
    let newrule = (base, args, iid, reflected) => {
      let [result, thrown] = this.runOriginFunc(f, base, args, false, reflected);

      if (thrown) {
        throw thrown;
      }

      return result;
    };
    Object.setPrototypeOf(newrule, new RuleFunctionPrototype());
    return newrule;
  }


  /**
   * @description
   * --------------------------------
   * Executes a function with the provided base and arguments, optionally concretizing them.
   * 
   * @notes
   * --------------------------------
   * We should be careful when using recursive concrete (rconcrete) function. It will make us lose
   * the taint unintentionally. 
   * 
   * For example, for `Array.from([TAINTED("a")]`, we will lose the taint information of the element if 
   * we use rconcrete. But we can pass the taint (make the taint alive) by using concrete + noneAffect model function.
   * 
   * The runOriginFunc will make sure that
   * 1/ The function will be invoked will the concretized base and arguments.
   * 2/ The taint information of base and arguments will be restored after the function invocation.
   * 
   * @param {Function} f - The function to execute.
   * @param {Object} base - The base object for the function call.
   * @param {Arguments} args - The arguments for the function call.
   * @param {boolean} [concretize=true] - Whether to concretize the base and arguments.
   * @returns {Array} An array containing the result of the function and any thrown error.
   */
  static runOriginFunc(f, base, args, concretize=true, reflected) {
    let result, thrown;
    let c_base, c_args;
    let storedTaintInfo = [];

    try {
      if (concretize) {
        [c_base, storedTaintInfo[0]] = base !== null ? TaintHelper.concrete(base) : [base, null];
        c_args = Array.from(args).map((item, index) => {
          let [concreteItem, taintInfo] = TaintHelper.concrete(item);
          storedTaintInfo[index + 1] = taintInfo;
          return concreteItem;
        });
  
        // TODO:
        // There are functions that we need to concretize the arguments recursively
        if (f === JSON.stringify) {
          c_args[0] = TaintHelper.rconcreteHard(c_args[0]);
        }
      } else {
        c_base = base;
        c_args = Array.from(args);
      }
  
      if (reflected === "apply") {
        result = Function.prototype.apply.call(f.apply, c_base, c_args);
      } else if (reflected === "call") {
        result = Function.prototype.apply.call(f.call, c_base, c_args);
      } else {
        result = Function.prototype.apply.call(f, c_base, c_args);
      }
    } catch (e) {
      thrown = e;
    } finally {
      // Restore taint information using createTaintValue
      if (concretize) {
        if (storedTaintInfo[0] && !Utils.isPrimitive(base)) {
          base = TaintHelper.reinstallTaint(c_base, storedTaintInfo[0]);
        }
        Array.from(args).forEach((item, index) => {
          if (storedTaintInfo[index + 1] && !Utils.isPrimitive(item)) {
            args[index] = TaintHelper.reinstallTaint(c_args[index], storedTaintInfo[index + 1]);
          }
        });
      }
    }
  
    return [result, thrown];
  }
}
