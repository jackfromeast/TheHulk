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

import { WrappedValue, _, TaintValue } from '../values/wrapped-values.js';
import { DehydratedTaintValue } from '../values/dehydrated-taint-info.js';
import { TaintInfo, TaintPropOperation } from '../values/taint-info.js';
import { BinaryOpsTaintPropRules } from './operations/binary-ops.js';
import { UnaryOpsTaintPropRules } from './operations/unary-ops.js';
import { BaseClobberableBuiltins, ArgumentsClobberableBuiltins } from './rule-builtin-dict.js';
import { BindValueChecker } from './rule-prechecker.js';
import { Utils } from '../utils/util.js';
import { SafeBuiltins } from '../utils/safe-builtins.js';

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

function DynamicRuleFunctionPrototype() {
  this.type = 'DynamicRuleFunction';
  this.installed = false;

  this.install = function(f) {
    this.installed = true;
    return RuleBuilder.makeRule(f, this.condition, this.model, this.concretize, this.featureDisabled);
  }
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
      
      // Before calling the original function,
      // We prepare the arguments for runOriginFunc to make it won't call the user-defined function and surprise us
      // We handle all the implicit bind operations here
      // If operand is object and has user-defined toString or valueOf function
      // See whether the unary operation will call the user-defined function
      // If so, we call the function and replace the left with the result
      // Only valueOf is considered for unary operations
      [left] = BindValueChecker.handleUserDefinedValueOf(left, operator);

      function unaryOpsOrigin(operator, left_c) {
        return UnaryOpsTaintPropRules.UnaryJumpTable[operator](left_c);
      }

      let result, thrown, _, tmp;
      [result, thrown, _, tmp] = this.runOriginFunc(unaryOpsOrigin, null, [operator, left], true);
      [operator, left] = tmp;

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

      [left, right] = BindValueChecker.handleUserDefinedFunctionsForBinaryOps(left, right, operator);

      function binaryOpsOrigin(operator, left_c, right_c) {
        return BinaryOpsTaintPropRules.BinaryJumpTable[operator](left_c, right_c);
      }

      let result, thrown, _, tmp;
      [result, thrown, _, tmp] = this.runOriginFunc(binaryOpsOrigin, null, [operator, left, right], true);
      [operator, left, right] = tmp;

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

      let result, thrown, _, tmp;
      [result, thrown, _, tmp] = this.runOriginFunc(getFieldOriginal, null, [base, offset], true);
      [base, offset] = tmp;

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
      
      let result, thrown, _, tmp;
      [result, thrown, _, tmp] = this.runOriginFunc(putFieldOriginal, null, [base, offset, val], concretize);
      [base, offset, val] = tmp;

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
   * You should only create rule using the this function when you are sure that the function will not clobber the base or arguments.
   * This is because, the runOriginFunc with concretize=true will dehydrate the taint information of the base and arguments
   * If the base or args has changed, the moisturizeTaint will fail in general. However, in the most case, we can still restore the taint
   * information even if base or args has changed if we only dehydrate the taint information with depth=1. This is because the base or args
   * 's outmost layer will not be changed.
   * 
   * @param {Function} f - The function to apply the rule to.
   * @param {Function} condition - The condition check function.
   * @param {Function} model - The modeling function.
   * @returns {Object} The rule object.
   */
  static makeRule(f, condition, modelF, concretize = true, featureDisabled = false) {
    let newRule = (base, args, iid, reflected) => {
      let result, thrown;
      [base, args] = BindValueChecker.handleUserDefinedFunctionsForBuiltins(f, base, args, iid);

      [result, thrown, base, args] = this.runOriginFunc(f, base, args, concretize, reflected);

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
   * There are builtins that you want to use this rule:
   * 1/ The function that will clobber the base or arguments, e.g. `Array.prototype.push`.
   *    Making NoneRule for these functions will not be a problem bacause 
   *    1) it only changes the existing base or arguments and will not generate new values that need to be tainted
   *    2) all of them are object/array/set/etc. builtins, and run the builtins with taint will not cause the error 
   *       as taint is added by __TAINT__ property, not wrapped value.
   *    Even if the function will clobber the base or arguments, in most case, using makeRule and hydrate with depth=1 will be fine,
   *    e.g. Object.assign(obj1, obj2), after the builtin call, we can still restore the taint information of obj1 and obj2.
   * 
   * 
   * 2/ The function that you don't want to propagate the taint to the return value.
   * 
   * @param {Function} f - The function to apply the rule to.
   */
  static makeNoneRule(f) {
    let newrule = (base, args, iid, reflected) => {
      let result, thrown;
      [base, args] = BindValueChecker.handleUserDefinedFunctionsForBuiltins(f, base, args);

      [result, thrown, base, args] = this.runOriginFunc(f, base, args, false, reflected);

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
   * Creates a new rule for the constructor.
   * 
   * @param {Function} f - f is the constructor should be invoked through new keyword.
  */
  static makeRuleForConstructor(constructor, condition, modelF, concretize = true, featureDisabled = false) {
    let newRule = (base, args, iid, reflected) => {
      let result, thrown;
      [base, args] = BindValueChecker.handleUserDefinedFunctionsForBuiltins(constructor, base, args);

      [result, thrown, args] = this.runOriginFuncAsConstructor(constructor, args, concretize);

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
   * Creates a new rule for the constructor.
   * 
   * @param {Function} f - f is the constructor should be invoked through new keyword.
  */
  static makeNoneRuleForConstructor(constructor, condition, modelF, concretize = true, featureDisabled = false) {
    let newRule = (base, args, iid, reflected) => {
      let result, thrown;
      [base, args] = BindValueChecker.handleUserDefinedFunctionsForBuiltins(constructor, base, args);

      [result, thrown, args] = this.runOriginFuncAsConstructor(constructor, args, concretize=false);

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
   * Create a dynamic function rule.
   * 
   * There are cases that we cannot get the reference to the builtin function during the rule creation time.
   * These builtins are implemented as the interface, e.g. TrustedTypes. And user can define their own functions.
   * 
   * To handle these cases, we create a dynamic rule that first return an object with condition and model function.
   * And during the function invoke time, we install the original function and return the real rule function.
   * 
   * @param {*} placeHolder 
   * @param {*} condition 
   * @param {*} modelF 
   * @param {*} concretize 
   * @param {*} featureDisabled 
   */
  static makeDynamicRule(placeHolder, condition, modelF, concretize = true, featureDisabled = false) {
    let dynamicRule = {
      condition: condition,
      model: modelF,
      concretize: concretize,
      featureDisabled: featureDisabled  
    };

    Object.setPrototypeOf(dynamicRule, new DynamicRuleFunctionPrototype());

    return dynamicRule;
  }

  /**
   * @description
   * --------------------------------
   * Executes a function with the provided base and arguments, optionally concretizing them.
   * 
   * The runOriginFunc will make sure that
   * 1/ The function will be invoked with the concretized base and arguments if concretize=true.
   * 2/ The taint information of base and arguments will be restored after the function invocation.
   * 
   * @notes
   * --------------------------------
   * You should only call the function with concretize=true when you are sure that the function will not clobber the base or arguments.
   * We cannot handle the case whether operation will clobber the base or args itself and execute the function with taint will cause the error.
   * For these kind of case, we need to use concretizeHard (I don't see any case so far, reason see MakeNoRule comments).
   * 
   * @param {Function} f - The function to execute.
   * @param {Object} base - The base object for the function call.
   * @param {Arguments} args - The arguments for the function call.
   * @param {boolean} [concretize=true] - Whether to concretize the base and arguments.
   * @returns {Array} An array containing the result of the function and any thrown error.
   */
  static runOriginFunc(f, base, args, concretize=true, reflected) {
    let result, thrown;
    let dehydratedBase, dehydratedArgs;
  
    try {
      if (concretize) {
        // Only when we are sure that f will not change base and args
        // we can dehydrate the taint information with depth > 1
        if (f === JSON.stringify) {
          dehydratedBase = new DehydratedTaintValue(base);
          dehydratedArgs = Array.from(args).map(arg => new DehydratedTaintValue(arg, Infinity));
        } else if (f === Array.prototype.join) {
          dehydratedBase = new DehydratedTaintValue(base, 5);
          dehydratedArgs = Array.from(args).map(arg => new DehydratedTaintValue(arg));
        } else {
          dehydratedBase = new DehydratedTaintValue(base);
          dehydratedArgs = Array.from(args).map(arg => new DehydratedTaintValue(arg));  
        }

        const concreteBase = dehydratedBase.concrete;
        const concreteArgs = dehydratedArgs.map(dt => dt.concrete);

        result = RuleBuilder.callOriginFunc(f, concreteBase, concreteArgs, reflected);
      } else {
        result = RuleBuilder.callOriginFunc(f, base, args, reflected);
      }  
    } catch (e) {
      thrown = e;
    } finally {
      // Restore taint information
      if (concretize) {
        if (dehydratedBase) {
          base = dehydratedBase.moisturizeTaint(dehydratedBase.concrete, dehydratedBase.DehydratedTaintInfo);
        }
        SafeBuiltins.ArrayForEach.call(Array.from(args), (item, index) => {
          if (dehydratedArgs[index]) {
            args[index] = dehydratedArgs[index].moisturizeTaint(dehydratedArgs[index].concrete, dehydratedArgs[index].DehydratedTaintInfo);
          }
        })
      }
    }
  
    return [result, thrown, base, args];
  }

  static runOriginFuncAsConstructor(constructor, args, concretize=true) {
    let result, thrown;
    let dehydratedBase, dehydratedArgs;
  
    try {
      if (concretize) {
        dehydratedArgs = Array.from(args).map(arg => new DehydratedTaintValue(arg));  
        const concreteArgs = dehydratedArgs.map(dt => dt.concrete);
        result = RuleBuilder.callOriginFuncAsConstructor(constructor, concreteArgs);
      } else {
        result = RuleBuilder.callOriginFuncAsConstructor(constructor, args);
      }  
    } catch (e) {
      thrown = e;
    } finally {
      // Restore taint information
      if (concretize) {
        SafeBuiltins.ArrayForEach.call(Array.from(args), (item, index) => {
          if (dehydratedArgs[index]) {
            args[index] = dehydratedArgs[index].moisturizeTaint(dehydratedArgs[index].concrete, dehydratedArgs[index].DehydratedTaintInfo);
          }
        })
      }
    }
  
    return [result, thrown, args];
  }

  /**
   * We assume the c_base and c_args are already concretized
   * 
   * @param {*} f 
   * @param {*} c_base 
   * @param {*} c_args 
   * @param {*} reflected 
   */
  static callOriginFunc(f, c_base, c_args, reflected) {
    let result;
    if (reflected === "apply") {
      result = Function.prototype.apply.call(f.apply, c_base, c_args);
    } else if (reflected === "call") {
      result = Function.prototype.apply.call(f.call, c_base, c_args);
    } else {
      result = Function.prototype.apply.call(f, c_base, c_args);
    }
    return result;
  }


  static callOriginFuncAsConstructor(constructor, args) {
    const argsArray = Array.from(args);
    return new constructor(...argsArray);
  }
}
