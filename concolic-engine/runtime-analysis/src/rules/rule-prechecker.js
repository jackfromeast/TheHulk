import { Utils } from '../utils/util.js';
import { TaintHelper } from '../taint-helper.js';
/**
 * @description
 * --------------------------------
 * Performing precheck for user-defined bind functions for each rule.
 * 
 * When executing the original operation (e.g., built-in functions or a binary/unary/get/set operation) on stripped values (the first step),
 * it might implicitly call a user-defined function (e.g., toString, getter, or setter).
 * This can lead to several issues if the bind function returns a tainted value:
 * 1/ it might directly apply to the original operation without stripping, making the value taint-aware, or
 * 2/ it could alter the program logic. The following two cases illustrate these problems.
 * For more details, see the documentation: https://github.com/jackfromeast/TheHulk/wiki/Concolic-Execution-Bind-User-Functions
 * 
 * Perchecker will handle these user-defined functions and ensure the runOriginalFun won't arrive at any user-defined functions.
 */
export class BindValueChecker {

  static handleUserDefinedValueOf(left, operator) {
    if (left && Utils.realTypeOf(left) === 'object') {
      if (Utils.isUserDefinedFunction(left["valueOf"]) && ["+", "-", "~", "!"].includes(operator)) {
        left = left.valueOf();
      }
    }
    return left;
  }
  
  static handleUserDefinedToString(left, operator) {
    if (left && Utils.realTypeOf(left) === 'object') {
      if (Utils.isUserDefinedFunction(left["toString"]) && operator === "+") {
        left = left.toString();
      }
    }
    return left;
  }
  
  static handleUserDefinedFunctionsForBinaryOps(left, right, operator) {
    left = BindValueChecker.handleUserDefinedValueOf(left, operator);
    left = BindValueChecker.handleUserDefinedToString(left, operator);
  
    right = BindValueChecker.handleUserDefinedValueOf(right, operator);
    right = BindValueChecker.handleUserDefinedToString(right, operator);
  
    return [left, right];
  }

  static handleUserDefinedFunctionsForBuiltins(f, base, args) {
    // Before calling the original function,
    // We prepare the arguments for runOriginFunc to make it won't call the user-defined function and surprise us
    // We handle all the implicit bind operations here
    // For the array.filter, we need to make sure the return value of the first f needs to be concretized
    if (f === Array.prototype.filter) {
      const original_f = args[0];
      function wrapped_f (element) {
        return TaintHelper.concreteWrappedOnly(original_f.call(this, element));
      }
      args[0] = wrapped_f;
    }
    else if (f === String.prototype.replace && typeof args[1] === 'function') {
      const original_f = args[1];
      function wrapped_f (...wrappedArgs) {
        return TaintHelper.concreteWrappedOnly(original_f.call(this, ...wrappedArgs));
      }
      args[1] = wrapped_f;
    }
    return [base, args];
  }

}
