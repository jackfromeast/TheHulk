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
 * For more details, see the documentation: https://github.com/xxxxxxxxxxxx/TheHulk/wiki/Concolic-Execution-Bind-User-Functions
 * 
 * Perchecker will handle these user-defined functions and ensure the runOriginalFun won't arrive at any user-defined functions.
 */
export class BindValueChecker {

  static handleUserDefinedValueOf(left) {
    let carriedOut = false;
    if (left && Utils.realTypeOf(left) === 'object') {
      try {
        if (Utils.isUserDefinedFunction(left["valueOf"])) {
          left = left.valueOf();
          carriedOut = true;
        }
      } catch (e) {
        // Reading valueOf property on cross-origin objects might throw an error
        if (e.name === "SecurityError") {
          J$$.analysis.logger.warn("SecurityError: Might because of reading valueOf property on cross-origin objects.");
        } else {
          throw e;
        }
      }
    }
    return [left, carriedOut];
  }

  static handleUserDefinedToString(left) {
    let carriedOut = false;
    if (left && Utils.realTypeOf(left) === 'object') {
      try {
        if (Utils.isUserDefinedFunction(left["toString"])) {
          left = left.toString();
          carriedOut = true;
        }
      } catch (e) {
        // Reading toString property on cross-origin objects might throw an error
        if (e.name === "SecurityError") {
          J$$.analysis.logger.warn("SecurityError: Might because of reading toString property on cross-origin objects.");
        } else {
          throw e;
        }
      }
    }
    return [left, carriedOut];
  }
  
  static handleUserDefinedFunctionsForBinaryOps(left, right, operator) {
    let carriedOutValueOfLeft = false;
    let carriedOutValueOfRight = false;

    if (["+", "-", "~", "!"].includes(operator)) {
      [left, carriedOutValueOfLeft]  = BindValueChecker.handleUserDefinedValueOf(left);
      [right, carriedOutValueOfRight] = BindValueChecker.handleUserDefinedValueOf(right);
    } 
    
    if (operator === "+" && !carriedOutValueOfLeft) {
      [left] = BindValueChecker.handleUserDefinedToString(left);
    }

    if (operator === "+" && !carriedOutValueOfRight) {
      [right] = BindValueChecker.handleUserDefinedToString(right);
    }

    return [left, right];
  }

  static handleUserDefinedFunctionsForBuiltins(f, base, args, iid) {
    // Before calling the original function,
    // We prepare the arguments for runOriginFunc to make it won't call the user-defined function and surprise us
    // We handle all the implicit bind operations here
    // For the array.filter, we need to make sure the return value of the first f needs to be concretized
    if (f === Array.prototype.filter || f === Array.prototype.find || f === Array.prototype.findIndex || f === Array.prototype.findLastIndex) {
      const original_f = args[0];
      function wrapped_f (...wrappedArgs) {
        return TaintHelper.concreteWrappedOnly(original_f.call(this, ...wrappedArgs));
      }
      args[0] = wrapped_f;
    }
    else if (f === String.prototype.replace && typeof args[1] === 'function') {
      const original_f = args[1];
      
      // Test Case:string-replace-3
      if (TaintHelper.isTainted(base)) {
        let taintInfoPairs = [['base', TaintHelper.getTaintInfo(base)]];
        const newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'String:replace(callback)', base, args, iid);
        function wrapped_f_taint (...wrappedArgs) {
          wrappedArgs[0] = TaintHelper.createTaintValue(wrappedArgs[0] , newTaintInfo);
          return TaintHelper.concreteWrappedOnly(original_f.call(this, ...wrappedArgs));
        }
        args[1] = wrapped_f_taint
      } else{
        function wrapped_f (...wrappedArgs) {
          return TaintHelper.concreteWrappedOnly(original_f.call(this, ...wrappedArgs));
        }
        args[1] = wrapped_f;
      }
    } else if (f === String && typeof args[0] === 'object') {
      [args[0]] = BindValueChecker.handleUserDefinedToString(args[0]);
    }
    return [base, args];
  }

}
