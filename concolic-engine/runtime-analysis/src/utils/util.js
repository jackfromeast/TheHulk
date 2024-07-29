import { TaintHelper } from "../taint-helper.js";

/**
 * @description
 * --------------------------------
 * General utility functions that are used across the analysis
 */
export class Utils {
  static reportDangerousFlow(sourceReason, sourceLoc, sinkReason, sinkLoc, taintedValue, iid) {
    J$$.analysis.logger.reportVulnFlow(sourceReason, sinkReason, taintedValue);
    
    try{
      // TODO: Think of a better way to take the snapshot of the tainted value
      // const clonedTaintedValue = structuredClone(taintedValue);
      J$$.analysis.dangerousFlows.push({
        sourceReason: sourceReason,
        sourceLoc: sourceLoc,
        sinkReason: sinkReason,
        sinkLoc: sinkLoc,
        taintedValue: taintedValue,
        iid: iid
      });
    }
    catch(e){
      J$$.analysis.logger.debug("Failed to clone tainted value", taintedValue, " because ", e);
    }
  }

  /**
   * @description
   * --------------------------------
   * Safe tostring function that handles exceptions
   * The value might doesn't inherited from Object.prototype and don't have toString method
   */
  static safeToString(value) {
    try {
      // value.toString shouldn't be overwritten by developer
      // If it is overwritten, we will get recursive function
      if (!Utils.isNativeFunction(value.toString)) { throw new Error('toString is not native'); }
      return value.toString();
    } catch (e) {
      return '[Unable to convert to string]';
    }
  }

  /**
   * Safe toPrimitive function that handles exceptions
   * @param {*} value 
   */
  static safeToPrimitive(value) {
    try {
      return value.toString();
    } catch (e) {
      return null;
    }
  }

  /**
   * @description
   * --------------------------------
   * Retrun the array like arguments
   * 
   * @param {Argruments} args 
   * @param {String} reflected 
   * @returns 
   */
  static getArrayLikeArguments(args, reflected) {
    if (args.length === 0) { return []; }
      
    let argsArray = args;
    if (Utils.isArguments(args)) {
      argsArray = Array.from(args);
    }
    
    if (reflected === 'apply') {
      // For f.apply(this, args)
      // If there is only one argument, it is the arg itself
      // If there is more than one argument, it is [arg1, arg2, ...]
      if (argsArray[1] instanceof Array) {
        return argsArray[1];
      } else {
        return [argsArray[1]];
      }
    }

    return argsArray;
  }

  /**
   * isNativeFunction should free from any side effects
   * 
   * The f and value should be any type of value even without prototype
   * We should swallow any exceptions
   * 
   * @param {*} f 
   * @returns 
   */
  static isNativeFunction(f) {
    const toString = Object.prototype.toString;
    const fnToString = Function.prototype.toString;
    const reHostCtor = /^\[object .+?Constructor\]$/;
    
    // We need to make sure String() is not overwritten by developer
    // If String() is instrumented, we will get recursive function call 
    const staticPattern = "function toString() { [native code] }"
    const reNative = RegExp("^" + staticPattern
            .replace(/[.*+?^${}()|[\]\/\\]/g, "\\$&")
            .replace(/toString|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$"
    );

    function isNativeCore(value) {
        if (!value.hasOwnProperty || value.hasOwnProperty('toString')) {
          // isNativeFunction will not work on custom toString methods. 
          // We assume nobody would overwrite core method toStrings
          return false;
        }

        if (typeof(value) === "function") {
            return reNative.test(fnToString.call(value)); 
        } else if (typeof(value) === "object") {
            return reHostCtor.test(toString.call(value));
        } else {
            return false;
        }
    }

    if (f === null || f === undefined) {
        // isNativeFunction called on null or undefined;
        return false;
    }

    if (typeof(f) === "function" || typeof(f) === "object") {
        return isNativeCore(f);
    } else {
        // isNativeFunction called on non-function/non-object;
        return false;
    }
  }

  static isAnyUserDefinedFunction(args) {
    return Array.from(args).some(arg => typeof arg === 'function' && !Utils.isNativeFunction(arg));
  }

  /**
   * Check the real type of the value no matter if it is tainted
   * @param {*} value 
   */
  static realTypeOf(value) {
    if (TaintHelper.isTainted(value)) {
      return typeof TaintHelper.concrete(value);
    }
    return typeof value;
  }

  static isArguments(args) {
    return Object.prototype.toString.call(args) === '[object Arguments]';
  }

  static isPrimitive(value) {
    return value !== Object(value);
  }

  /**
   * Check if the value is a string no matter if it is tainted
   * @param {*} value 
   * @returns 
   */
  static isString(value) {
    return Utils.realTypeOf(value) === 'string' || TaintHelper.concreteWrappedOnly(value) instanceof String;
  }

  /**
   * Check if the value is an iterator from String.prototype.matchAll
   * @param {*} value 
   * @returns {boolean}
   */
  static isRegExpStringIterator(value) {
    const matchAllIteratorPrototype = Object.getPrototypeOf(''.matchAll(''));
    return Object.getPrototypeOf(value) === matchAllIteratorPrototype;
  }

  static isArray(value) { 
    return Array.isArray(value);
  }
}