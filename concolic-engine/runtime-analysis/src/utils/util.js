import { TaintHelper } from "../taint-helper.js";

/**
 * @description
 * --------------------------------
 * General utility functions that are used across the analysis
 * 
 */
export class Utils {
  // Get a safe version of Object.prototype.toString and Function.prototype.toString
  static safeObjectToString = Object.prototype.toString;
  static safeFunctionToString = Function.prototype.toString;
  static reHostCtor = /^\[object .+?Constructor\]$/;
  static staticNativeFuncPattern = "function toString() { [native code] }"
  static reNative = new RegExp("^" + Utils.staticNativeFuncPattern
                                    .replace(/[.*+?^${}()|[\]\/\\]/g, "\\$&")
                                    .replace(/toString|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$");

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
   * Safe toString function that handles exceptions
   * - The value might doesn't inherited from Object.prototype and don't have toString method
   * - The value can have user-defined toString method, we need to check if it is native
   * - The value may be proixied, and calling toString will trigger the getter
   */
  static safeToString(value) {
    try {
      if (value === null || value === undefined) {
        return value + '';
      }

      if (Utils.isPrimitive(value)) {
        return value.toString();
      } else {
        return Object.prototype.toString.call(value);
      }
      
    } catch (e) {
      return '[Unable to convert to string]';
    }
  }

  /**
   * @description
   * --------------------------------
   * Safe toString function that handles exceptions and is user-defined function aware
   * - The value might doesn't inherited from Object.prototype and don't have toString method
   */
  static safeToStringWithUserDefinedToString(value) {
    try {
      if (value === null || value === undefined) {
        return value + '';
      }

      return value.toString();
    } catch (e) {
      return '[Unable to convert to string]';
    }
  }

  /**
   * @description
   * --------------------------------
   * Safe lookup function is to access a property of an user-passed object
   * 
   * @notes
   * --------------------------------
   * If obj[prop] is a getter, and when executing the getter, the function uses obj itself again,
   * We will likely get a recursive function call, if we check taint or concretize of the argument recursively (as it will 
   * trigger the obj[prop] getter again)
   * 
   * @param {*} obj 
   * @param {*} prop
   * @returns {Array} [value, isSafe]
   */
  static safeLookup(obj, prop, skipGetter=false) {
    if (skipGetter) {
      const descriptor = Object.getOwnPropertyDescriptor(obj, prop);
      if (descriptor && descriptor.get && Utils.isUserDefinedFunction(descriptor.get)) {
        return [null, false];
      }
    }

    try {
      // Set receiver to obj to avoid getter recursion
      // In case, the get function uses Reflect.get(obj, prop, receiver) in its body
      return [Reflect.get(obj, prop, obj), true];
    }
    catch (e) {
      // Have seen exceptions where base.tagName will cause Illegal invocation error
      return [null, false];
    }
  }

  /**
   * This function helps to check if the object has the property and avoid triggering any getter
   * As long as the proxy doesn't define the [[OwnPropertyKeys]] method
   * 
   * @param {*} obj 
   * @param {*} prop 
   * @returns 
   */
  static hasOwnKey(obj, prop) {
    try{
      // Quite slow, need proxy doesn't define [[OwnPropertyKeys]]
      // return Reflect.ownKeys(obj).some(key => key === prop);
      // Faster, need proxy doesn't define getOwnPropertyDescriptor 
      return Object.prototype.hasOwnProperty.call(obj, prop);
    } catch(e){
      return false;
    }
  }

  /**
   * @description
   * --------------------------------
   * Safe toPrimitive function that handles exceptions
   * 
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
   * @TODO
   * ------------------------------
   * Now, this function is quite slow, we need to optimize it
   * 
   * @param {*} f 
   * @returns 
   */
  static isNativeFunction(f) {
    function isNativeCore(value) {
        if (!value.hasOwnProperty || value.hasOwnProperty('toString')) {
          // isNativeFunction will not work on custom toString methods. 
          // We assume nobody would overwrite core method toStrings
          return false;
        }

        if (typeof(value) === "function") {
            return Utils.reNative.test(Utils.safeFunctionToString.call(value)) && value.name !== 'bound '; 
        } else if (typeof(value) === "object") {
            return Utils.reHostCtor.test(Utils.safeObjectToString.call(value));
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

  static isUserDefinedFunction(f) {
    return typeof f === 'function' && !Utils.isNativeFunction(f);
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
      return typeof TaintHelper.concreteWrappedOnly(value);
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
   * https://developer.mozilla.org/en-US/docs/Web/API/Node
   * @param {*} value 
   * @returns {Boolean}
   */
  static isDOMNode(value) {
    try{
      if (value instanceof Node || value.prototype instanceof Node) {
        return true;
      }
    } catch(e){
      return false;
    }
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