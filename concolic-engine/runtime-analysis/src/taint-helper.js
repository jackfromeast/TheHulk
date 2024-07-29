import { TaintValue, WrappedValue } from './values/wrapped-values.js';
import { TaintInfo, TaintPropName } from './values/taint-info.js';
import { Utils } from './utils/util.js';

/**
 * @description
 * --------------------------------
 * This class defines the taint-related helper functions
 * This class help you check, add, merge, and remove taint information
 */
export class TaintHelper {
  
  /**
   * Create a new taint value
   * @param {*} value 
   * @param {TaintInfo} taintInfo
   */
  static createTaintValue(value, taintInfo) {
    if (value === undefined || value === null) {
      return value;
    }

    // Check if value is tainted already
    if (TaintHelper.isTainted(value)) {
      // TODO: If it is already tainted, we need to merge the taint info
      // Currently, we just return the value itself
      return value;
    }

    if (Utils.isPrimitive(value)) {
      J$$.analysis.logger.reportTaintInstall(value);
      return new TaintValue(value, taintInfo);
    }
    else {
      try {
        if (!Object.isExtensible(value)) {
          J$$.analysis.logger.debug("Cannot install taint to non-extensible object", value);
          return value;
        }

        J$$.analysis.logger.reportTaintInstall(value);
        Object.defineProperty(value, TaintPropName, {
          value: taintInfo,
          enumerable: false,
          writable: true,
          configurable: true
        });
        return value;
      }
      catch (e) {
        J$$.analysis.logger.debug("Failed to install taint to", value, " because ", e);
        return value;
      }
    }
  }

  /**
   * This function is used to reinstall the taint info for the object
   * Sometimes, we will strip the taint info from the object and 
   * perform some operations on the object and then we reinstall the taint info
   * 
   * @param {*} value 
   * @param {TaintInfo|null} taintInfo 
   */
  static reinstallTaint(value, taintInfo) {
    if (value === undefined || value === null) {
      return value;
    }
    
    if (!taintInfo) {
      return value;
    }

    try {
      if (Utils.isPrimitive(value)) {
        return new TaintValue(value, taintInfo);
      }else{
        if (!Object.isExtensible(value)) {
          J$$.analysis.logger.debug("Cannot reinstall taint to non-extensible object", value);
          return value;
        }
  
        Object.defineProperty(value, TaintPropName, {
          value: taintInfo,
          enumerable: false,
          writable: true,
          configurable: true
        });
        return value;
      }
    }
    catch (e) {
      J$$.analysis.logger.debug("Failed to reinstall taint to", value, " because ", e);
      return value;
    }
  }

  static risTainted(value) {
    if (TaintHelper.isTainted(value)) {
      return true;
    } else if (Array.isArray(value)) {
      return value.some(item => TaintHelper.risTainted(item));
    } else if (value && typeof value === 'object' && value.constructor === Object) {
      return Object.keys(value).some(key => TaintHelper.risTainted(value[key]));
    }
    return false;
  }

  /**
   * Check if the value is tainted in one level
   * @param {*} value 
   * @returns 
   */
  static isTainted(value) {
    try {
      return value instanceof TaintValue || (!Utils.isPrimitive(value) && value[TaintPropName]);
    }
    catch (DOMException) {
      J$$.analysis.logger.debug("Cannot check if the value is tainted because ", DOMException);
      return false;
    }
  }

  /**
   * Concrete the value and return the concrete value and taint info
   * 
   * This function will concrete the value by one level guarranteed
   * This function will be used in the rule functions to get the concrete value
   * and apply the original operation/function call
   * 
   * However, note that, the caller is responsible for reinstalling the taint info
   * if the value is object type and the taint info is installed in the property __TAINT__
   * 
   * @param {*} value 
   * @returns {Array} [concreteValue, taintInfo]
   */
  static concrete(value) {
    if (TaintHelper.isTainted(value)) {
      if (value instanceof TaintValue) {
        return [value.getConcrete(), value.getTaintInfo()];
      } else {
        // If the value is not wrapped in TaintValue, but has taint info
        // We return the value itself with __TAINT__ stripped
        // Then, we need to mually reinstall the taint info back if the original value is needed
        let taintInfo = value[TaintPropName];
        delete value[TaintPropName];
        return [value, taintInfo];
      }
    }
    return [value, null];
  }

  /**
   * Concrete the warapped value 
   * This function will not delete the taint info from the value if the taint
   * info is installed in the property __TAINT__
   * Therefore, it is working for the wrapped value only
   * 
   * By using this function, you don't need to worry about installing the taint info back
   * could be problematic for the rule functions as it will run the original function/operation
   * on the concrete value which is not *really* the concrete value without taint info
   * 
   * Most of the time, you don't need to strip the __TAINT__ property of a taint object
   * 
   * @param {*} value 
   * @returns 
   */
  static concreteWrappedOnly(value) {
    if (TaintHelper.isTainted(value)) {
      if (value instanceof TaintValue) {
        return value.getConcrete();
      } else {
        // If the value is not wrapped in TaintValue, but has taint info
        // We return the value itself without __TAINT__ stripped
        return value;
      }
    }
    return value;
  }

  /**
   * Concrete the value hard
   * 
   * Note that this will strip the taint info from the value
   * And you will lose the taint information forever if the taint info
   * is installed in the property __TAINT__
   * 
   * @param {*} value 
   * @returns {*} concreteValue
   */
  static concreteHard(value) {
    if (TaintHelper.isTainted(value)) {
      if (value instanceof TaintValue) {
        return value.getConcrete();
      } else {
        // If the value is not wrapped in TaintValue, but has taint info
        // We return the value itself with __TAINT__ stripped
        delete value[TaintPropName];
        return value;
      }
    }
    return [value, null];
  }
  
    /**
   * Concrete the value if it is tainted recursively
   * 
   * Note that at most time, we don't need to concrete the value recursively
   * This function will strip the taint info in very level of the value and
   * you will lose the taint information forever
   * 
   * - For the primitive types, we can just concrete them in one level
   * - For the object types, we doesn't need to strip the taint as it 
   *   shouldn't affect the execution at most time
   * 
   * @param {*} value 
   * @returns {*} concreteValue
   */
  static rconcreteHard(value) {

    if (!TaintHelper.risTainted(value)) {
      return value;
    }

    if (TaintHelper.isTainted(value)) {
      return TaintHelper.concreteHard(value);
    } else if (Array.isArray(value)) {
      return value.map(item => TaintHelper.rconcreteHard(item));
    } else if (value && typeof value === 'object' && value.constructor === Object) {
      // This operation might be dangerous, because we will lose the keys that cannot be looped out
      return Object.keys(value).reduce((acc, key) => {
        acc[key] = TaintHelper.rconcreteHard(value[key]);
        return acc;
      }, {});
    }

    return value;
  }


  /**
   * Create a new taintInfo object
   * Given the newly added taintPropOperation and existing taintInfo
   * 
   * This function can be seen a wrapper of taintInfo.addTaintPropOperation()
   * which will handle the clone part automatically
   * 
   * @param {TaintInfo} oldTaintInfo
   * @param {String} operationName
   * @param {Array} args
   * @param {Number} iid
   */
  static addTaintPropOperation(oldTaintInfo, operationName, args, iid) {
    if (!structuredClone) {
      throw new Error("structuredClone is not defined");
    }
    
    // A workaround to clone the object with the same prototype
    let newTaintInfo = Object.create(Object.getPrototypeOf(oldTaintInfo));
    Object.assign(newTaintInfo, structuredClone(Object.assign({}, oldTaintInfo)));

    let cloned_args = args.map(arg => {
      try{
        // If the argument itself is a TaintValue
        if (arg instanceof WrappedValue) {
          return arg.toString();
        }
        return structuredClone(arg);
      }
      catch(e) {
        // J$$.analysis.logger.debug(`Cannot clone ${arg} because ${e}`);
        return arg;
      }
    });
    newTaintInfo.addTaintPropOperation(operationName, cloned_args, iid);

    return newTaintInfo;
  }

  static getTaintInfo(value) {
    if (TaintHelper.isTainted(value)) {
      if (value instanceof TaintValue) {
        return value.getTaintInfo();
      } else{
        return value[TaintPropName];
      }
    }
    return null;
  }

  /**
   * @description
   * --------------------------------
   * Recursively check and get nested arrays and objects for taint information.
   * 
   * @TODO
   * --------------------------------
   * Now, we don't merge the taint information from different elements in the array.
   * Or we should return multiple taint info if there are multiple taints and let the caller 
   * to merge them
   * 
   * Now, we only support array and primitive types
   * 
   * @param {Array|Object|*} value - The item to check for taint.
   * @returns {TaintInfo|null} - The taint information if found, otherwise null.
   */
  static rgetTaintInfo(value) {
    
    if (TaintHelper.isTainted(value)) {
      return TaintHelper.getTaintInfo(value);
    }

    if (Array.isArray(value)) {
      for (let element of value) {
        let taintInfo = TaintHelper.rgetTaintInfo(element);
        if (taintInfo) return taintInfo;
      }
    } else if (typeof value === 'object' && value !== null) {
      for (let key in value) {
        if (value.hasOwnProperty(key)) {
          let taintInfo = TaintHelper.rgetTaintInfo(value[key]);
          if (taintInfo) return taintInfo;
        }
      }
    }

    return null;
  }
    
  /**
   * Check if any of the arguments are tainted
   * If function has been called in this way: f.apply(this, args),
   * We need to unwrap the args, because it is [arg1, arg2, ...]
   * 
   * @param {Argruments} args 
   * @param {String} reflected 
   * @returns 
   */
  static risAnyArgumentsTainted(args, reflected) {
    if (args.length === 0) { return false; }

    let argsArray = args;
    if (Utils.isArguments(args)) {
      argsArray = Array.from(args);
    }
    
    if (reflected === 'apply') {
      // For f.apply(this, args)
      // If there is only one argument, it is the arg itself
      // If there is more than one argument, it is [arg1, arg2, ...]
      return TaintHelper.risTainted(argsArray[1]) ||
             argsArray[1].some(arg => TaintHelper.risTainted(arg));
    }

    return argsArray.some(arg => TaintHelper.risTainted(arg));
  }

  static isAnyArgumentsTainted(args, reflected) {
    if (args.length === 0) { return false; }

    let argsArray = args;
    if (Utils.isArguments(args)) {
      argsArray = Array.from(args);
    }
    
    if (reflected === 'apply') {
      // For f.apply(this, args)
      // If there is only one argument, it is the arg itself
      // If there is more than one argument, it is [arg1, arg2, ...]
      return TaintHelper.isTainted(argsArray[1]) ||
             argsArray[1].some(arg => TaintHelper.isTainted(arg));
    }

    return argsArray.some(arg => TaintHelper.isTainted(arg));
  }
}
