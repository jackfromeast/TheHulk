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
      if (J$$.analysis.debugPrint) {
        Utils.debugPrint ("Adding taint to " + value);
      }
      return new TaintValue(value, taintInfo);
    }
    else {
      try {
        if (J$$.analysis.debugPrint) {
          Utils.debugPrint ("Adding taint to " + value);
        }
        Object.defineProperty(value, TaintPropName, {
          value: taintInfo,
          enumerable: false,
          writable: true,
          configurable: true
        });
        return value;
      }
      catch (e) {
        console.log(`Error in adding taint to ${value}: ${e}`);
        return value;
      }
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
    return value instanceof TaintValue || (!Utils.isPrimitive(value) && value[TaintPropName]);
  }

  /**
   * Concrete the value if it is tainted recursively
   * 
   * Note that at most time, we don't need to concrete the value recursively
   * 
   * - For the primitive types, we can just concrete them in one level
   * - For the object types, we doesn't need to strip the taint as it 
   *   shouldn't affect the execution at most time
   * 
   * @param {*} value 
   * @returns 
   */
  static rconcrete(value) {

    if (!TaintHelper.risTainted(value)) {
      return value;
    }

    if (TaintHelper.isTainted(value)) {
      return TaintHelper.concrete(value);
    } else if (Array.isArray(value)) {
      return value.map(item => TaintHelper.rconcrete(item));
    } else if (value && typeof value === 'object' && value.constructor === Object) {
      // This operation might be dangerous, because we will lose the keys that cannot be looped out
      return Object.keys(value).reduce((acc, key) => {
        acc[key] = TaintHelper.rconcrete(value[key]);
        return acc;
      }, {});
    }

    return value;
  }

  /**
   * Concrete the value if it is tainted in one level
   * @param {*} value 
   * @returns 
   */
  static concrete(value) {
    if (TaintHelper.isTainted(value)) {
      if (value instanceof TaintValue) {
        return value.getConcrete();
      } else {
        // If the value is not wrapped in TaintValue, but has taint info
        // We return the value itself without getting rid of the taint info
        return value;
      }
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
        return structuredClone(arg);
      }
      catch(e) {
        // Utils.debugPrint(`Cannot clone ${arg} because ${e}`);
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
   * @param {Array|Object} value - The item to check for taint.
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
      if (argsArray[1] instanceof Array) {
        return argsArray[1].some(arg => TaintHelper.risTainted(arg));
      } else {
        return TaintHelper.risTainted(argsArray[1]);
      }
    }

    return argsArray.some(arg => TaintHelper.risTainted(arg));
  }
}
