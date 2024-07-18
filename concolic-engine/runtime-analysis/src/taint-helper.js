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
    // Check if value is tainted already
    if (TaintHelper.isTainted(value)) {
      // TODO: If it is already tainted, we need to merge the taint info
      // Currently, we just return the value itself
      return value;
    }

    if (Utils.isPrimitive(value)) {
      return new TaintValue(value, taintInfo);
    }
    else {
      try {
        Object.defineProperty(value, TaintPropName, {
          value: taintInfo,
          enumerable: false,
          writable: true,
          configurable: true
        });
      }
      catch (e) {
        console.log(`Error in adding taint to ${value}: ${e}`);
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
   * @param {*} value 
   * @returns 
   */
  static rconcrete(value) {

    if (TaintHelper.isTainted(value)) {
      return TaintHelper.concrete(value.getConcrete());
    } else if (Array.isArray(value)) {
      return value.map(item => TaintHelper.rconcrete(item));
    } else if (value && typeof value === 'object' && value.constructor === Object) {
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
      return value.getConcrete();
    }
    return value;
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
        return argsArray[1].some(arg => TaintHelper.isTainted(arg));
      } else {
        return TaintHelper.isTainted(argsArray[1]);
      }
    }

    return argsArray.some(arg => TaintHelper.isTainted(arg));
  }
}
