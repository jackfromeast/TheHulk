import { TaintValue, WrappedValue } from './values/wrapped-values.js';
import { TaintInfo, TaintPropName, TaintPropNameForDebug } from './values/taint-info.js';
import { Utils } from './utils/util.js';

/**
 * @description
 * --------------------------------
 * This class defines the taint-related helper functions
 * This class help you check, add, merge, and remove taint information
 * 
 * @notes
 * --------------------------------
 * All the operation on the value that can be redefined by the user (e.g. get, set, in, ...)
 * should use the functions provided by the utils to avoid recursive call 
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

      if ((!J$$.analysis.taintConfig.TAINT_VALUE.Number && typeof value === 'number') || 
          (!J$$.analysis.taintConfig.TAINT_VALUE.Boolean && typeof value === 'boolean')) {
        return value;
      }
      
      return new TaintValue(value, taintInfo);
    }
    else {
      try {
        if (!Object.isExtensible(value)) {
          J$$.analysis.logger.debug("Cannot install taint to non-extensible object", value);
          return value;
        } else if (TaintHelper.isInTaintBlacklist(value)) {
          return value;
        }

        J$$.analysis.logger.reportTaintInstall(value);

        Object.defineProperty(value, TaintPropName, {
          value: taintInfo,
          enumerable: false,
          writable: true,
          configurable: true
        });

        if (J$$.analysis.DCHECK && J$$.analysis.DCHECK_SHADOW_TAINT) {
          // Add a shadow property to store the actual taint value
          Object.defineProperty(value, TaintPropNameForDebug, {
            value: taintInfo,
            enumerable: false,
            writable: true,
            configurable: true
          });
  
          // Add a proxy property with a getter and setter
          Object.defineProperty(value, TaintPropName, {
            get() {
              return this[TaintPropNameForDebug];
            },
            set(newValue) {
              if (!(newValue instanceof TaintInfo)) {
                debugger; // Trigger debugger if the value is not of type TaintInfo
              }
              this[TaintPropNameForDebug] = newValue;
            },
            enumerable: false,
            configurable: true
          });
        }

        return value;
      }
      catch (e) {
        J$$.analysis.logger.debug("Failed to install taint to", value, " because ", e);
        return value;
      }
    }
  }

  static isInTaintBlacklist(value) {
    // Don't taint history, localStorage, sessionStorage, and indexedDB
    if (value === document ||
        value === window ||
        value === window.document ||
        value === window.history ||
        value === window.localStorage ||
        value === window.sessionStorage ||
        value === window.indexedDB ||
        value instanceof DOMStringMap) {
      return true;
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
    if (Utils.isDOMNode(value)) { return value; }

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
    return value;
  }
  
  /**
   * Concrete the value if it is tainted recursively up to a specified depth.
   * 
   * Note that at most time, we don't need to concrete the value recursively.
   * This function will strip the taint info in very level of the value and
   * you will lose the taint information forever.
   * 
   * - For the primitive types, we can just concrete them in one level.
   * - For the object types, we don't need to strip the taint as it 
   *   shouldn't affect the execution at most time.
   * 
   * @param {*} value 
   * @param {number} depth - The depth to which the concreting should be performed.
   * @returns {*} concreteValue
   */
  static rconcreteHard(value, depth=Infinity) {
    if (depth < 0) {
      return value;
    }

    if (Utils.isDOMNode(value)) { return value; }

    if (TaintHelper.isTainted(value)) {
      return TaintHelper.concreteHard(value);
    } else if (Array.isArray(value)) {
      return value.map(item => TaintHelper.rconcreteHard(item, depth - 1));
    } else if (value && typeof value === 'object' && value.constructor === Object) {
      return Object.keys(value).reduce((acc, key) => {
        let [item, isSafeLookup] = Utils.safeLookup(value, key, true);
        if (isSafeLookup) {
          acc[key] = TaintHelper.rconcreteHard(item, depth - 1);
        }

        return acc;
      }, {});
    }

    return value;
  }



  /**
   * This function is used to reinstall the taint info for the object
   * Sometimes, we will strip the taint info from the object and 
   * perform some operations on the object and then we reinstall the taint info
   * 
   * @param {*} value 
   * @param {TaintInfo|null} taintInfo 
   */
  static reinstall(value, taintInfo) {
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


  static risTainted(value, depth = 0) {
    if (depth > J$$.analysis.MAX_DEPTH_FOR_TAINT_CHECK) {
      return false; // Do not trace beyond MAX_DEPTH_FOR_TAINT_CHECK layers
    }
    if (TaintHelper.isTainted(value)) {
      return true;
    } else if (Array.isArray(value)) {
      try{
        return value.some(item => TaintHelper.risTainted(item, depth + 1));
      } catch (e) {
        if (e instanceof DOMException) { return false; }
        J$$.analysis.logger.debug("Cannot check if the value is tainted because ", e);
        return false;
      }
    } else if (value && typeof value === 'object') {
      // Don't traverse the DOM Node's properties
      if (Utils.isDOMNode(value)) { return false; }
      return Object.keys(value).some(key => {
        try{
          let [item, isSafeLookup] = Utils.safeLookup(value, key);
          if (isSafeLookup) { return TaintHelper.risTainted(item, depth + 1); }
          return false;
        } catch (e) {
          if (e instanceof DOMException) { return false; }
          J$$.analysis.logger.debug("Cannot check if the value is tainted because ", e);
          return false;
        }
      });
    }
    return false;
  }

  /**
   * Check if the value is tainted in one level
   * @param {*} value 
   * @returns {boolean}
   */
  static isTainted(value) {
    try {
      // Check if value is an instance of TaintValue
      if (value instanceof TaintValue) {
        return true;
      }

      // Check if the value is primitive
      if (Utils.isPrimitive(value)) {
        return false;
      }

      // Avoid using the lookup which might trigger getter unexpectedly
      return Utils.hasOwnKey(value, TaintPropName);
    } catch (e) {
      if (e instanceof DOMException) { return false; }
      J$$.analysis.logger.debug("Cannot check if the value is tainted because ", e);
      return false;
    }
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
   * @param {*} base
   * @param {Array[*]|Argruments} args
   * @param {Number} iid
   */
  static addTaintPropOperation(oldTaintInfo, operationName, base, args, iid) {
    if (!structuredClone) {
      throw new Error("structuredClone is not defined");
    }
    
    // A workaround to clone the object with the same prototype
    // The following line will be slow
    let newTaintInfo = Object.create(Object.getPrototypeOf(oldTaintInfo));
    Object.assign(newTaintInfo, structuredClone(Object.assign({}, oldTaintInfo)));

    let clonedBase;
    try {
      if (base instanceof WrappedValue) {
        clonedBase = base.toStringInternal();
      } else {
        clonedBase = Utils.safeToString(base);
        // The following line will be slow, and will trigger getter unexpectedly
        // clonedBase = structuredClone(base);
      }
    } catch (e) {
      clonedBase = base;
    }
    
    if (Utils.isArguments(args)) { args = Array.from(args); }
    let clonedArgs = args.map(arg => {
      try {
        if (arg instanceof WrappedValue) {
          return arg.toStringInternal();
        }
        // return structuredClone(arg);
        return Utils.safeToString(arg);
      } catch (e) {
        return arg;
      }
    });

    newTaintInfo.addTaintPropOperation(operationName, clonedBase, clonedArgs, iid);

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
          let [item, isSafeLookup] = Utils.safeLookup(value, key);
          if (!isSafeLookup) { continue; }

          let taintInfo = TaintHelper.rgetTaintInfo(item);
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
      // If there is more than one argument, it is [arg1, arg2, ...] (in Array type)

      // If argsArray[1] is not in type of array, we need to check if it is tainted
      if (!Utils.isArray(argsArray[1])) {
        return TaintHelper.risTainted(argsArray[1]);
      }else{
        // If argsArray[1] is in type of array, it can be [arg1, arg2, ...] or arg1 is an array
        return TaintHelper.risTainted(argsArray[1]) ||
               (argsArray[1].length > 0 &&
               argsArray[1].some(arg => TaintHelper.risTainted(arg)));
      }
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

      // If argsArray[1] is not in type of array, we need to check if it is tainted
      if (!Utils.isArray(argsArray[1])) {
        return TaintHelper.isTainted(argsArray[1]);
      }else{
        // If argsArray[1] is in type of array, it can be [arg1, arg2, ...] or arg1 is an array
        return TaintHelper.isTainted(argsArray[1]) ||
                (argsArray[1].length > 0 &&
                argsArray[1].some(arg => TaintHelper.isTainted(arg)));
      }
    }

    return argsArray.some(arg => TaintHelper.isTainted(arg));
  }
}
