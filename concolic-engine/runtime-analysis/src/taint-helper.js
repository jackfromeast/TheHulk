import { TaintValue, WrappedValue } from './values/wrapped-values.js';
import { TaintInfo } from './values/taint-info.js';


export class TaintHelper {
  
  static rconcrete(value) {
    if (value instanceof WrappedValue) {
      return this.concrete(value.getConcrete());
    } else if (Array.isArray(value)) {
      return value.map(item => this.concrete(item));
    } else if (value && typeof value === 'object' && value.constructor === Object) {
      return Object.keys(value).reduce((acc, key) => {
        acc[key] = this.concrete(value[key]);
        return acc;
      }, {});
    }
    return value;
  }

  static concrete(value) {
    if (value instanceof WrappedValue){
      return value.getConcrete();
    }
    return value;
  }

  static isTainted(value) {
    return value instanceof TaintValue;
  }

  static reportDangerousFlow(sourceReason, sourceLoc, sinkReason, sinkLoc, taintedValue, iid) {
    console.log("%c[TheHulk] Found a dangerous flow from %s to %s!",
                'background: #222; color: #bada55',            
                sourceReason, sinkReason);
    
    const clonedTaintedValue = JSON.parse(JSON.stringify(taintedValue));

    J$$.analysis.dangerousFlows.push({
      sourceReason: sourceReason,
      sourceLoc: sourceLoc,
      sinkReason: sinkReason,
      sinkLoc: sinkLoc,
      taintedValue: clonedTaintedValue,
      iid: iid
    });
  }

  static reportUnsupportedBuiltin(builtinName, ) {
    console.log("%c[TheHulk] Unsupported builtin %s!",
                'background: white; color: brown',            
                builtinName);
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
    if (TaintHelper.isArguments(args)) {
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

  /**
   * Retrun the array like arguments
   * 
   * @param {Argruments} args 
   * @param {String} reflected 
   * @returns 
   */
  static getArrayLikeArguements(args, reflected) {
    if (args.length === 0) { return []; }
      
    let argsArray = args;
    if (TaintHelper.isArguments(args)) {
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


  static isNativeFunction(f) {
    const toString = Object.prototype.toString;
    const fnToString = Function.prototype.toString;
    const reHostCtor = /^\[object .+?Constructor\]$/;
    const reNative = RegExp("^" +
        String(toString)
            .replace(/[.*+?^${}()|[\]\/\\]/g, "\\$&")
            .replace(/toString|(function).*?(?=\\\()| for .+?(?=\\\])/g, "$1.*?") + "$"
    );

    function isNativeCore(value) {
        if (value.hasOwnProperty('toString')) {
            console.warn('WARNING: isNativeFunction will not work on custom toString methods. We assume nobody would overwrite core method toStrings');
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
        console.warn('isNativeFunction called on null or undefined');
        return false;
    }

    if (typeof(f) === "function" || typeof(f) === "object") {
        return isNativeCore(f);
    } else {
        console.warn('isNativeFunction called on non-function/non-object');
        return false;
    }
  }

  static isArguments(args) {
    return Object.prototype.toString.call(args) === '[object Arguments]';
  }

}
