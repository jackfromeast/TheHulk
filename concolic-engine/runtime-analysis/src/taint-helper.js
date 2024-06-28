import { TaintValue, WrappedValue } from './values/wrapped-values.js';
import { TaintInfo } from './values/taint-info.js';


export class TaintHelper {
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

    J$$.analysis.dangerousFlows.push({
      sourceReason: sourceReason,
      sourceLoc: sourceLoc,
      sinkReason: sinkReason,
      sinkLoc: sinkLoc,
      taintedValue: taintedValue,
      iid: iid
    });
  }

  static reportUnsupportedBuiltin(builtinName, ) {
    console.log("%c[TheHulk] Unsupported builtin %s!",
                'background: white; color: brown',            
                builtinName);
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

}
