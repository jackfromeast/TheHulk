// JALANGI DO NOT INSTRUMENT
import { Utils } from '../utils/util.js';
class WrappedValue {
  /**
   * 
   * @TODO
   * Append the origin location & type of the wrapped value to the constructor
   * 
   * @param {*} concrete 
   */
  constructor(concrete) {
    Object.defineProperty(this, 'concrete', {
        value: concrete,
        enumerable: false,
        writable: true,
        configurable: true
    });
  }

  clone() {
    return new WrappedValue(this.concrete);
  }

  toString() {
    return "Wrapped(" + Utils.safeToString(this.concrete) + ", " + (this.rider ? this.rider.toString() : "") + ")";
  }

  valueOf() {
    return this.concrete ? this.concrete.valueOf() : this.concrete;
  }

  getConcrete() {
    return this.concrete;
  }
}

class ConcolicValue extends WrappedValue { 
  constructor(concrete, symbolic, arrayType = undefined) {
      super(concrete);
      this.__defineProperty('symbolic', symbolic);
      this.__defineProperty('_arrayType', arrayType);
  }

  __defineProperty(name, value){
    Object.defineProperty(this, name, {
        value: value,
        enumerable: false,
        writable: true,
        configurable: true
    });
  }

  toString() {
      return "Concolic(" + Utils.safeToString(this.concrete) + ", " + this.symbolic + ")";
  }

  clone() {
      return new ConcolicValue(this.concrete, this.symbolic);
  }

  getConcrete() {
      return this.concrete;
  }

  getSymbolic() {
      return this.symbolic;
  }

  getArrayType() {
      return this._arrayType;
  }

}

ConcolicValue.getSymbolic = function(val) {
  return val instanceof ConcolicValue ? val.symbolic : undefined;
};

ConcolicValue.setSymbolic = function(val, val_s) {
  if (val instanceof ConcolicValue) {
      val.symbolic = val_s;
  }
};


/**
 * @description
 * --------------------------------
 * TaintValue is a wrapper class for values that are tainted
 * Similar to ConcolicValue class, but with the addition of taint information
 * Ideally, all the JavaScript values can be wrapped with TaintValue
 * 
 */
class TaintValue extends WrappedValue {
  /**
   * TaintValue constructor
   * 
   * @param {*} concrete 
   * @param {TaintInfo} taintInfo 
   */
  constructor(concrete, taintInfo) {
    super(concrete);
    this.__defineProperty('taintInfo', taintInfo);
  }

  __defineProperty(name, value){
    Object.defineProperty(this, name, {
        value: value,
        enumerable: false,
        writable: true,
        configurable: true
    });
  }

  toString() {
    if (J$$.analysis.DCHECK) {
      try {
        const error = new Error();
        const stack = error.stack.split('\n');
  
        const topFrames = stack.slice(2, 6); // 2,3,4,5
        const hasvalidCallSite = topFrames.some(frame => frame.includes('addTaintPropOperation') ||
                                                         frame.includes('checkTaintAtSinkInvokeFun'));
  
        if (!hasvalidCallSite) {
          // debugger; 
          // J$$.analysis.logger.debug('Unkown caller of TaintValue.toString.');
          return this.concrete;
        }
      } catch (e) {
        J$$.analysis.logger.debug('Error during DebugCheck in toString.');
      }
    }

    return "TaintValue(" + Utils.safeToString(this.concrete) + ")";
  }

  clone() {
    return new TaintValue(this.concrete, this.taintInfo);
  }

  getConcrete() {
    return this.concrete;
  }

  getTaintInfo() {
    return this.taintInfo;
  }
}

export {WrappedValue, ConcolicValue, TaintValue};