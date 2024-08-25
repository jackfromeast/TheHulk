import { Utils } from '../utils/util.js';
import { TaintHelper } from '../taint-helper.js';

/**
 * This class is used by the runOriginFunc function
 * to store the taint information of a value and then reinstall it back
 * 
 * @notes
 * --------------------------------
 * This class is based on the fact that we cannot fully clone an object in javascript and keeping all its
 * type, properties and methods. So, we cannot get a identical copy of the object with taint information stripped for runOriginFunc and
 * use its original value for the model function afterwards.
 * 
 * 
 * And also, in the most case, we don't need to recursive dehydrate and moisturize the taint information.
 * E.g. 
 *  - For ["TAINTED"].pop, we don't want to recursively dehydrate the taint information of the array and
 *    we will not be able to moisturize the taint information back. The best way is to leave the concretize=false when
 *    calling the runOriginFunc.
 * 
 *  - For ["TAINTED"].join, we need to recursively dehydrate the taint information of the array and moisturize the taint information back.
 *    otherwise, the taint's toString method will be called and ruin the original result.
 * 
 * Therefore, you should only call DehydratedTaintValue.maxDepth>1 when you are sure that the value will not be clobbered by running
 * the runOriginFunc function and there is a reason for that (e.g. array.join). Otherwise, you should set maxDepth=1.
 * 
 * 
 * @param {Object} self - Taint information of the current object
 * @param {Object|Array} children - Taint information of nested objects/arrays
 */
export class DehydratedTaintValue {
  constructor(value, depth=1) {
    this.concrete = value;
    this.DehydratedTaintInfo = null;
    // Usually, depth=1 means we are calling concrete and reinstall functions on the value
    this.maxDepth = depth;
    [this.concrete, this.DehydratedTaintInfo] = this.dehydrateTaint(value, 0);
  }

  /**
   * Get the DehydratedTaintInfo from a value
   * 
   * @param {*} value 
   * @param {number} depth - Current recursion depth
   * @returns {Array} [concreteValue, DehydratedTaintInfo]
   */
  dehydrateTaint(value, depth) {
    if (depth > this.maxDepth) {
      return [value, null]; // No taint for primitives or beyond max depth
    }

    let taintInfo = null;
    let concreteValue = value;
    if (TaintHelper.isTainted(value)) {
      // KNOWN ISSUE:
      // [concreteValue, taintInfo] = TaintHelper.concrete(value);
      // We currently only concrete the wrapped value but not object
      // This is because once we delete the __TAINT__ from the original object, we delete it from all th references in the caller scope
      // Even though we add it back afterwards, we cannot change the reference in the caller scope but only the reference in the callee scope
      concreteValue = TaintHelper.concreteWrappedOnly(value);
      taintInfo = TaintHelper.getTaintInfo(value);
    }

    if (this.maxDepth > 1) {
      if (Array.isArray(concreteValue)) {
        let taintInfoArray = [];
        let concreteArray = concreteValue.map((item, index) => {
          let [concreteItem, itemTaint] = this.dehydrateTaint(item, depth + 1);
          taintInfoArray[index] = itemTaint;
          return concreteItem;
        });
        return [concreteArray, { self: taintInfo, children: taintInfoArray }];
      } else if (concreteValue !== null && typeof concreteValue === 'object') {
        const taintInfoObj = {};
        const concreteObj = {};
  
        // Use Object.keys to avoid traversing the prototype chain
        Object.keys(concreteValue).forEach((key) => {
          const [concreteItem, itemTaint] = this.dehydrateTaint(concreteValue[key], depth + 1);
          concreteObj[key] = concreteItem;
          taintInfoObj[key] = itemTaint;
        });
        
        Object.setPrototypeOf(concreteObj, Object.getPrototypeOf(concreteValue));

        return [concreteObj, { self: taintInfo, children: taintInfoObj }];
      }
    }

    if (taintInfo) {
      return [concreteValue, { self: taintInfo }];
    }

    return [value, null];
  }

  /**
   * Method to reinstall the taint information to a value from its DehydratedTaintInfo
   * 
   * @param {*} value 
   * @param {Object} taintInfo - Taint information to be reinstalled
   * @param {number} depth - Current recursion depth
   * @returns {*} value with reinstalled taint
   */
  moisturizeTaint(value, taintInfo, depth = 0) {
    if (depth > this.maxDepth || taintInfo == null) {
      return value; // No taint for primitives, beyond max depth, or null taint info
    }

    if (J$$.analysis.DCHECK) {
     // If the value and taintInfo are not consistent, throw an error     
    }

    value = TaintHelper.reinstall(value, taintInfo.self);

    if (this.maxDepth > 1) {
      if (Array.isArray(value)) {
        value.forEach((item, index) => {
          if (taintInfo.children && taintInfo.children[index]) {
            value[index] = this.moisturizeTaint(value[index], taintInfo.children[index], depth + 1);
          }
        });
      } else if (typeof value === 'object') {
        for (let key in value) {
          if (taintInfo.children && taintInfo.children[key]) {
            value[key] = this.moisturizeTaint(value[key], taintInfo.children[key], depth + 1);
          }
        }
      }
    }

    return value;
  }
}