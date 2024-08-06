import {WrappedValue, _, TaintValue} from './values/wrapped-values.js'
import {TaintInfo, TaintPropOperation} from './values/taint-info.js'

/**
 * @description
 * --------------------------------
 * This class defines the taint source policy
 * The taint source listed below is *over-approximated*, 
 * that we assume we can control the DOM elements (through DOM Clobbering & DOM APIs).
 * 
 */
export class TaintSourceRules {
  /**
   * @description
   * --------------------------------
   * This function will be invoked during the getField operation hook
   * 
   * SOURCE-TYPE-1: 
   * - SOURCE-FROM-DOM-ELEMENT
   * - Value flows from the DOM Elements as taint sources
   * - E.g. image.src, script.src, iframe.src, etc.
   * 
   * SOURCE-TYPE-2: 
   * - SOURCE-FROM-DOCUMENT
   * - Value flows from the document object as taint sources
   * - E.g. document.cookie, document.domain, document.doctype, and etc.
   * 
   * SOURCE-TYPE-3:
   * - SOURCE-FROM-WINDOW
   * - Value flows from the window object as taint sources
   * - This is potentially clobberable if there is:
   *   !window.MathJax && window.MathJax = ...
   *   Tracing a defined value might be a good idea
   * - E.g. window.MathJax
   * 
   * @param {*} base - The base object of the getField operation. (which not be a WrappedValue)
   * @param {*} offset - The offset of the getField operation.
   * @param {*} val - The value of the getField operation.
   * @param {number} iid - The instruction id.
   */
  shouldTaintSourceAtGetField(base, offset, val, iid) {
    // SOURCE-TYPE-1:
    // Check if the base is a DOM element
    if (this.isDOMElement(base) && 
        !this.isFunction(val)) {
      return "SOURCE-FROM-DOM-ELEMENT";
    }

    // SOURCE-TYPE-2:
    // Check if the base is the document object
    if (this.isDocumentObject(base) &&
        !this.isFunction(val)) {
      return "SOURCE-FROM-DOCUMENT";
    }

    // SOURCE-TYPE-3:
    // Check if the base is the window object
    if (this.isWindowObject(base) &&
        !this.isFunction(val)) {
      return "SOURCE-FROM-WINDOW";
    }

    return false;
  }

  /**
   * @description
   * --------------------------------
   * This function will be invoked during the invokeFun operation hook
   * 
   * SOURCE-TYPE-3 (Inactive):
   * - SOURCE-FROM-BROWSER-API
   * - Value flows from the browser APIs as taint sources
   * - E.g. exampleAttr = div1.getAttribute("id");
   * - Conditions:
   *   - `base` is a DOM Element or the document object
   *   - `f`is a built-in function
   *   - `result` is not a function (we don't taint functions)
   *   - `f.name` is not in the blacklistForBrowserAPIs
   * 
   * @param {Function} f - The function being invoked.
   * @param {*} base - The base object of the getField operation. (which should not be a WrappedValue)
   * @param {Array} args - The arguments passed to the function.
   * @param {*} result - The result of the getField operation.
   * @param {number} iid - The instruction id.
   */
  shouldTaintSourceAtInvokeFun(f, base, args, result, iid) {
    if (!J$$.analysis.taintConfig.TAINT_SOURCE["SOURCE-FROM-BROWSER-API"]) {
      return false;
    }

    if (this.isBuiltInFunction(f) && 
       (this.isDOMElement(base) || this.isDocumentObject(base)) &&
       !this.isBuiltInFunction(result) &&
       !this.blacklistForBrowserAPIs.includes(f.name)) {
        return "SOURCE-FROM-BROWSER-API";
    }

    return false;
  }

  isDOMElement(element) {
    return element instanceof Element;
  }

  isDocumentObject(obj) {
    return obj === document;
  }

  isWindowObject(obj) {
    return obj === window;
  }

  isBuiltInFunction(f) {
    return typeof f === 'function' && (f === Object.prototype.toString.call(f).indexOf('[native code]') !== -1);
  }

  isFunction(f) {
    return typeof f === 'function';
  }

  blacklistForBrowserAPIs = [
    'createElement',
    'appendChild',
    'insertBefore',
    'insertAdjacentElement',
    'insertAdjacentHTML',
    'insertAdjacentText',
    'insertAdjacentElement',
  ];
}