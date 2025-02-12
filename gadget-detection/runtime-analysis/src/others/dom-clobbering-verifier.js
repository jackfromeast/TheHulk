/*
 * Copyright 2014 Samsung Information Systems America, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Author: Koushik Sen

// do not remove the following comment
// JALANGI DO NOT INSTRUMENT
import { Logger } from '../utils/logger.js';

/**
 * @description
 * --------------------------------
 * This class is used to check whether the attacker-injected value can flow to the taint sinks.
 * It will check the arguments of the sinks to see whether it contains string: HULK
 */
export class DOMClobberingVerifier {
  constructor(sandbox) {
    this.taintSinkRules = new TaintSinkRules();
    this.logger = new Logger({
      level: 'info',
      name: 'TheHulk'
    });

    this.report = [];
    this.dangerousFlows = [];
    this.payload = "";
    this.injected = false;
  }
  
  /**
   * This callback is called before the execution of a JavaScript file
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {string} instrumentedFileName - Name of the instrumented script file
   * @param {string} originalFileName - Name of the original script file
   */
  scriptEnter(iid, instrumentedFileName, originalFileName) {
    if (!this.injected) {
      try {
        document.head.insertAdjacentHTML('beforeend', this.payload);
        J$$.analysis.injected = true;
      } catch (error) {
        console.error("Error injecting the HTML markup:", error);
      }
    }
  }

  /**
   * This callback is called before a function, method, or constructor invocation.
   * Note that a method invocation also triggers a {@link MyAnalysis#getFieldPre} and a
   * {@link MyAnalysis#getField} callbacks.
   *
   * @example
   * y.f(a, b, c)
   *
   * // the above call roughly gets instrumented as follows:
   *
   * var skip = false;
   * var aret = analysis.invokeFunPre(113, f, y, [a, b, c], false, true);
   * if (aret) {
   *     f = aret.f;
   *     y = aret.y;
   *     args = aret.args;
   *     skip = aret.skip
   * }
   * if (!skip) {
   *     f.apply(y, args);
   * }
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {function} f - The function object that going to be invoked
   * @param {object} base - The receiver object for the function <tt>f</tt>
   * @param {Array} args - The array of arguments passed to <tt>f</tt>
   * @param {boolean} isConstructor - True if <tt>f</tt> is invoked as a constructor
   * @param {boolean} isMethod - True if <tt>f</tt> is invoked as a method
   * @param {number} functionIid - The iid (i.e. the unique instruction identifier) where the function was created
   * @param {number} functionSid - The sid (i.e. the unique script identifier) where the function was created
   * {@link MyAnalysis#functionEnter} when the function <tt>f</tt> is executed.  The <tt>functionIid</tt> can be
   * treated as the static identifier of the function <tt>f</tt>.  Note that a given function code block can
   * create several function objects, but each such object has a common <tt>functionIid</tt>, which is the iid
   * that is passed to {@link MyAnalysis#functionEnter} when the function executes.
   * @returns {{f: function, base: Object, args: Array, skip: boolean}|undefined} - If an object is returned and
   * the <tt>skip</tt> property of the object is true, then the invocation operation is skipped.
   * Original <tt>f</tt>, <tt>base</tt>, and <tt>args</tt> are replaced with that from the returned object if
   * an object is returned.
   *
   */
  invokeFunPre (iid, f, base, args, isConstructor, isMethod, functionIid, functionSid) {
    try{
      let reason = this.taintSinkRules.checkTaintAtSinkInvokeFun(f, base, args);
      if (reason) {
        this.logger.reportVerifedFlow(reason, this.payload);
        J$$.analysis.dangerousFlows.push({
          sink: reason,
          payload: this.payload
        })
        __reportDangerousFlowPlaywright && __reportDangerousFlowPlaywright({
          sink: reason,
          payload: this.payload
        });
      }
    } finally {
      return {f: f, base: base, args: args, skip: false};
    }
  };

  /**
   * This callback is called before a import module function invocation.
   * @param {string|URL} moduleURL 
   */
  importModulePre(moduleURL) {
    if ((typeof moduleURL === 'string' && moduleURL.toLowerCase().includes('hulk')) ||
        (moduleURL instanceof URL && moduleURL.origin.includes('hulk'))) {
      this.logger.reportVerifedFlow("SINK-TO-IMPORT-MODULE", this.payload);
      J$$.analysis.dangerousFlows.push({
        sink: "SINK-TO-IMPORT-MODULE",
        payload: this.payload
      })
      __reportDangerousFlowPlaywright && __reportDangerousFlowPlaywright({
        sink: "SINK-TO-IMPORT-MODULE",
        payload: this.payload
      });
    }
  }

  /**
   * This callback is called before a property of an object is written.
   * 
   * @steps
   * 1/ We will instrument the code if it has been set to .innerHTML
   * 
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} base - Base object
   * @param {*} offset - Property
   * @param {*} val - Value to be stored in <code>base[offset]</code>
   * @param {boolean} isComputed - True if property is accessed using square brackets.  For example,
   * <tt>isComputed</tt> is <tt>true</tt> if the get field operation is <tt>o[p]</tt>, and <tt>false</tt>
   * if the get field operation is <tt>o.p</tt>
   * @param {boolean} isOpAssign - True if the operation is of the form <code>o.p op= e</code>
   * @returns {{base: *, offset: *, val: *, skip: boolean} | undefined} -  If an object is returned and the <tt>skip</tt>
   * property is true, then the put field operation is skipped.  Original <tt>base</tt>, <tt>offset</tt>, and
   * <tt>val</tt> are replaced with that from the returned object if an object is returned.
   */
  putFieldPre (iid, base, offset, val, isComputed, isOpAssign) {
    try{
      let reason = this.taintSinkRules.checkTaintAtSinkPutField(base, offset, val);
      if (reason) {
        this.logger.reportVerifedFlow(reason, this.payload);
        J$$.analysis.dangerousFlows.push({
          sink: reason,
          payload: this.payload
        })
        __reportDangerousFlowPlaywright && __reportDangerousFlowPlaywright({
          sink: reason,
          payload: this.payload
        });
      }
    } finally {
    return {base: base, offset: offset, val: val, skip: false};
    }
  };
}


class TaintSinkRules {

  /**
   * @description
   * --------------------------------
   * This class defines the taint sink policy.
   * This function will be invoked during the putField operation hook.
   * 
   * SINK-TYPE-1-0:
   * - SINK-TO-SCRIPT-SRC
   * - Tainted value flows to the script.src property.
   * - E.g. script.src = taintedValue
   * - Conditions:
   *   - `base` is a script element
   *   - `offset` is 'src'
   * 
   * SINK-TYPE-1-1:
   * - SINK-TO-DOM-ELEMENT-INNERHTML
   * - Tainted value flows to the innerHTML property of a DOM element.
   * - E.g. element.innerHTML = taintedValue
   * - Conditions:
   *   - `base` is a DOM element
   *   - `offset` is 'innerHTML'
   * 
   * SINK-TYPE-1-2:
   * - SINK-TO-DOM-ELEMENT-OUTERHTML
   * - Tainted value flows to the outerHTML property of a DOM element.
   * - E.g. element.outerHTML = taintedValue
   * - Conditions:
   *   - `base` is a DOM element
   *   - `offset` is 'outerHTML'
   * 
   * SINK-TYPE-1-3:
   * - SINK-TO-DOM-ELEMENT-SRCDOC
   * - Tainted value flows to the srcdoc property of an iframe element.
   * - E.g. iframe.srcdoc = taintedValue
   * - Conditions:
   *   - `base` is an iframe element
   *   - `offset` is 'srcdoc'
   * 
   * SINK-TYPE-1-4:
   * - SINK-TO-LINK-HREF
   * - Tainted value flows to the srcdoc property of an iframe element.
   * - E.g. link.rel = 'script'; link.href = taintedValue
   * - Conditions:
   *   - `base` is an link element
   *   - `offset` is 'href'
   *   - (`base.rel` is 'script') 
   *     sometimes rel attribute is defined after href attribute
   * 
   * SINK-TYPE-2:
   * - SINK-TO-WINDOW-LOCATION
   * - Tainted value flows to the window.location property.
   * - E.g. window.location = taintedValue
   * - Conditions:
   *   - `base` is the window object
   *   - `offset` is 'location'
   * 
   * SINK-TYPE-3:
   * - SINK-TO-LOCATION-HREF
   * - Tainted value flows to the href property of the window.location object.
   * - E.g. window.location.href = taintedValue
   * - Conditions:
   *   - `base` is the window.location object
   *   - `offset` is 'href'
   * 
   * SINK-TYPE-4:
   * - SINK-TO-DOCUMENT-COOKIE
   * - Tainted value flows to the cookie property of the document object.
   * - E.g. document.cookie = taintedValue
   * - Conditions:
   *   - `base` is the document object
   *   - `offset` is 'cookie'
   * 
   * SINK-TYPE-5:
   * - SINK-TO-DOCUMENT-DOMAIN
   * - Tainted value flows to the domain property of the document object.
   * - E.g. document.domain = taintedValue
   * - Conditions:
   *   - `base` is the document object
   *   - `offset` is 'domain'
   * 
   * @param {*} base - The base object of the getField operation (which should not be a WrappedValue).
   * @param {*} offset - The offset (property name) of the getField operation.
   * @param {*} val - The value being assigned in the getField operation.
   * @param {number} iid - The instruction id.
   */
  checkTaintAtSinkPutField(base, offset, val) {
    if (
      !(typeof val === 'string' || val instanceof URL) ||
      !(val.toString().toLowerCase().includes('hulk'))
    ) {
      return;
    }

    if (base instanceof Element) {
      try {
        if (base.tagName && base.tagName.toUpperCase() === 'SCRIPT' && offset === 'src') {
          return "SINK-TO-SCRIPT-SRC";
        } else if (base.tagName && base.tagName.toUpperCase() === 'SCRIPT' && offset === 'text') {
          return "SINK-TO-SCRIPT-TEXT";
        } else if (offset === 'innerHTML' || offset === 'outerHTML') {
          return `SINK-TO-DOM-ELEMENT-${offset.toUpperCase()}`;
        } else if (offset === 'srcdoc') {
          return "SINK-TO-DOM-ELEMENT-SRCDOC";
        } else if (base.tagName && base.tagName.toUpperCase() === 'LINK' && offset === 'href') {
          return "SINK-TO-LINK-HREF";
        }
      } catch (e) {
        // Have seen exceptions where base.tagName will cause Illegal invocation error
      }
    }

    if (base === window && offset === 'location') {
      return "SINK-TO-WINDOW-LOCATION";
    }

    if (base === window.location && offset === 'href') {
      return "SINK-TO-LOCATION-HREF";
    }

    if (base === document && offset === 'cookie') {
      return "SINK-TO-DOCUMENT-COOKIE";
    }

    if (base === document && offset === 'domain') {
      return "SINK-TO-DOCUMENT-DOMAIN";
    }

    return false;
  }

  /**
   * @description
   * --------------------------------
   * This function will be invoked during the call operation hook
   * 
   * @param {Function} f - The function that is being called.
   * @param {*} base - The base object of the function call.
   * @param {Array} args - The arguments to the function.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   */
  checkTaintAtSinkInvokeFun(f, base, args) {
    args = Array.from(args);
    const hasTaintedArgs = args.some(
      (arg) => (typeof arg === 'string' || arg instanceof URL) && arg.toString().toLowerCase().includes('hulk')
    );

    if (f.name === 'eval' && args.length && hasTaintedArgs) {
      return "SINK-TO-EVAL";
    }

    if (f.name === 'Function' && args.length && hasTaintedArgs) {
      return "SINK-TO-FUNCTION";
    }
  
    if ((f.name === 'setTimeout' || f.name === 'setInterval') && args.length && hasTaintedArgs) {
      return `SINK-TO-${f.name.toUpperCase()}`;
    }

    if (base === document && (f.name === 'write' || f.name === 'writeln') && args.length && hasTaintedArgs) {
      return `SINK-TO-DOCUMENT-${f.name.toUpperCase()}`;
    }


    if (f.name === 'setAttribute' && base && base.tagName && base.tagName.toUpperCase() === 'SCRIPT' &&
        args.length >= 2 && (typeof args[1] === 'string' || args[1] instanceof URL) &&
        args[1].toString().toLowerCase().includes('hulk')
    ) {
      return "SINK-TO-SETATTRIBUTE-SCRIPT-SRC";
    }

    if (f.name === 'fetch' && args.length && hasTaintedArgs) {
      return "SINK-TO-FETCH";
    }

    // Assume the base's toString shouldn't be overwritten
    // If it is overwritten, we will get recursive function call
    if (this.safeToString(base) === '[object XMLHttpRequest]' && f.name === 'open' &&
        args.length && hasTaintedArgs
    ) {
      return "SINK-TO-XMLHTTPREQUEST-OPEN";
    }

    if (this.isLocationObject(base) && (f.name === 'replace' || f.name === 'assign') &&
        args.length && hasTaintedArgs
    ) {
      return `SINK-TO-LOCATION-${f.name.toUpperCase()}`;
    }

    // if (base === JSON && f.name === 'parse') {
    //   if (args.length && TaintHelper.isTainted(args[0])) {
    //     return ["SINK-TO-JSON-PARSE", args[0]];
    //   }
    // }

    if (
      (base === window.localStorage || base === window.sessionStorage) &&
      f.name === 'setItem' &&
      args.length &&
      (typeof args[1] === 'string' || args[1] instanceof URL) &&
      args[1].toString().toLowerCase().includes('hulk')
    ) {
      return `SINK-TO-${base === window.localStorage ? 'LOCALSTORAGE' : 'SESSIONSTORAGE'}-SETITEM`;
    }

    return false;
  }

  isDOMElement(element) {
    return element instanceof Element;
  }

  isLocationObject(obj) {
    return obj === window.location || obj === location;
  }

  safeToString(value) {
    try {
      if (value === null || value === undefined) {
        return value + '';
      }

      if (this.isPrimitive(value)) {
        return value.toString();
      } else {
        // Hopefully this will not trigger any getter or user-defined toString
        if (value instanceof RegExp) {
          return value.toString();
        }
        return Object.prototype.toString.call(value);
      }
      
    } catch (e) {
      return '[Unable to convert to string]';
    }
  }

  isPrimitive(value) {
    return value !== Object(value);
  }

}