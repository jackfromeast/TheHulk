import { WrappedValue, _, TaintValue } from './values/wrapped-values.js'
import { TaintInfo, TaintPropOperation } from './values/taint-info.js'
import { Utils } from './utils/util.js';
import { TaintHelper } from './taint-helper.js';

export class TaintSinkRules {

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
    this.reportClobberableSinkPutField(base, offset);
    if (!TaintHelper.isTainted(val)) { return false; }
    if (base instanceof WrappedValue) { base = base.getConcrete(); }

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

    if (f.name === 'eval') {
      this.reportClobberableSink("SINK-TO-EVAL");
      if (args.length && TaintHelper.isTainted(args[0])) {
        return ["SINK-TO-EVAL", args[0]];
      }
    }

    if (f.name === 'Function') {
      this.reportClobberableSink("SINK-TO-FUNCTION");
      if (args.length && Array.from(args).some(arg => TaintHelper.isTainted(arg))) {
        for (let arg of Array.from(args)) {
          if (TaintHelper.isTainted(arg)) {
            return ["SINK-TO-FUNCTION", arg];
          }
        }
      }
    }

    if (f.name === 'setTimeout' || f.name === 'setInterval') {
      this.reportClobberableSink(`SINK-TO-${f.name.toUpperCase()}`);
      if (args.length && TaintHelper.isTainted(args[0])) {
        return [`SINK-TO-${f.name.toUpperCase()}`, args[0]];
      }
    }

    if (base === document) {
      if (f.name === 'write' || f.name === 'writeln') {
        this.reportClobberableSink(`SINK-TO-DOCUMENT-${f.name.toUpperCase()}`);
        if (args.length && TaintHelper.isTainted(args[0])) {
          return [`SINK-TO-DOCUMENT-${f.name.toUpperCase()}`, args[0]];
        }
      }
    }

    if (f.name === 'insertAdjacentHTML' && this.isDOMElement(base)) {
      this.reportClobberableSink("SINK-TO-INSERTADJACENTHTML");
      if (args.length >= 2 && TaintHelper.isTainted(args[1])) {
        return ["SINK-TO-INSERTADJACENTHTML", args[1]];
      }
    }

    if (f.name === 'setAttribute' && base && base.tagName && base.tagName.toUpperCase() === 'SCRIPT') {
      this.reportClobberableSink("SINK-TO-SETATTRIBUTE-SCRIPT-SRC");
      if (args.length >= 2 && TaintHelper.isTainted(args[1])) {
        return ["SINK-TO-SETATTRIBUTE-SCRIPT-SRC", args[1]];
      }
    }

    if (f.name === 'fetch') {
      this.reportClobberableSink("SINK-TO-FETCH");
      if (args.length && TaintHelper.isTainted(args[0])) {
        return ["SINK-TO-FETCH", args[0]];
      }
    }

    // Assume the base's toString shouldn't be overwritten
    // If it is overwritten, we will get recursive function call
    if (Utils.safeToString(base) === '[object XMLHttpRequest]' && f.name === 'open') {
      this.reportClobberableSink("SINK-TO-XMLHTTPREQUEST-OPEN");
      if (args.length && TaintHelper.isTainted(args[1])) {
        return ["SINK-TO-XMLHTTPREQUEST-OPEN", args[1]];
      }
    }

    if (this.isLocationObject(base) && (f.name === 'replace' || f.name === 'assign')) {
      this.reportClobberableSink(`SINK-TO-LOCATION-${f.name.toUpperCase()}`);
      if (args.length && TaintHelper.isTainted(args[0])) {
        return [`SINK-TO-LOCATION-${f.name.toUpperCase()}`, args[0]];
      }
    }

    if (base === JSON && f.name === 'parse') {
      this.reportClobberableSink("SINK-TO-JSON-PARSE");
      if (args.length && TaintHelper.isTainted(args[0])) {
        return ["SINK-TO-JSON-PARSE", args[0]];
      }
    }

    if ((base === window.localStorage || base === window.sessionStorage) && f.name === 'setItem') {
      this.reportClobberableSink(`SINK-TO-${base === window.localStorage ? 'LOCALSTORAGE' : 'SESSIONSTORAGE'}-SETITEM`);
      if (args.length && TaintHelper.isTainted(args[1])) {
        return [`SINK-TO-${base === window.localStorage ? 'LOCALSTORAGE' : 'SESSIONSTORAGE'}-SETITEM`, args[1]];
      }
    }

    return [false, null];
  }

  isDOMElement(element) {
    return element instanceof Element;
  }

  isLocationObject(obj) {
    return obj === window.location || obj === location;
  }

  reportClobberableSink(sinkType) {
    if (!J$$.analysis.logger.logClobberableSink) {
      return;
    }
    if (J$$.analysis.clobberableSinks[sinkType]) {
      J$$.analysis.clobberableSinks[sinkType] += 1;
    } else {
      J$$.analysis.clobberableSinks[sinkType] = 1;
    }
  }

  reportClobberableSinkPutField(base, offset) {
    if (!J$$.analysis.logger.clobberableSinks) {
      return;
    }

    if (base instanceof WrappedValue) { base = base.getConcrete(); }

    if (base instanceof Element) {
      try {
        if (base.tagName && base.tagName.toUpperCase() === 'SCRIPT' && offset === 'src') {
          reportClobberableSink("SINK-TO-SCRIPT-SRC");
          return;
        } else if (base.tagName && base.tagName.toUpperCase() === 'SCRIPT' && offset === 'text') {
          reportClobberableSink("SINK-TO-SCRIPT-TEXT");
          return;
        } else if (offset === 'innerHTML' || offset === 'outerHTML') {
          reportClobberableSink(`SINK-TO-DOM-ELEMENT-${offset.toUpperCase()}`);
          return;
        } else if (offset === 'srcdoc') {
          reportClobberableSink("SINK-TO-DOM-ELEMENT-SRCDOC");
          return;
        } else if (base.tagName && base.tagName.toUpperCase() === 'LINK' && offset === 'href') {
          reportClobberableSink("SINK-TO-LINK-HREF");
          return;
        }
      } catch (e) {
        // Have seen exceptions where base.tagName will cause Illegal invocation error
      }
    }

    if (base === window && offset === 'location') {
      reportClobberableSink("SINK-TO-WINDOW-LOCATION");
      return;
    }

    if (base === window.location && offset === 'href') {
      reportClobberableSink("SINK-TO-LOCATION-HREF");
      return;
    }

    if (base === document && offset === 'cookie') {
      reportClobberableSink("SINK-TO-DOCUMENT-COOKIE");
      return;
    }

    if (base === document && offset === 'domain') {
      reportClobberableSink("SINK-TO-DOCUMENT-DOMAIN");
      return;
    }
  }
}