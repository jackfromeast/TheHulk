import {WrappedValue, _, TaintValue} from './values/wrapped-values.js'
import {TaintInfo, TaintPropOperation} from './values/taint-info.js'


export class TaintSinkRules {

  /**
   * @description
   * --------------------------------
   * This class defines the taint sink policy
   * This function will be invoked during the putField operation hook
   * 
   * @TODO
   * add sink descriptions for the following cases
   * 
   * @param {*} base - The base object of the getField operation. (which not be a WrappedValue)
   * @param {*} offset - The offset of the getField operation.
   * @param {*} val - The value of the getField operation.
   * @param {number} iid - The instruction id.
   */
  checkTaintAtSinkPutField(base, offset, val) {

    if (!this.isTainted(val)) { return false; }

    if (base instanceof Element) {
      if (base.tagName && base.tagName.toUpperCase() === 'SCRIPT' && offset === 'src') {
        if (this.isTainted(val)) {
          return "SINK-TO-SCRIPT-SRC";
        }
      } else if (offset === 'innerHTML' || offset === 'outerHTML') {
        if (this.isTainted(val)) {
          return `SINK-FROM-DOM-ELEMENT-${offset.toUpperCase()}`;
        }
      }
    }

    if (base === window && offset === 'location') {
      if (this.isTainted(val)) {
        return "SINK-FROM-WINDOW-LOCATION";
      }
    }

    if (base === window.location && offset === 'href') {
      if (this.isTainted(val)) {
        return "SINK-FROM-LOCATION-HREF";
      }
    }

    if (base === document && offset === 'cookie') {
      if (this.isTainted(val)) {
        return "SINK-FROM-DOCUMENT-COOKIE";
      }
    }

    if (base === document && offset === 'domain') {
      if (this.isTainted(val)) {
        return "SINK-FROM-DOCUMENT-DOMAIN";
      }
    }
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
      if (args.length && this.isTainted(args[0])) {
        return ["SINK-TO-EVAL", args[0]];
      }
    }

    if (f.name === 'setTimeout' || f.name === 'setInterval') {
      if (args.length && this.isTainted(args[0])) {
        return [`SINK-TO-${f.name.toUpperCase()}`, args[0]];
      }
    }

    if (base === document) {
      if (f.name === 'write' || f.name === 'writeln') {
        if (args.length && this.isTainted(args[0])) {
          return [`SINK-TO-DOCUMENT-${f.name.toUpperCase()}`, args[0]];
        }
      }
    }

    if (f.name === 'insertAdjacentHTML' && isDOMElement(base)) {
      if (args.length >= 2 && this.isTainted(args[1])) {
        return ["SINK-TO-INSERTADJACENTHTML", args[1]];
      }
    }

    if (f.name === 'setAttribute' && base && base.tagName && base.tagName.toUpperCase() === 'SCRIPT') {
      if (args.length >= 2 && this.isTainted(args[1])) {
        return ["SINK-TO-SETATTRIBUTE-SCRIPT-SRC", args[1]];
      }
    }

    if (f.name === 'fetch') {
      if (args.length && this.isTainted(args[0])) {
        return ["SINK-TO-FETCH", args[0]];
      }
    }

    if (base.toString() === '[object XMLHttpRequest]' && f.name === 'open') {
      if (args.length && this.isTainted(args[1])) {
        return ["SINK-TO-XMLHTTPREQUEST-OPEN", args[1]];
      }
    }

    if (isLocationObject(base) && (f.name === 'replace' || f.name === 'assign')) {
      if (args.length && this.isTainted(args[0])) {
        return [`SINK-TO-LOCATION-${f.name.toUpperCase()}`, args[0]];
      }
    }

    if (base === JSON && f.name === 'parse') {
      if (args.length && this.isTainted(args[0])) {
        return ["SINK-TO-JSON-PARSE", args[0]];
      }
    }

    if ((base === window.localStorage || base === window.sessionStorage) && f.name === 'setItem') {
      if (args.length && this.isTainted(args[1])) {
        return [`SINK-TO-${base === window.localStorage ? 'LOCALSTORAGE' : 'SESSIONSTORAGE'}-SETITEM`, args[1]];
      }
    }

    return [false, null];
  }

  isTainted(value) {
    return value instanceof TaintValue;
  }

  isDOMElement(element) {
    return element instanceof Element;
  }

  isLocationObject(obj) {
    return obj === window.location || obj === location;
  }

}