import { TaintValue, WrappedValue } from './values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from './values/taint-info.js';

J$$.wrapTaintWithIID = function (val, iid) {
  let taintInfo = new TaintInfo(iid, "ManuallyAdded", new TaintPropOperation("ManuallyAdded", []));
  return new TaintValue(val, taintInfo);
}

J$$.wrapTaint = function (val, iid) {
  let taintInfo = new TaintInfo(-1, "ManuallyAdded", new TaintPropOperation("ManuallyAdded", []));
  return new TaintValue(val, taintInfo);
}