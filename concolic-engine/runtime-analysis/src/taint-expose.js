import { TaintInfo, TaintPropOperation } from './values/taint-info.js';
import { TaintHelper } from './taint-helper.js'

J$$.wrapTaintWithIID = function (val, iid) {
  let taintInfo = new TaintInfo(iid, "ManuallyAdded", new TaintPropOperation("ManuallyAdded", null, [], iid));
  return TaintHelper.createTaintValue(val, taintInfo);
}

J$$.wrapTaint = function (val, iid) {
  let taintInfo = new TaintInfo(-1, "ManuallyAdded", new TaintPropOperation("ManuallyAdded", null, [], -1));
  return TaintHelper.createTaintValue(val, taintInfo);
}