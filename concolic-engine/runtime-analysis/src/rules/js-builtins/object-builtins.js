import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from './../rule-builder.js';
import { TaintPropRules } from './../rules.js';
import { TaintHelper } from '../../taint-helper.js';


class ObjectBuiltinTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();
  }

}


export { ObjectBuiltinTaintPropRules };
