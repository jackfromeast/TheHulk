import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { ConditionBuilder } from '../rule-condition.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';
import { Utils } from '../../utils/util.js';

export class ReflectBuiltinsTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();

    if (!Utils) {
      J$$.analysis.logger.error('Utils is not defined');
    }
  }

  /**
   * Define Reflect built-ins that are affected by taint and need custom handling.
   */
  supportedReflectBuiltins = {
    'get': [Reflect.get, this.getReflectModel, 'FIRST_ARG_TAINTED'],
  };

  noneAffectBuiltins = {
    'set': Reflect.set,
    'apply': Reflect.apply,
    'ownKeys':  Reflect.ownKeys,
    'isExtensible': Reflect.isExtensible,
    'preventExtensions':  Reflect.preventExtensions,
  };

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedReflectBuiltins)) {
      const condition = ConditionBuilder.makeCondition(fGroup[2]);
      const rule = RuleBuilder.makeRule(fGroup[0], condition, fGroup[1]);
      this.addRule(fGroup[0], rule);
    }

    for (const [fName, fGroup_0] of Object.entries(this.noneAffectBuiltins)) {
      const rule = RuleBuilder.makeNoneRule(fGroup_0);
      this.addRule(fGroup_0, rule);
    }
  }

  addRule(func, rule) {
    this.ruleDict.push({ func, rule });
  }

  getRule(func) {
    const found = this.ruleDict.find(x => x.func === func);
    return found ? found.rule : null;
  }

  /**
   * @description
   * Apply the taint propagation rule for the Proxy 'get' trap.
   * 
   * @condition
   * Condition Barrier: BASE_TAINTED_OR_PROP_TAINTED
   * 
   * @usage
   * Reflect.get(target, propertyKey, receiver)
   * 
   * @example
   * TYPE-1:
   * Reflect.get(TAINTED(target), "prop")
   * -> TAINTED(value)
   * 
   * @param {Object} target - The target object.
   * @param {String} property - The property name.
   * @param {Object} receiver - The receiver object.
   * @param {*} result - The result of the get operation.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  getReflectModel(base, args, reflected, result, iid) {
    if (TaintHelper.isTainted(args[0])) {
      let taintInfo = TaintHelper.getTaintInfo(args[0]);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'Proxy:get', property, [target, property, receiver], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }
}
