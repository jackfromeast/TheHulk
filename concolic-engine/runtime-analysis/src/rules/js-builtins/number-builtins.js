import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { ConditionBuilder } from '../rule-condition.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';
import { Utils } from '../../utils/util.js';

export class NumberBuiltinsTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();

    if (!Utils) {
      J$$.analysis.logger.error('Utils is not defined');
    }
  }

  /**
   * @description
   * --------------------------------
   * We support rules for the number builtins that follow:
   * 1/ The return value needs to be tainted if the number itself is tainted.
   * 2/ The return value is in type of String, not Boolean.
   * 
   * Builtins that need to be handled:
   * - Number.prototype.toString
   * 
   * @TODO
   * --------------------------------
   * TODO: condition check function should also be added to the rules Dict
   * E.g. condition: BASE_TAINTED, etc.
   */
  supportedNumberBuiltins = {
    'toString': [Number.prototype.toString, this.toStringNumberModel, 'BASE_TAINTED'],
    'valueOf': [Number.prototype.valueOf, this.valueOfNumberModel, 'BASE_TAINTED'],
    'toFixed': [Number.prototype.toFixed, this.toFixedNumberModel, 'BASE_TAINTED'],
  };

  noneAffectBuiltins = {
  };

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedNumberBuiltins)) {
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
   * --------------------------------
   * Apply the taint propagation rule for the toString function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * Number.prototype.toString()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * let num = TAINTED(123);
   * num.toString(); // Returns TAINTED("123")
   * 
   * @param {Object} base - The number object.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toStringNumberModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);

    if (taintInfo) { 
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'Number:toString', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the valueOf function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * Number.prototype.valueOf()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * let num = TAINTED(123);
   * num.valueOf(); // Returns TAINTED(123)
   * 
   * @param {Object} base - The number object.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  valueOfNumberModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);

    if (taintInfo) { 
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'Number:valueOf', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the toFixed function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * Number.prototype.toFixed()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * let num = TAINTED(123);
   * num.toFixed(); // Returns TAINTED("123")
   * 
   * @param {Object} base - The number object.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toFixedNumberModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(base);

    if (taintInfo) { 
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'Number:toFixed', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }
}
