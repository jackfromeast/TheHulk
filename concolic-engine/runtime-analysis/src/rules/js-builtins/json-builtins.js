import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { ConditionBuilder } from '../rule-condition.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';
import { Utils } from '../../utils/util.js';

export class JSONBuiltinsRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();

    if (!Utils) {
      J$$.analysis.logger.error('Utils is not defined');
    }
  }

  supportedJSONBuiltins = {
    'parse': [JSON.parse, this.parseJSONModel, 'FIRST_ARG_TAINTED'],
    'stringify': [JSON.stringify, this.stringifyJSONModel, 'FIRST_ARG_TAINTED_RECURSIVE'],
  };

  noneAffectBuiltins = {};

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedJSONBuiltins)) {
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
   * Apply the taint propagation rule for the JSON.parse function.
   * 
   * @condition
   * Condition Barrier: FIRST_ARG_TAINTED
   * 
   * @usage
   * JSON.parse(text)
   * JSON.parse(text, reviver)
   * 
   * @example
   * TYPE-1:
   * JSON.parse(TAINTED('{"key": "value"}'))
   * -> TAINTED({"key": "value"})
   * 
   * @param {Function} f - The JSON built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  parseJSONModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(args[0]);

    if (taintInfo) { 
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'JSON:parse', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }

  /**
   * @description
   * Apply the taint propagation rule for the JSON.stringify function.
   * 
   * @condition
   * Condition Barrier: BASE_TAINTED or FIRST_ARG_TAINTED
   * 
   * @usage
   * JSON.stringify(value)
   * JSON.stringify(value, replacer)
   * JSON.stringify(value, replacer, space)
   * 
   * @example
   * TYPE-1:
   * JSON.stringify(TAINTED({"key": "value"}))
   * -> TAINTED('{"key": "value"}')
   * 
   * @param {Function} f - The JSON built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  stringifyJSONModel(base, args, reflected, result, iid) {
    let taintInfo = null;
    
    if (TaintHelper.risTainted(args[0])) {
      taintInfo = TaintHelper.rgetTaintInfo(args[0]);
    }

    if (taintInfo) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'JSON:stringify', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }
}