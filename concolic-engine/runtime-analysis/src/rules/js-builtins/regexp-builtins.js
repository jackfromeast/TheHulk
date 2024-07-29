import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { ConditionBuilder } from '../rule-condition.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';
import { Utils } from '../../utils/util.js';

export class RegExpBuiltinsRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();

    if (!Utils) {
      J$$.analysis.logger.error('Utils is not defined');
    }
  }

  supportedRegExpBuiltins = {
    'exec': [RegExp.prototype.exec, this.execRegExpModel, 'FIRST_ARG_TAINTED'],
    'test': [RegExp.prototype.test, this.testRegExpModel, 'FIRST_ARG_TAINTED']
  };

  noneAffectBuiltins = {};

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedRegExpBuiltins)) {
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
   * Apply the taint propagation rule for the RegExp.prototype.exec function.
   * 
   * @condition
   * Condition Barrier: FIRST_ARG_TAINTED
   * 
   * @usage
   * RegExp.prototype.exec(str)
   * 
   * @example
   * TYPE-1:
   * /abc/.exec(TAINTED("abcdef"))
   * -> TAINTED(["abc"])
   * 
   * @param {Function} f - The RegExp built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  execRegExpModel(base, args, reflected, result, iid) {
    let taintInfo = null;

    if (args.length > 0 && TaintHelper.isTainted(args[0])) {
      taintInfo = TaintHelper.getTaintInfo(args[0]);
    }

    if (taintInfo) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'RegExp:exec', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }

  /**
   * @description
   * Apply the taint propagation rule for the RegExp.prototype.test function.
   * 
   * @condition
   * Condition Barrier: FIRST_ARG_TAINTED
   * 
   * @usage
   * RegExp.prototype.test(str)
   * 
   * @example
   * TYPE-1:
   * /abc/.test(TAINTED("abcdef"))
   * -> TAINTED(true)
   * 
   * @param {Function} f - The RegExp built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  testRegExpModel(base, args, reflected, result, iid) {
    let taintInfo = null;

    if (args.length > 0 && TaintHelper.isTainted(args[0])) {
      taintInfo = TaintHelper.getTaintInfo(args[0]);
    }

    if (taintInfo) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'RegExp:test', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }
}
