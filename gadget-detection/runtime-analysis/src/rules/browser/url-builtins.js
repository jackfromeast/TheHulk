import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { ConditionBuilder } from '../rule-condition.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';
import { Utils } from '../../utils/util.js';

export class URLBuiltinsTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();

    if (!Utils) {
      J$$.analysis.logger.error('Utils is not defined');
    }
  }

  /**
   * Define Promise built-ins that are affected by taint and need custom handling.
   */
  supportedURLBuiltins = {
    'URL': [URL, this.URLConstructorModel, 'FIRST_ARG_TAINTED || SECOND_ARG_TAINTED'],
  };

  noneAffectBuiltins = {
  };

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedURLBuiltins)) {
      if (fName === 'URL') {
        const condition = ConditionBuilder.makeCondition(fGroup[2]);
        const rule = RuleBuilder.makeRuleForConstructor(fGroup[0], condition, fGroup[1]);
        this.addRule(fGroup[0], rule, true);
      }

      const condition = ConditionBuilder.makeCondition(fGroup[2]);
      const rule = RuleBuilder.makeRule(fGroup[0], condition, fGroup[1]);
      this.addRule(fGroup[0], rule);
    }

    for (const [fName, fGroup_0] of Object.entries(this.noneAffectBuiltins)) {
      const rule = RuleBuilder.makeNoneRule(fGroup_0);
      this.addRule(fGroup_0, rule);
    }
  }

  /**
   * @description
   * --------------------------------
   * Adds a rule to the rule dictionary.
   * 
   * @param {Function} function - The builtin function.
   * @param {Function} rule - The rule function to be added.
   */
  addRule(func, rule, isConstructor=false) {
    if (isConstructor) {
      this.ruleDict.push({constructor: func, rule: rule});
    } else {
      this.ruleDict.push({func, rule});
    }
  }

  getRuleForConstructor(func) {
    const found = this.ruleDict.find(x => x.constructor === func);
    return found ? found.rule : null;
  }


  getRule(func) {
    const found = this.ruleDict.find(x => x.func === func);
    return found ? found.rule : null;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the URL constructor.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: FIRST_ARG_TAINTED || SECOND_ARG_TAINTED
   * 
   * @usage
   * --------------------------------
   * new URL(value)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * new URL(TAINTED("Hello"))
   * -> TAINTED("Hello")
   * 
   * @param {Function} f - The string built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  URLConstructorModel(base, args, reflected, result, iid) {
    let taintInfo = TaintHelper.getTaintInfo(args[0]);
    let taintInfoPairs = [];
    taintInfo ? taintInfoPairs.push(['arg0', taintInfo]) : null;

    if (TaintHelper.isTainted(args[1])) {
      let taintInfo = TaintHelper.getTaintInfo(args[1]);
      taintInfo ? taintInfoPairs.push([`arg1`, taintInfo]): null;
    }

    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'URL:constructor', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }
}
