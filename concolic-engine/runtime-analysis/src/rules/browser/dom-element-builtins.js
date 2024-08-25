import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { ConditionBuilder } from '../rule-condition.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';
import { Utils } from '../../utils/util.js';

export class DOMElementBuiltinsTaintPropRules {
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
   * We support rules for the DOMElement builtins that follow:
   */
  supportedDOMElementBuiltins = {
    'getAttribute': [Element.prototype.getAttribute, this.getAttributeModel, 'BASE_TAINTED']
  };

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedDOMElementBuiltins)) {
      const condition = ConditionBuilder.makeCondition(fGroup[2]);
      const rule = RuleBuilder.makeRule(fGroup[0], condition, fGroup[1]);
      this.addRule(fGroup[0], rule);
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
   * Apply the taint propagation rule for the getAttribute function for elements.
   * 
   * @condition
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * element.getAttribute("prop")
   * 
   * @example
   * TYPE-1:
   * TAINTED(element).getAttribute("prop")
   * 
   * @param {Function} base - The TrustedTypes function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  getAttributeModel(base, args, reflected, result, iid) {
    let taintInfoPairs = [];
    let taintInfo = TaintHelper.getTaintInfo(base);
    taintInfo ? taintInfoPairs.push(['base', taintInfo]) : null;

    if (taintInfoPairs.length > 0) {
      const newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'Element:getAttribute', base, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }
}
