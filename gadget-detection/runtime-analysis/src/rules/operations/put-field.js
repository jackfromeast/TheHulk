import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js'
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js'
import { RuleBuilder } from '../rule-builder.js'
import { TaintPropRules } from '../rules.js'
import { TaintHelper } from '../../taint-helper.js'
import { Utils } from '../../utils/util.js'


/**
 * @description
 * --------------------------------
 * Class to manage taint propagation rules for property lookup operations.
 */
export class PutFieldTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();
  }

  /**
   * @description
   * --------------------------------
   * Function to build rules for property setting operations.
   * 
   * Setting properties on DOM nodes should always strip the taint.
   */
  buildRules() {
    const condition = (base, offset, val) => { return true; };
    const defaultRule = RuleBuilder.makeRulePutField(condition, this.defaultPutFieldModel);
    this.addRule('default', 'default', defaultRule);

    const DOMNodesPutFieldRule = RuleBuilder.makeRulePutField(condition, this.DOMNodesPutFieldModel);
    this.addRule('DOMNodes', 'default', DOMNodesPutFieldRule);
  }

  /**
   * @description
   * --------------------------------
   * Adds a rule to the rule dictionary.
   * 
   * @param {string} operator - The unary operator.
   * @param {Function} rule - The rule function to be added.
   */
  addRule(base, offset, rule) {
    this.ruleDict.push({base, offset, rule});
  }

  /**
   * @description
   * --------------------------------
   * Retrieves a rule for the specified putField operator.
   * 
   * Currently, we propagate all the property lookups all the from a TaintValue
   * Therefore, we return the rule with the key ('all', 'all')
   * 
   * @param {string} operator - The unary operator.
   * @returns {Function|null} The rule function if found, otherwise null.
   */
  getRule(base, offset) {
    if (Utils.isDOMNode(base)) {
      return this.ruleDict.find(x => x.base === 'DOMNodes').rule;
    }else{
      return this.ruleDict.find(x => x.base === 'default').rule;
    }
  }

  /**
   * @description
   * --------------------------------
   * Rule to propagate taint for property setting operations.
   * Always strip the taint from the value.
   * 
   * @param {*} base 
   * @param {*} offset 
   * @param {*} val 
   */
  DOMNodesPutFieldModel(base, offset, val, iid) {
    if (!base instanceof Element) {
      throw new Error('DOMNodesPutFieldModel: base is not an Element');
    }

    val = TaintHelper.concreteWrappedOnly(val);

    let offset_c = TaintHelper.concreteWrappedOnly(offset);
    if (TaintHelper.isTainted(base)) {
      TaintHelper.concreteWrappedOnly(base)[offset_c] = val;
    }else{
      base[offset_c] = val;
    }

    return val;
  }

  /**
   * @description
   * --------------------------------
   * Rule to propagate taint for property setting operations.
   * 
   * @param {*} base 
   * @param {*} offset 
   * @param {*} val 
   */
  defaultPutFieldModel(base, offset, val, iid) {
    let offset_c = TaintHelper.concrete(offset)[0];
    if (TaintHelper.isTainted(base)) {
      TaintHelper.concrete(base)[0][offset_c] = val;
    }else{
      base[offset_c] = val;
    }

    return val;
  }
}