import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { ConditionBuilder } from '../rule-condition.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';
import { Utils } from '../../utils/util.js';

export class ProxyBuiltinsTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();
    this.proxyTag = Symbol('proxy');

    if (!Utils) {
      J$$.analysis.logger.error('Utils is not defined');
    }
  }

  /**
   * @description
   * --------------------------------
   * Define Proxy traps that are affected by taint and need custom handling.
   * 
   */
  supportedProxyBuiltins = {
    // 'Proxy': [Proxy, this.ProxyConstructorModel, 'ALL'],
  };

  /**
   * @description
   * --------------------------------
   * Here is a list of built-ins that use none affected taint propagation rules.
   * 
   * These built-ins will not affect taint propagation even if their arguments are tainted.
   * This explicit list helps in preventing the invocation of taint logic unnecessarily.
   */
  noneAffectBuiltins = {
    'Proxy': Proxy,
    'Proxy.revocable': Proxy.revocable
  };

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedProxyBuiltins)) {
      const condition = ConditionBuilder.makeCondition(fGroup[2]);
      const rule = RuleBuilder.makeRule(fGroup[0], condition, fGroup[1]);
      this.addRule(fGroup[0], rule);
    }

    for (const [fName, fGroup_0] of Object.entries(this.noneAffectBuiltins)) {
      if (fName === "Proxy") {
        const rule = RuleBuilder.makeNoneRuleForConstructor(fGroup_0);
        this.addRule(fGroup_0, rule);
        continue;
      }
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

}