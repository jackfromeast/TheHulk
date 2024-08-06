import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { ConditionBuilder } from '../rule-condition.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';
import { Utils } from '../../utils/util.js';

export class TrustedTypesTaintPropRules {
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
   * We support rules for the TrustedTypes builtins that follow:
   * 
   * Different from other builtins, the first element in the array is the function name, e.g. 'createScript'.
   * We will use Utils.isTrustedTypeFunction(f, fName) to check if the function is a TrustedType function.
   */
  supportedArrayBuiltins = {
    'createScript': ["createScript", this.createScriptTrustedTypesModel, 'FIRST_ARG_TAINTED'],
    'createScriptURL': ["createScriptURL", this.createScriptURLTrustedTypesModel, 'FIRST_ARG_TAINTED'],
    'createHTML': ["createHTML", this.createHTMLTrustedTypesModel, 'FIRST_ARG_TAINTED'],
  };

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedArrayBuiltins)) {
      const condition = ConditionBuilder.makeCondition(fGroup[2]);
      const rule = RuleBuilder.makeDynamicRule(null, condition, fGroup[1]);
      this.addRule(fGroup[0], rule);
    }
  }

  addRule(func, rule) {
    this.ruleDict.push({ func, rule });
  }

  getRule(func) {
    const found = this.ruleDict.find(x => Utils.isTrustedTypeFunction(func, x.func));
    return found ? found.rule : null;
  }

  /**
   * @description
   * Apply the taint propagation rule for the createScript TrustedTypes function.
   * 
   * @condition
   * Condition Barrier: FIRST_ARG_TAINTED
   * 
   * @usage
   * createScript(input)
   * 
   * @example
   * TYPE-1:
   * createScript(TAINTED('scriptContent'))
   * -> TAINTED(scriptContent)
   * 
   * @param {Function} base - The TrustedTypes function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  createScriptTrustedTypesModel(base, args, reflected, result, iid) {
    const taintInfo = TaintHelper.getTaintInfo(args[0]);

    if (taintInfo) {
      const newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'TrustedTypes:createScript', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }

  /**
   * @description
   * Apply the taint propagation rule for the createScriptURL TrustedTypes function.
   * 
   * @condition
   * Condition Barrier: FIRST_ARG_TAINTED
   * 
   * @usage
   * createScriptURL(input)
   * 
   * @example
   * TYPE-1:
   * createScriptURL(TAINTED('https://example.com/script.js'))
   * -> TAINTED('https://example.com/script.js')
   * 
   * @param {Function} base - The TrustedTypes function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  createScriptURLTrustedTypesModel(base, args, reflected, result, iid) {
    const taintInfo = TaintHelper.getTaintInfo(args[0]);

    if (taintInfo) {
      const newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'TrustedTypes:createScriptURL', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }

  /**
   * @description
   * Apply the taint propagation rule for the createHTML TrustedTypes function.
   * 
   * @condition
   * Condition Barrier: FIRST_ARG_TAINTED
   * 
   * @usage
   * createHTML(input)
   * 
   * @example
   * TYPE-1:
   * createHTML(TAINTED('<div>content</div>'))
   * -> TAINTED('<div>content</div>')
   * 
   * @param {Function} base - The TrustedTypes function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  createHTMLTrustedTypesModel(base, args, reflected, result, iid) {
    const taintInfo = TaintHelper.getTaintInfo(args[0]);

    if (taintInfo) {
      const newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'TrustedTypes:createHTML', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
  }
}
