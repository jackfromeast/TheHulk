import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js';
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js';
import { RuleBuilder } from '../rule-builder.js';
import { ConditionBuilder } from '../rule-condition.js';
import { TaintPropRules } from '../rules.js';
import { TaintHelper } from '../../taint-helper.js';
import { Utils } from '../../utils/util.js';

export class ObjectBuiltinsTaintPropRules {
  constructor() {
    this.ruleDict = [];
    this.buildRules();

    if (!Utils) {
      J$$.analysis.logger.error('Utils is not defined');
    }
  }

  /**
   * For object built-ins, we select the builtins that will load values from the object.
   * And if the object itself is tainted, we propagate the taint to the result.
   * We don't worry about the values inside the object.
   */
  supportedObjectBuiltins = {
    'assign': [Object.assign, this.assignObjectModel, 'ANY_ARGS_TAINTED'],
    'fromEntries': [Object.fromEntries, this.fromEntriesObjectModel, 'FIRST_ARG_TAINTED'],
    'entries': [Object.entries, this.entriesObjectModel, 'FIRST_ARG_TAINTED'],
    'values': [Object.values, this.valuesObjectModel, 'FIRST_ARG_TAINTED'],
  };

  noneAffectBuiltins = {
    'keys': Object.keys,
  };

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedObjectBuiltins)) {
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
   * Apply the taint propagation rule for the Object.assign function.
   * 
   * @condition
   * Condition Barrier: ANY_ARGS_TAINTED
   * 
   * @usage
   * Object.assign(target, ...sources)
   * 
   * @example
   * TYPE-1:
   * Object.assign({}, TAINTED({a: 1}))
   * -> TAINTED({a: 1})
   * 
   * @param {Function} f - The Object built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
   assignObjectModel(base, args, reflected, result, iid) {
    let taintInfo = null;
    
    // Skip the first argument which is the target object
    for (let i = 1; i < args.length; i++) {
      if (TaintHelper.isTainted(args[i])) {
        taintInfo = TaintHelper.getTaintInfo(args[i]);
        break;
      }
    }

    if (taintInfo) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'Object:assign', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * Apply the taint propagation rule for the Object.fromEntries function.
   * 
   * @condition
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * Object.fromEntries(iterable)
   * 
   * @example
   * TYPE-1:
   * Object.fromEntries(TAINTED([['a', 1], ['b', 2]]))
   * -> TAINTED({a: 1, b: 2})
   * 
   * @param {Function} f - The Object built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  fromEntriesObjectModel(base, args, reflected, result, iid) {
    if (TaintHelper.isTainted(args[0])) {
      let taintInfo = TaintHelper.getTaintInfo(args[0]);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'Object:fromEntries', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * Apply the taint propagation rule for the Object.entries function.
   * 
   * @condition
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * Object.entries(obj)
   * 
   * @example
   * TYPE-1:
   * Object.entries(TAINTED({a: 1, b: 2}))
   * -> TAINTED([["a", 1], ["b", 2]])
   * 
   * @param {Function} f - The Object built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  entriesObjectModel(base, args, reflected, result, iid) {
    if (TaintHelper.isTainted(args[0])) {
      let taintInfo = TaintHelper.getTaintInfo(args[0]);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'Object:entries', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  /**
   * @description
   * Apply the taint propagation rule for the Object.values function.
   * 
   * @condition
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * Object.values(obj)
   * 
   * @example
   * TYPE-1:
   * Object.values(TAINTED({a: 1, b: 2}))
   * -> TAINTED([1, 2])
   * 
   * @param {Function} f - The Object built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  valuesObjectModel(base, args, reflected, result, iid) {
    if (TaintHelper.isTainted(args[0])) {
      let taintInfo = TaintHelper.getTaintInfo(args[0]);
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfo, 'Object:values', null, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    return result;
  }

  // ToString, fill me!
}
