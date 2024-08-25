import { WrappedValue, _, TaintValue } from '../../values/wrapped-values.js'
import { TaintInfo, TaintPropOperation } from '../../values/taint-info.js'
import { RuleBuilder } from '../rule-builder.js'
import { ConditionBuilder } from '../rule-condition.js'
import { TaintPropRules } from '../rules.js'
import { TaintHelper } from '../../taint-helper.js'
import { Utils } from '../../utils/util.js'

export class ArrayBuiltinsTaintPropRules {
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
   * We support rules for the array builtins that follow:
   * 1/ The return value need to be tainted if one of the elements in the array is tainted 
   *    and is not the return value itself.
   * 2/ The return value is in type of String, not Boolean.
   * 
   * We also need to handle the case where the element is tainted and will cause the builtins panic:
   * - TODO:
   * 
   * Builtins that don't need to be handled:
   * - Array.prototype.entries
   * - Array.prototype.keys
   * - Array.prototype.values
   * - Array.prototype.push
   * - Array.prototype.pop
   * - etc.
   * 
   * @TODO
   * --------------------------------
   * TODO: condition check function should also be added to the rules Dict
   * E.g. condition: ANY_ARGS_TAINTED OR BASE_TAINTED, FIRST_ARG_TAINTED, etc.
   * from builtins should use the FIRST_ARG_TAINTED condition
   * Now, all of them use the ANY_ARGS_TAINTED OR BASE_TAINTED condition
   */
  supportedArrayBuiltins = {
    'from': [Array.from, this.fromArrayModel, 'BASE_TAINTED || ANY_ARGS_TAINTED'],
    'join': [Array.prototype.join, this.joinArrayModel, 'BASE_TAINTED_RECURSIVE || FIRST_ARG_TAINTED_RECURSIVE'],
    'toString': [Array.prototype.toString, this.toStringArrayModel, 'BASE_TAINTED'],
    'toLocaleString': [Array.prototype.toLocaleString, this.toLocaleStringArrayModel, 'BASE_TAINTED'],

    'pop': [Array.prototype.pop, this.popArrayModel, 'BASE_TAINTED'],
    'shift': [Array.prototype.shift, this.shiftArrayModel, 'BASE_TAINTED'],
  };

  /**
   * @description
   * --------------------------------
   * Here is a list of builtins that will concretize the base and arguments if they are tainted but no taint propagation.
   * 
   * We have this list because we
   * 1/ don't want to lose the taint on base and arguments
   * 2/ don't want to propagate the taint to the return value.
   * 3/ and it will change the logic if we run the builtin with tainted arguments.
   * 
   */
  noneTaintNonePropagationBuiltins = {
    'includes': Array.prototype.includes,
    'indexOf': Array.prototype.indexOf,
  }

  /**
   * @description
   * --------------------------------
   * Here is a list of builtins that uses none affected taint propagation rules.
   * 
   * This means, even the arguments are tainted or the return value is tainted,
   * we don't do anything but call the original function.
   * 
   * We need to maintain this list becuase if invokeFunPre function doesn't find the 
   * rule for the builtins, it will concreate all the base and arguments and return value.
   * Therefore, we need to explicitly set an none-affect builtins list.
   * 
   */
  noneAffectBuiltins = {
    'push': Array.prototype.push,
    'unshift': Array.prototype.unshift,
    'slice': Array.prototype.slice,
    'reverse': Array.prototype.reverse,
    'sort': Array.prototype.sort,
    'splice': Array.prototype.splice,
    'forEach': Array.prototype.forEach,
    'map': Array.prototype.map,
    'concat': Array.prototype.concat,
    'splice': Array.prototype.splice,
    'values': Array.prototype.values,
    'filter': Array.prototype.filter,
    'reduce': Array.prototype.reduce,
    'every': Array.prototype.every,
    'flatMap': Array.prototype.flatMap,
    'reduceRight': Array.prototype.reduceRight,
    'keys': Array.prototype.keys,
    'fill': Array.prototype.fill,
    'find': Array.prototype.find,
    'findIndex': Array.prototype.findIndex,
    'findLastIndex': Array.prototype.findLastIndex,
  }

  buildRules() {
    for (const [fName, fGroup] of Object.entries(this.supportedArrayBuiltins)) {
      const condition = ConditionBuilder.makeCondition(fGroup[2]);
      const rule = RuleBuilder.makeRule(fGroup[0], condition, fGroup[1]);
      this.addRule(fGroup[0], rule);
    }

    for (const [fName, fGroup_0] of Object.entries(this.noneAffectBuiltins)) {
      const rule = RuleBuilder.makeNoneRule(fGroup_0);
      this.addRule(fGroup_0, rule);
    }

    for (const [fName, fGroup_0] of Object.entries(this.noneTaintNonePropagationBuiltins)) {
      const condition = ConditionBuilder.makeCondition("NONE");
      const rule = RuleBuilder.makeRule(fGroup_0, condition, ()=>{});
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
   * Apply the taint propagation rule for the from function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: FIRST_ARG_TAINTED
   * 
   * @usage
   * --------------------------------
   * Array.from(arrayLike)
   * Array.from(arrayLike, mapFn)
   * Array.from(arrayLike, mapFn, thisArg)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * Array.from("abc", x => x + x)
   * TAINTED("abc") -> [TAINTED("aa"), TAINTED("bb"), TAINTED("cc")]
   * 
   * TYPE-2:
   * RegExpStringIterator is an array-like object usually comes from the matchAll function.
   * E.g. TAINTED("abcabdadc").matchAll(/a/g)
   * Array.from(RegExpStringIterator)
   * TAINTED(RegExpStringIterator) -> [[TAINTED("a"), index=?], [TAINTED("a"), index=?], [TAINTED("a"), index=?]]
   * 
   * TYPE-3:
   * Array.from([TAINTED("a"), "b", "c"])
   * -> [TAINTED("a"), "b", "c"]
   * 
   * @param {Function} f - The array built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   * 
   * // TODO: FORGET TO ADD THE NEW TAINT OPERATION
   */
  fromArrayModel(base, args, reflected, result, iid) {
    let argsArray = Utils.getArrayLikeArguments(args, reflected);
    let taintInfoPairs = [];
    taintInfoPairs.push(['arg0', TaintHelper.getTaintInfo(argsArray[0])]);

    if (taintInfoPairs.length == 0) { return result; }

    // TYPE-1
    if (Utils.isString(argsArray[0])) {
      for (let i = 0; i < result.length; i++) {
        let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'Array:from', base, argsArray, iid);
        result[i] = TaintHelper.createTaintValue(result[i], newTaintInfo);
      }
    }

    // TYPE-2
    else if (Utils.isRegExpStringIterator(argsArray[0])) {
      for (let i = 0; i < result.length; i++) {
        let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'Array:from', base, argsArray, iid);
        result[i][0] = TaintHelper.createTaintValue(result[i][0], newTaintInfo);
      }
    }

    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the join function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED or FIRST_ARG_TAINTED
   * 
   * @usage
   * --------------------------------
   * Array.prototype.join(separator)
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED(["a", "b", "c"]).join(", ")
   * -> TAINTED("a, b, c")
   * 
   * TYPE-2:
   * TAINTED(["a", "b", "c"]).join(TAINTED(", "))
   * -> TAINTED("a, b, c")
   * 
   * TYPE-3:
   * The join function will call 'toString' on each element in the array.
   * [['a', 'b'], [TAINTED('c'), 'd']].join(TAINTED(", "))
   * -> TAINTED("a,b,c,d")
   * 
   * @param {Function} f - The array built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  joinArrayModel(base, args, reflected, result, iid) {
    let taintInfoPairs = [];
    let argsArray = Utils.getArrayLikeArguments(args, reflected);

    // TYPE-1
    if (TaintHelper.getTaintInfo(base)) {
      taintInfoPairs.push(['base', TaintHelper.getTaintInfo(base)]);
    }

    // TYPE-2
    if (argsArray.length > 0 && TaintHelper.getTaintInfo(argsArray[0])) {
      taintInfoPairs.push(['arg0', TaintHelper.getTaintInfo(argsArray[0])])
    }

    // TYPE-3
    if (taintInfoPairs.length === 0) {
      let taintInfo = TaintHelper.rgetTaintInfo(base);
      taintInfo ? taintInfoPairs.push(['base', taintInfo]) : null;
    }

    if (taintInfoPairs.length > 0) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'Array:join', base, argsArray, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }

    return result;
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
   * Array.prototype.toString()
   * 
   * @example
   * --------------------------------
   * CASE ONE:
   * [TAINTED("a"), "b", "c"].toString()
   * -> TAINTED("a,b,c")
   * 
   * @param {Function} f - The array built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toStringArrayModel(base, args, reflected, result, iid) {
    let taintInfoPairs = [];
    if (Utils.isArray(base)) {
      for (let i=0; i < base.length; i++) {
        if (TaintHelper.isTainted(base[i])) {
          taintInfoPairs.push([`arg${i}`, base[i].getTaintInfo()]);
        }
      }
    }

    if (taintInfoPairs) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'Array:toString', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the toLocaleString function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * Array.prototype.toLocaleString()
   * 
   * @example
   * --------------------------------
   * CASE ONE:
   * [TAINTED("a"), "b", "c"].toLocaleString()
   * -> TAINTED("a,b,c")
   * 
   * @param {Function} f - The array built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  toLocaleStringArrayModel(base, args, reflected, result, iid) {
    let taintInfoPairs = [];
    if (Utils.isArray(base)) {
      for (let i=0; i < base.length; i++) {
        if (TaintHelper.isTainted(base[i])) {
          taintInfoPairs.push([`arg${i}`, base[i].getTaintInfo()]);
        }
      }
    }

    if (taintInfoPairs) {
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'Array:toLocaleString', base, [], iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    
    return result;
  }

    /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the pop function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * Array.prototype.pop()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED(["a", "b", "c"]).pop()
   * -> TAINTED("c")
   * 
   * @param {Function} f - The array built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  popArrayModel(base, args, reflected, result, iid) {
    if (TaintHelper.isTainted(base)) {
      let taintInfoPairs = [];
      taintInfoPairs.push(['base', TaintHelper.getTaintInfo(base)]);
      
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'Array:pop', base, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    
    return result;
  }

  /**
   * @description
   * --------------------------------
   * Apply the taint propagation rule for the shift function.
   * 
   * @condition
   * --------------------------------
   * Condition Barrier: BASE_TAINTED
   * 
   * @usage
   * --------------------------------
   * Array.prototype.shift()
   * 
   * @example
   * --------------------------------
   * TYPE-1:
   * TAINTED(["a", "b", "c"]).shift()
   * -> TAINTED("a")
   * 
   * @param {Function} f - The array built-in function.
   * @param {Array} args - The arguments to the function.
   * @param {String} reflected - The reflected function name.
   * @param {*} result - The result of the function.
   * @param {number} iid - The instruction id.
   * @returns {TaintValue | *} - The tainted result or the original result if no taint is present.
   */
  shiftArrayModel(base, args, reflected, result, iid) {
    if (TaintHelper.isTainted(base)) {
      let taintInfoPairs = [];
      taintInfoPairs.push(['base', TaintHelper.getTaintInfo(base)]);
      
      let newTaintInfo = TaintHelper.addTaintPropOperation(taintInfoPairs, 'Array:shift', base, args, iid);
      return TaintHelper.createTaintValue(result, newTaintInfo);
    }
    
    return result;
  }
}