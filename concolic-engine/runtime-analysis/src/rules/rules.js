// import StringBuiltinTaintPropRules from './string.js'
import { BinaryOpsTaintPropRules } from './operations/binary-ops.js'
import { UnaryOpsTaintPropRules } from './operations/unary-ops.js'
import { GetFieldTaintPropRules } from './operations/get-field.js'
import { PutFieldTaintPropRules } from './operations/put-field.js';
import { StringBuiltinsTaintPropRules } from './js-builtins/string-builtins.js'
import { ArrayBuiltinsTaintPropRules } from './js-builtins/array-builtins.js';
import { JSONBuiltinsRules } from './js-builtins/json-builtins.js'
import { RegExpBuiltinsRules } from './js-builtins/regexp-builtins.js';
import { ObjectBuiltinsTaintPropRules } from './js-builtins/object-builtins.js';
import { ReflectBuiltinsTaintPropRules } from './js-builtins/reflect-builtins.js';
import { ProxyBuiltinsTaintPropRules } from './js-builtins/proxy-builtins.js';
import { SymbolBuiltinsTaintPropRules } from './js-builtins/symbol-builtins.js';
import { BooleanBuiltinsTaintPropRules } from './js-builtins/boolean-builtins.js';
import { NumberBuiltinsTaintPropRules } from './js-builtins/number-builtins.js';
import { TrustedTypesTaintPropRules } from './browser/trust-types.js';

export class TaintPropRules {
  constructor() {
    this.putFieldRules = new PutFieldTaintPropRules()
    this.getFieldRules = new GetFieldTaintPropRules();
    this.binaryRules = new BinaryOpsTaintPropRules();
    this.unaryRules = new UnaryOpsTaintPropRules();

    this.stringBuiltinsRules = new StringBuiltinsTaintPropRules();
    this.arrayBuiltinsRules = new ArrayBuiltinsTaintPropRules();
    this.jsonBuiltinsRules = new JSONBuiltinsRules();
    this.regexpBuiltinsRules = new RegExpBuiltinsRules();
    this.objectBuiltinsRules = new ObjectBuiltinsTaintPropRules();
    this.reflectBuiltinsRules = new ReflectBuiltinsTaintPropRules();
    this.proxyBuiltinsRules = new ProxyBuiltinsTaintPropRules();
    this.symbolBuiltinsRules = new SymbolBuiltinsTaintPropRules();
    this.booleanBuiltinsRules = new BooleanBuiltinsTaintPropRules();
    this.numberBuiltinsRules = new NumberBuiltinsTaintPropRules();

    this.trustedTypesTaintPropRules = new TrustedTypesTaintPropRules();

    this.invokeFunRules = this.aggregateRules([
      this.stringBuiltinsRules,
      this.arrayBuiltinsRules,
      this.jsonBuiltinsRules,
      this.regexpBuiltinsRules,
      this.objectBuiltinsRules,
      this.reflectBuiltinsRules,
      this.proxyBuiltinsRules,
      this.symbolBuiltinsRules,
      this.booleanBuiltinsRules,
      this.numberBuiltinsRules,
      this.trustedTypesTaintPropRules
    ]);
  }

   /**
   * Aggregates rules from the provided rule instances.
   * 
   * @param {Array} ruleInstances - An array of rule class instances to aggregate.
   * @returns {Object} - An object with methods to get rules.
   */
  aggregateRules(ruleInstances) {
    return {
      ruleInstances,
      getRule(fn) {
        for (const ruleInstance of ruleInstances) {
          const rule = ruleInstance.getRule(fn);
          if (rule) { return rule; }
        }
        return null;
      },
      getRuleForConstructor(fn) {
        for (const ruleInstance of ruleInstances) {
          if (ruleInstance.getRuleForConstructor) {
            const rule = ruleInstance.getRuleForConstructor(fn);
            if (rule) { return rule; }
          }
        }
        return null;
      }
    };
  }

  /**
   * Adds a rule to the rule dictionary.
   * 
   * @param {Function} fn - The function to which the rule applies.
   * @param {Function} rule - The rule to be applied.
   */
  addRule(fn, rule) {
    this.ruleDict.push({ fn, rule });
  }

  /**
   * Retrieves a rule for the specified function.
   * 
   * @param {Function} fn - The function for which the rule is retrieved.
   * @returns {Function|null} The rule if found, otherwise null.
   */
  getRule(fn) {
    const found = this.ruleDict.find(x => x.fn === fn);
    return found ? found.rule : null;
  }
}


export default TaintPropRules;