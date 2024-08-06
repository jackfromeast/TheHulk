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


    this.invokeFunRules = this.aggregateRules([
      this.stringBuiltinsRules.ruleDict,
      this.arrayBuiltinsRules.ruleDict,
      this.jsonBuiltinsRules.ruleDict,
      this.regexpBuiltinsRules.ruleDict,
      this.objectBuiltinsRules.ruleDict,
      this.reflectBuiltinsRules.ruleDict,
      this.proxyBuiltinsRules.ruleDict,
      this.symbolBuiltinsRules.ruleDict,
      this.booleanBuiltinsRules.ruleDict,
      this.numberBuiltinsRules.ruleDict,
    ]);
  }

   /**
   * Aggregates rules from the provided rule dictionaries.
   * 
   * @param {Array} ruleDicts - An array of rule dictionaries to aggregate.
   * @returns {Array} - The aggregated array of rules.
   */
   aggregateRules(ruleDicts) {
    const rules = ruleDicts.flat();
    
    return {
      rules,
      getRule(fn) {
        const found = rules.find(x => x.func === fn);
        return found ? found.rule : null;
      },
      getRuleForConstructor(fn) {
        const found = rules.find(x => x.constructor === fn);
        return found ? found.rule : null;
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