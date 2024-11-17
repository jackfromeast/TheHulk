// JALANGI DO NOT INSTRUMENT
/**
 * @description
 * --------------------------------
 * This script holds the taint engine behaviors which will be invoked by the jalangi2 runtime.
 * This script will load and execute in the browser environment.
 * 
 * @notes
 * --------------------------------
 * Ideally, the analysis class should not directly manipulate TaintValues; this should be managed by
 * sources, sinks, and taint propagation rules. 
 * The analysis should simply apply the appropriate rules for each operation hook.
 * 
 * @usage 
 * --------------------------------
 */

import { Logger } from './utils/logger.js';
import { Coverage }  from './coverage.js';
import { TaintValue, WrappedValue } from './values/wrapped-values.js';
import { TaintInfo } from './values/taint-info.js';
import { TaintPropRules } from './rules/rules.js';
import { TaintSourceRules } from './taint-sources.js';
import { TaintSinkRules } from './taint-sinks.js';
import { TaintPropOperation } from './values/taint-info.js';
import { TaintHelper } from './taint-helper.js';
import { Utils } from './utils/util.js';
import { DefinedConcretizeBuiltinHelper } from './rules/rule-concretize.js';
import { TaintStackHelper } from './taint-stack-helper.js';

export class TaintTracking {
  constructor(sandbox) {
    this.taintID = 0;
    this.sandbox = sandbox;
    this.coverage = new Coverage(sandbox);
    this.logger = new Logger({
      level: 'info',
      name: 'TheHulk',
      logUnsupportBuiltin: false,
      logTaintInstall: false,
      logClobberableSource: true,
      logClobberableSink: true
    });

    this.taintConfig = {
      TAINT_VALUE:{
        Number: true,
        Boolean: true,
      },
      
      TAINT_SOURCE: {
        "SOURCE-FROM-BROWSER-API": false,
        "SOURCE-FROM-DOM-ELEMENT": false,
        "SOURCE-FROM-DOCUMENT": true,
        "SOURCE-FROM-WINDOW": true,
      },

      TAINT_SINK: {}
    };

    this.taintPropRules = new TaintPropRules();
    this.taintSourceRules = new TaintSourceRules();
    this.taintSinkRules = new TaintSinkRules();

    this.dangerousFlows = [];
    this.clobberableSources = {};
    this.clobberableSinks = {};

    this.DCHECK = true;
    this.taintStackHelper = new TaintStackHelper();
    this.builtinConcretizeHelper = new DefinedConcretizeBuiltinHelper();
    this.MAX_DEPTH_FOR_TAINT_CHECK = 3;
  }

  /**
   * This callback is called before a binary operation. Binary operations include  +, -, *, /, %, &, |, ^,
   * <<, >>, >>>, <, >, <=, >=, ==, !=, ===, !==, instanceof, delete, in.  No callback for <code>delete x</code>
   * because this operation cannot be performed reflectively.
   *  
   * @notes
   * We always skip the original binary operation and let binary handle the operation.
   * 
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {string} op - Operation to be performed
   * @param {*} left - Left operand
   * @param {*} right - Right operand
   * @param {boolean} isOpAssign - True if the binary operation is part of an expression of the form
   * <code>x op= e</code>
   * @param {boolean} isSwitchCaseComparison - True if the binary operation is part of comparing the discriminant
   * with a consequent in a switch statement.
   * @param {boolean} isComputed - True if the operation is of the form <code>delete x[p]</code>, and false
   * otherwise (even if the operation if of the form <code>delete x.p</code>)
   * @returns {{op: string, left: *, right: *, skip: boolean}|undefined} - If an object is returned and the
   * <tt>skip</tt> property is true, then the binary operation is skipped.  Original <tt>op</tt>, <tt>left</tt>,
   * and <tt>right</tt> are replaced with that from the returned object if an object is returned.
   */
  binaryPre (iid, op, left, right, isOpAssign, isSwitchCaseComparison, isComputed) {
    return {op: op, left: left, right: right, skip: true};
  };

  /**
   * This callback is called after a binary operation. Binary operations include  +, -, *, /, %, &, |, ^,
   * <<, >>, >>>, <, >, <=, >=, ==, !=, ===, !==, instanceof, delete, in.
   *
   * @steps
   * 1/ Apply the taint propagation rules for the binary operation if one of the operands is tainted.
   * 
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {string} op - Operation to be performed
   * @param {*} left - Left operand
   * @param {*} right - Right operand
   * @param {undefined} result - Always undefined, as we skip the original binary operation
   * @param {boolean} isOpAssign - True if the binary operation is part of an expression of the form
   * <code>x op= e</code>
   * @param {boolean} isSwitchCaseComparison - True if the binary operation is part of comparing the discriminant
   * with a consequent in a switch statement.
   * @param {boolean} isComputed - True if the operation is of the form <code>delete x[p]</code>, and false
   * otherwise (even if the operation if of the form <code>delete x.p</code>)
   * @returns {{result: *}|undefined} - If an object is returned, the result of the binary operation is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  binary (iid, op, left, right, result, isOpAssign, isSwitchCaseComparison, isComputed) {
    try{
      let rule = this.taintPropRules.binaryRules.getRule(op);
      if (rule) {
        result = rule(left, right, iid);
      } else {
        result = this.taintPropRules.binaryRules.BinaryJumpTable[op](left, right);
      }

      return {result: result};
    } catch (e) {
      // Avoid the error swallow by user program
      J$$.analysis.logger.warn("(Can be ignored)", e);
      throw e;
    }
  };

  /**
   * This callback is called before a unary operation. Unary operations include  +, -, ~, !, typeof, void.
   *  
   * @notes
   * We always skip the original unary operation and let unary handle the operation.
   * 
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {string} op - Operation to be performed
   * @param {*} left - Left operand
   * @returns {{op: *, left: *, skip: boolean} | undefined} If an object is returned and the
   * <tt>skip</tt> property is true, then the unary operation is skipped.  Original <tt>op</tt> and <tt>left</tt>
   * are replaced with that from the returned object if an object is returned.
   */
  unaryPre (iid, op, left) {
      return {op: op, left: left, skip: true};
  };

  /**
   * This callback is called after a unary operation. Unary operations include  +, -, ~, !, typeof, void.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {string} op - Operation to be performed
   * @param {*} left - Left operand
   * @param {*} result - The result of the unary operation
   * @returns {{result: *}|undefined} - If an object is returned, the result of the unary operation is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   *
   */
  unary (iid, op, left, result) {
    try { 
      let rule = this.taintPropRules.unaryRules.getRule(op);
      if (rule) {
        result = rule(left, iid);
      } else {
        let left_c = TaintHelper.concreteWrappedOnly(left);
        result = this.taintPropRules.unaryRules.UnaryJumpTable[op](left_c);
      }

      return {result: result};
    } catch (e) {
      // Avoid the error swallow by user program
      J$$.analysis.logger.warn("(Can be ignored)", e);
      throw e;
    }
  };


  /**
   * This callback is called after a condition check before branching. Branching can happen in various statements
   * including if-then-else, switch-case, while, for, ||, &&, ?:.
   *
   * @steps
   * 1/ We always concretize the taint value before the conditional expression.
   * 
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} result - The value of the conditional expression
   * @returns {{result: *}|undefined} - If an object is returned, the result of the conditional expression is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  conditional (iid, result) {
    return {result: TaintHelper.concreteWrappedOnly(result)};
  };

  /**
   * This callback is called before a string passed as an argument to eval or Function is instrumented.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} code - Code that is going to get instrumented
   * @param {boolean} isDirect - true if this is a direct call to eval
   * @returns {{code: *, skip: boolean}} - If an object is returned and the
   * <tt>skip</tt> property is true, then the instrumentation of <tt>code</tt> is skipped.
   * Original <tt>code</tt> is replaced with that from the returned object if an object is returned.
   */
  instrumentCodePre (iid, code, isDirect) {
    return {code: code, skip: false};
  };

  /**
   * This callback is called after a string passed as an argument to eval or Function is instrumented.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} newCode - Instrumented code
   * @param {Object} newAst - The AST of the instrumented code
   * @param {boolean} isDirect - true if this is a direct call to eval
   * @returns {{result: *}|undefined} - If an object is returned, the instrumented code is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  instrumentCode (iid, newCode, newAst, isDirect) {
      return {result: newCode};
  };


  /**
   * This callback is called before a function, method, or constructor invocation.
   * 
   * @example
   * y.f(a, b, c)
   * --------------------------------
   * var skip = false;
   * var aret = analysis.invokeFunPre(113, f, y, [a, b, c], false, true);
   * if (aret) {
   *     f = aret.f;
   *     y = aret.y;
   *     args = aret.args;
   *     skip = aret.skip
   * }
   * if (!skip) {
   *     f.apply(y, args);
   * }
   * 
   * @steps
   * 1/ Check the taint value at the sink function call.
   * 2/ If a taint value is passed, check whether the function is a built-in function
   *    and has the taint propagation rules.
   * 3/ If the function is a built-in function and has the taint propagation rules,
   *    we update the taint information on the return value.
   * 4/ If the function is a built-in function and has no taint propagation rules,
   *    we concretize the taint value and apply the original function. Concretization
   *    will be logged.
   * 5/ Log the coverage information for the analysis.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {function} f - The function object that going to be invoked
   * @param {object} base - The receiver object for the function <tt>f</tt>
   * @param {Arguments} args - The array of arguments passed to <tt>f</tt>
   * @param {boolean} isConstructor - True if <tt>f</tt> is invoked as a constructor
   * @param {boolean} isMethod - True if <tt>f</tt> is invoked as a method
   * @param {number} functionIid - The iid (i.e. the unique instruction identifier) where the function was created
   * @param {number} functionSid - The sid (i.e. the unique script identifier) where the function was created
   * {@link MyAnalysis#functionEnter} when the function <tt>f</tt> is executed.  The <tt>functionIid</tt> can be
   * treated as the static identifier of the function <tt>f</tt>.  Note that a given function code block can
   * create several function objects, but each such object has a common <tt>functionIid</tt>, which is the iid
   * that is passed to {@link MyAnalysis#functionEnter} when the function executes.
   * @returns {{f: function, base: Object, args: Arguments, skip: boolean}|undefined} - If an object is returned and
   * the <tt>skip</tt> property of the object is true, then the invocation operation is skipped.
   * Original <tt>f</tt>, <tt>base</tt>, and <tt>args</tt> are replaced with that from the returned object if
   * an object is returned. The args should has Arguments type as it will passed to the InvokeFun operation.
   */
  invokeFunPre (iid, f, base, args, isConstructor, isMethod, functionIid, functionSid) {
    try {
      let [reason, taintedArg] = this.taintSinkRules.checkTaintAtSinkInvokeFun(f, base, args);
      if (reason) {
        TaintHelper.getTaintInfo(taintedArg).addtaintSink(iid, reason, new TaintPropOperation(`invokeFun:${f.name}`, base, Array.from(args), iid));
        // TODO: Handle multiple tainted arguments here
        Utils.reportDangerousFlow(
          TaintHelper.getTaintInfo(taintedArg).getTaintSourceReason(),
          TaintHelper.getTaintInfo(taintedArg).getTaintSourceLocation(),
          reason,
          iid,
          taintedArg,
          iid
        )
      }

      // Check if the function is a built-in function
      // Functions can be called in different ways, 
      // e.g. y.f(arg1, arg2, ...), y.f.call(this, arg1, arg2), y.f.apply(this, args)
      // - y.f(arg1, arg2, ...) => base = y, f = y.f, args = [arg1, arg2, ...]
      // - y.f.call(this, arg1, arg2) => base = f, f = f.apply, args = [this, arg1, arg2]
      // - y.f.apply(this, args) => base = f, f = f.apply, args = [this, ...args]
      // This will affect how we check the taint args and the base object
      let fTobeCheck = f;
      let reflected = "";
      if (typeof(base) === "function" && (f === Function.prototype.apply || f === Function.prototype.call)) {
        fTobeCheck = base;
        reflected = f === Function.prototype.apply ? "apply" : "call";
      }

      let base_c = TaintHelper.concreteWrappedOnly(base);
      let f_c = TaintHelper.concreteWrappedOnly(f);

      if (f_c !== f) {
        // We don't taint the function object
        throw new Error("[TheHulk] Function object is tainted!");
      }

      if (Utils.isNativeFunction(fTobeCheck)) {
        let rule;
        if (isConstructor) {
          rule = this.taintPropRules.invokeFunRules.getRuleForConstructor(fTobeCheck);
        } else {
          rule = this.taintPropRules.invokeFunRules.getRule(fTobeCheck);
        }

        if (rule && rule.type && rule.type === "DynamicRuleFunction") {
          rule = rule.install(fTobeCheck);
        }
        
        if (rule) {
          // Push the function to the stack
          // this.taintStackHelper.pushStackFrame(rule, iid);
          return {f: rule, base: base, args: args, skip: false, reflected: reflected, isConstructor: false};
        }
        else {
          // f is a built-in function but no rule found
          // We concretize the taint value and apply the original function
          if (!this.builtinConcretizeHelper.isKnown(f)){
            J$$.analysis.logger.reportUnsupportedBuiltin(f, base);
          }

          // Using rconcreteHard could be very dangerous, as
          // - performace: if item is really big, like window, will the program run forever
          // - functionality: we will lost all the taint information on global object like item
          // However, it may break the program if we don't concretize the value for some built-in functions
          // So, we maintain a known concretized list for the built-in functions for sepecial cases
          // By default, we only concretize one level of the object
          [base_c, args] = this.builtinConcretizeHelper.concrete(f, base, args);

          // Push the function to the stack
          // this.taintStackHelper.pushStackFrame(f_c, iid);
          return {f: f_c, base: base_c, args: args, skip: false, reflected:""};
        }
      }
    
      // f is not a built-in function or it is a constructor
      // this.taintStackHelper.pushStackFrame(f_c, iid);
      return {f: f_c, base: base, args: args, skip: false, reflected:""};

    } catch (e) {
      // Avoid the error swallow by user program
      J$$.analysis.logger.warn("(Can be ignored)", e);
      throw e;
    }
  };

  /**
   * This callback is called after a function, method, or constructor invocation.
   *
   * @example
   * x = y.f(a, b, c)
   * --------------------------------
   * var skip = false;
   * var aret = analysis.invokeFunPre(113, f, y, [a, b, c], false, true);
   * if (aret) {
   *     f = aret.f;
   *     y = aret.y;
   *     args = aret.args;
   *     skip = aret.skip
   * }
   * if (!skip) {
   *     result =f.apply(y, args);
   * }
   * aret = analysis.invokeFun(117, f, y, args, result, false, true);
   * if (aret) {
   *     x = aret.result
   * } else {
   *     x = result;
   * }
   * 
   * @steps
   * 1/ Taint the return value if the function api is a taint source.
   * 2/ Log the coverage information for the analysis.
   * 
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {function} f - The function object that was invoked
   * @param {*} base - The receiver object for the function <tt>f</tt>
   * @param {Array} args - The array of arguments passed to <tt>f</tt>
   * @param {*} result - The value returned by the invocation
   * @param {boolean} isConstructor - True if <tt>f</tt> is invoked as a constructor
   * @param {boolean} isMethod - True if <tt>f</tt> is invoked as a method
   * @param {number} functionIid - The iid (i.e. the unique instruction identifier) where the function was created
   * @param {number} functionSid - The sid (i.e. the unique script identifier) where the function was created
   * {@link MyAnalysis#functionEnter} when the function f is executed.  <tt>functionIid</tt> can be treated as the
   * static identifier of the function <tt>f</tt>.  Note that a given function code block can create several function
   * objects, but each such object has a common <tt>functionIid</tt>, which is the iid that is passed to
   * {@link MyAnalysis#functionEnter} when the function executes.
   * @returns {{result: *}| undefined} - If an object is returned, the return value of the invoked function is
   * replaced with the value stored in the <tt>result</tt> property of the object.  This enables one to change the
   * value that is returned by the actual function invocation.
   *
   */
  invokeFun (iid, f, base, args, result, isConstructor, isMethod, functionIid, functionSid) {
    try {
      let reason = this.taintSourceRules.shouldTaintSourceAtInvokeFun(f, base, args, result);
      if (reason && !TaintHelper.isTainted(result)) {
        // TODO: We need to clone the variable or only save the taint information and not the value
        let taintInfo = new TaintInfo(iid, reason, new TaintPropOperation(`invokeFun:${f.name}`, base, Array.from(args), iid));
        result = TaintHelper.createTaintValue(result, taintInfo);
      }

      // Pop the function from the stack
      // let frame = this.taintStackHelper.peakStackFrame();
      // if (frame.function !== f) {
      //   throw new Error("[TheHulk] Function object is not the same!");
      // } else{
      //   this.taintStackHelper.popStackFrame();
      // }
      
      return {result: result};
    } catch (e) {
      // Avoid the error swallow by user program
      J$$.analysis.logger.warn("(Can be ignored)", e);
      throw e;
    }
  };

  /**
   * This callback is called after the creation of a literal.  A literal can be a function literal, an object literal,
   * an array literal, a number, a string, a boolean, a regular expression, null, NaN, Infinity, or undefined.
   *
   * @example
   * x = "Hello"
   * --------------------------------
   * var result = "Hello";
   * var aret = analysis.literal(201, result, false);
   * if (aret) {
   *     result = aret.result;
   * }
   * x = result;
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} val - The literal value
   * @param {boolean} hasGetterSetter - True if the literal is an object and the object defines getters and setters
   * @returns {{result: *} | undefined} - If the function returns an object, then the original literal value is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   *
   */
  literal(iid, val, _hasGetterSetter) {
		return {result: val};
	};

  /**
  * This callback is called when a for-in loop is used to iterate the properties of an object.
  *
  * @example
  * for (x in y) { }
  * --------------------------------
  * var aret = analysis.forinObject(iid, y);
  * if (aret) {
  *     y = aret.result;
  * }
  * for (x in y) {}
  *
  * @param {number} iid - Static unique instruction identifier of this callback
  * @param {*} val - Objects whose properties are iterated in a for-in loop.
  * @returns {{result: *} | undefined} - If the function returns an object, then the original object whose
  * properties are being iterated is replaced with the value stored in the <tt>result</tt> property of the
  * returned object.
  *
  */
  forinObject (iid, val) {
    return {result: val};
  };


  /**
   * This callback is triggered at the beginning of a scope for every local variable declared in the scope, for
   * every formal parameter, for every function defined using a function statement, for <tt>arguments</tt>
   * variable, and for the formal parameter passed in a catch statement.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {string} name - Name of the variable that is declared
   * @param {*} val - Initial value of the variable that is declared.  Variables can be local variables, function
   * parameters, catch parameters, <tt>arguments</tt>, or functions defined using function statements.  Variables
   * declared with <tt>var</tt> have <tt>undefined</tt> as initial values and cannot be changed by returning a
   * different value from this callback.  On the beginning of an execution of a function, a <tt>declare</tt>
   * callback is called on the <tt>arguments</tt> variable.
   * @param {boolean} isArgument - True if the variable is <tt>arguments</tt> or a formal parameter.
   * @param {number} argumentIndex - Index of the argument in the function call.  Indices start from 0.  If the
   * variable is not a formal parameter, then <tt>argumentIndex</tt> is -1.
   * @param {boolean} isCatchParam - True if the variable is a parameter of a catch statement.
   * @returns {{result: *} | undefined} - If the function returns an object, then the original initial value is
   * replaced with the value stored in the <tt>result</tt> property of the object.  This does not apply to local
   * variables declared with <tt>var</tt>.
   *
   */
  declare (iid, name, val, isArgument, argumentIndex, isCatchParam) {
    return {result: val};
  };


  /**
   * This callback is called before a property of an object is accessed.
   * 
   * @steps
   * 1/ We always skip the original getField operation and let getField handle the operation.
   * 
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} base - Base object
   * @param {string|*} offset - Property
   * @param {boolean} isComputed - True if property is accessed using square brackets.  For example,
   * <tt>isComputed</tt> is <tt>true</tt> if the get field operation is <tt>o[p]</tt>, and <tt>false</tt>
   * if the get field operation is <tt>o.p</tt>
   * @param {boolean} isOpAssign - True if the operation is of the form <code>o.p op= e</code>
   * @param {boolean} isMethodCall - True if the get field operation is part of a method call (e.g. <tt>o.p()</tt>)
   * @returns {{base: *, offset: *, skip: boolean} | undefined} - If an object is returned and the <tt>skip</tt>
   * property of the object is true, then the get field operation is skipped.  Original <tt>base</tt> and
   * <tt>offset</tt> are replaced with that from the returned object if an object is returned.
   *
   */
  getFieldPre (iid, base, offset, isComputed, isOpAssign, isMethodCall) {
    return {base: base, offset: offset, skip: true};
  };


  /**
   * This callback is called after a property of an object is accessed.
   * 
   * @steps
   * 1/ Apply the taint propagation rules for the get field operation if the property should be tainted.
   * 2/ Introduced a new taint value if the property is a taint source.
   * 3/ Log the coverage information for the analysis.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} base - Base object
   * @param {string|*} offset - Property
   * @param {*} val - Value of <code>base[offset]</code>
   * @param {boolean} isComputed - True if property is accessed using square brackets.  For example,
   * <tt>isComputed</tt> is <tt>true</tt> if the get field operation is <tt>o[p]</tt>, and <tt>false</tt>
   * if the get field operation is <tt>o.p</tt>
   * @param {boolean} isOpAssign - True if the operation is of the form <code>o.p op= e</code>
   * @param {boolean} isMethodCall - True if the get field operation is part of a method call (e.g. <tt>o.p()</tt>)
   * @returns {{result: *} | undefined} - If an object is returned, the value of the get field operation  is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  getField (iid, base, offset, val, isComputed, isOpAssign, isMethodCall) {
    try {
      val = this.taintPropRules.getFieldRules.getRule(base, offset)(base, offset, iid)
      
      let reason = this.taintSourceRules.shouldTaintSourceAtGetField(base, offset, val);
      if (reason && !TaintHelper.isTainted(val)) {
        if (val instanceof WrappedValue) {
          val = val.getConcrete();
        }
        let taintInfo = new TaintInfo(iid, reason, new TaintPropOperation("getField", base, [offset], iid));
        val = TaintHelper.createTaintValue(val, taintInfo);
      }

      return {result: val};
    } catch (e) {
      // Avoid the error swallow by user program
      J$$.analysis.logger.warn("(Can be ignored)", e);
      throw e;
    }
  };


  /**
   * This callback is called before a property of an object is written.
   * 
   * @steps
   * 1/ We will instrument the code if it has been set to .innerHTML
   * 
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} base - Base object
   * @param {*} offset - Property
   * @param {*} val - Value to be stored in <code>base[offset]</code>
   * @param {boolean} isComputed - True if property is accessed using square brackets.  For example,
   * <tt>isComputed</tt> is <tt>true</tt> if the get field operation is <tt>o[p]</tt>, and <tt>false</tt>
   * if the get field operation is <tt>o.p</tt>
   * @param {boolean} isOpAssign - True if the operation is of the form <code>o.p op= e</code>
   * @returns {{base: *, offset: *, val: *, skip: boolean} | undefined} -  If an object is returned and the <tt>skip</tt>
   * property is true, then the put field operation is skipped.  Original <tt>base</tt>, <tt>offset</tt>, and
   * <tt>val</tt> are replaced with that from the returned object if an object is returned.
   */
  putFieldPre (iid, base, offset, val, isComputed, isOpAssign) {
    return {base: base, offset: offset, val: val, skip: true};
  };


  /**
   * This callback is called after a property of an object is written.
   * 
   * @steps
   * 1/ Check whether a taint value has been set to the sink property (e.g. .innerHTML)
   * 2/ Apply the taint propagation rules for the put field operation
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} base - Base object
   * @param {*} offset - Property
   * @param {*} val - Value to be stored in <code>base[offset]</code>
   * @param {boolean} isComputed - True if property is accessed using square brackets.  For example,
   * <tt>isComputed</tt> is <tt>true</tt> if the get field operation is <tt>o[p]</tt>, and <tt>false</tt>
   * if the get field operation is <tt>o.p</tt>
   * @param {boolean} isOpAssign - True if the operation is of the form <code>o.p op= e</code>
   * @returns {{result: *} | undefined} -   If an object is returned, the result of the put field operation is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  putField (iid, base, offset, val, isComputed, isOpAssign) {
    try {
      if (J$$.analysis.DCHECK) {
        if (offset === "__TAINT__") {
          debugger;
        }
      }

      let reason = this.taintSinkRules.checkTaintAtSinkPutField(base, offset, val);
      if (reason) {
        TaintHelper.getTaintInfo(val).addtaintSink(iid, reason, new TaintPropOperation("putField", base, [offset], iid));
        Utils.reportDangerousFlow(
          TaintHelper.getTaintInfo(val).getTaintSourceReason(),
          TaintHelper.getTaintInfo(val).getTaintSourceLocation(),
          reason,
          iid,
          val,
          iid
        )
      }

      val = this.taintPropRules.putFieldRules.getRule(base, offset)(base, offset, val, iid)
      return {result: val};
    } catch (e) {
      // Avoid the error swallow by user program
      J$$.analysis.logger.warn("(Can be ignored)", e);
      throw e;
    }
  };


  /**
   * This callback is called after a variable is read.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {string} name - Name of the variable being read
   * @param {*} val - Value read from the variable
   * @param {boolean} isGlobal - True if the variable is not declared using <tt>var</tt> (e.g. <tt>console</tt>)
   * @param {boolean} isScriptLocal - True if the variable is declared in the global scope using <tt>var</tt>
   * @returns {{result: *} | undefined} - If an object is returned, the result of the read operation is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  read (iid, name, val, isGlobal, isScriptLocal) {
    return {result: val};
  };

  /**
   * This callback is called before a variable is written.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {string} name - Name of the variable being read
   * @param {*} val - Value to be written to the variable
   * @param {*} lhs - Value stored in the variable before the write operation
   * @param {boolean} isGlobal - True if the variable is not declared using <tt>var</tt> (e.g. <tt>console</tt>)
   * @param {boolean} isScriptLocal - True if the variable is declared in the global scope using <tt>var</tt>
   * @returns {{result: *} | undefined} - If an object is returned, the result of the write operation is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  write (iid, name, val, lhs, isGlobal, isScriptLocal) {
      return {result: val};
  };

  /**
   * This callback is called before a value is returned from a function using the <tt>return</tt> keyword.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} val - Value to be returned
   * @returns {{result: *} | undefined} - If an object is returned, the value to be returned is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  _return (iid, val) {
    // if (this.taintStackHelper.shouldConcretizeReturn) {
    //   val = TaintHelper.concreteWrappedOnly(val);
    // }
    return {result: val};
  };

  /**
   * This callback is called before a value is thrown using the <tt>throw</tt> keyword.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} val - Value to be thrown
   * @returns {{result: *} | undefined} - If an object is returned, the value to be thrown is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  _throw (iid, val) {
      return {result: val};
  };

  /**
   * This callback is called when a <tt>with</tt> statement is executed
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} val - Value used as an argument to <tt>with</tt>
   * @returns {{result: *} | undefined} - If an object is returned, the value to be used in <tt>with</tt> is
   * replaced with the value stored in the <tt>result</tt> property of the object.
   */
  _with (iid, val) {
      return {result: val};
  };


  /**
   * This callback is called before the execution of a function body starts.
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {function} f - The function object whose body is about to get executed
   * @param {*} dis - The value of the <tt>this</tt> variable in the function body
   * @param {Array} args - List of the arguments with which the function is called
   * @returns {undefined} - Any return value is ignored
   */
  functionEnter (iid, f, dis, args) {};
  
  /**
   * This callback is called when the execution of a function body completes
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {*} returnVal - The value returned by the function
   * @param {{exception:*} | undefined} wrappedExceptionVal - If this parameter is an object, the function
   * execution has thrown an uncaught exception and the exception is being stored in the <tt>exception</tt>
   * property of the parameter
   * @returns {{returnVal: *, wrappedExceptionVal: *, isBacktrack: boolean}}  If an object is returned, then the
   * actual <tt>returnVal</tt> and <tt>wrappedExceptionVal.exception</tt> are replaced with that from the
   * returned object. If an object is returned and the property <tt>isBacktrack</tt> is set, then the control-flow
   * returns to the beginning of the function body instead of returning to the caller.  The property
   * <tt>isBacktrack</tt> can be set to <tt>true</tt> to repeatedly execute the function body as in MultiSE
   * symbolic execution.
   */
  functionExit (iid, returnVal, wrappedExceptionVal) {
      return {returnVal: returnVal, wrappedExceptionVal: wrappedExceptionVal, isBacktrack: false};
  };


  /**
   * This callback is called before the execution of a JavaScript file
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {string} instrumentedFileName - Name of the instrumented script file
   * @param {string} originalFileName - Name of the original script file
   */
  scriptEnter (iid, instrumentedFileName, originalFileName) {};
  

  /**
   * This callback is called when the execution of a JavaScript file completes
   *
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {{exception:*} | undefined} wrappedExceptionVal - If this parameter is an object, the script
   * execution has thrown an uncaught exception and the exception is being stored in the <tt>exception</tt>
   * property of the parameter
   * @returns {{wrappedExceptionVal: *, isBacktrack: boolean}} - If an object is returned, then the
   * actual <tt>wrappedExceptionVal.exception</tt> is replaced with that from the
   * returned object. If an object is returned and the property <tt>isBacktrack</tt> is set, then the control-flow
   * returns to the beginning of the script body.  The property
   * <tt>isBacktrack</tt> can be set to <tt>true</tt> to repeatedly execute the script body as in MultiSE
   * symbolic execution.
   */
  scriptExit (iid, wrappedExceptionVal) {
      return {wrappedExceptionVal: wrappedExceptionVal, isBacktrack: false};
  };
}