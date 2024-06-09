/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./src/config.js":
/*!***********************!*\
  !*** ./src/config.js ***!
  \***********************/
/***/ (() => {

/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// do not remove the following comment
// JALANGI DO NOT INSTRUMENT
if (typeof J$$ === 'undefined') {
    J$$ = {};
}

(function (sandbox) {
    if (typeof sandbox.Config !== 'undefined') {
        return;
    }

    var Config = sandbox.Config = {};

    Config.DEBUG = false;
    Config.WARN = false;
    Config.SERIOUS_WARN = false;
// make MAX_BUF_SIZE slightly less than 2^16, to allow over low-level overheads
    Config.MAX_BUF_SIZE = 64000;
    Config.LOG_ALL_READS_AND_BRANCHES = false;

    //**********************************************************
    //  Functions for selective instrumentation of operations
    //**********************************************************
    // In the following functions
    // return true in a function, if you want the ast node (passed as the second argument) to be instrumented
    // ast node gets instrumented if you do not define the corresponding function
    Config.ENABLE_SAMPLING = false;
//    Config.INSTR_INIT = function(name, ast) { return false; };
//    Config.INSTR_READ = function(name, ast) { return false; };
//    Config.INSTR_WRITE = function(name, ast) { return true; };
//    Config.INSTR_GETFIELD = function(offset, ast) { return true; }; // offset is null if the property is computed
//    Config.INSTR_PUTFIELD = function(offset, ast) { return true; }; // offset is null if the property is computed
//    Config.INSTR_BINARY = function(operator, ast) { return true; };
//    Config.INSTR_PROPERTY_BINARY_ASSIGNMENT = function(operator, offset, ast) { return true; }; // a.x += e or a[e1] += e2
//    Config.INSTR_UNARY = function(operator, ast) { return true; };
//    Config.INSTR_LITERAL = function(literal, ast) { return true;}; // literal gets some dummy value if the type is object, function, or array
//    Config.INSTR_CONDITIONAL = function(type, ast) { return true; }; // type could be "&&", "||", "switch", "other"
//    Config.INSTR_TRY_CATCH_ARGUMENTS = function(ast) {return false; }; // wrap function and script bodies with try catch block and use arguments in J$.Fe.  DO NOT USE THIS.
//    Config.INSTR_END_EXPRESSION = function(ast) {return true; }; // top-level expression marker
}(J$$));


/***/ }),

/***/ "./src/constants.js":
/*!**************************!*\
  !*** ./src/constants.js ***!
  \**************************/
/***/ ((__unused_webpack_module, exports) => {

/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// do not remove the following comment
// JALANGI DO NOT INSTRUMENT
if (typeof J$$ === 'undefined') {
    J$$ = {};
}

(function (sandbox) {
    if (typeof sandbox.Constants !== 'undefined') {
        return;
    }
    var Constants = sandbox.Constants = {};

    Constants.isBrowser = !( true && this.exports !== exports);

    var APPLY = Constants.APPLY = Function.prototype.apply;
    var CALL = Constants.CALL = Function.prototype.call;
    APPLY.apply = APPLY;
    APPLY.call = CALL;
    CALL.apply = APPLY;
    CALL.call = CALL;

    var HAS_OWN_PROPERTY = Constants.HAS_OWN_PROPERTY = Object.prototype.hasOwnProperty;
    Constants.HAS_OWN_PROPERTY_CALL = Object.prototype.hasOwnProperty.call;


    var PREFIX1 = Constants.JALANGI_VAR = "J$$";
    Constants.SPECIAL_PROP = "*" + PREFIX1 + "*";
    Constants.SPECIAL_PROP2 = "*" + PREFIX1 + "I*";
    Constants.SPECIAL_PROP3 = "*" + PREFIX1 + "C*";
    Constants.SPECIAL_PROP4 = "*" + PREFIX1 + "W*";
    Constants.SPECIAL_PROP_SID = "*" + PREFIX1 + "SID*";
    Constants.SPECIAL_PROP_IID = "*" + PREFIX1 + "IID*";

    Constants.UNKNOWN = -1;

    //-------------------------------- End constants ---------------------------------

    //-------------------------------------- Constant functions -----------------------------------------------------------

    var HOP = Constants.HOP = function (obj, prop) {
        return (prop + "" === '__proto__') || CALL.call(HAS_OWN_PROPERTY, obj, prop); //Constants.HAS_OWN_PROPERTY_CALL.apply(Constants.HAS_OWN_PROPERTY, [obj, prop]);
    };

    Constants.hasGetterSetter = function (obj, prop, isGetter) {
        if (typeof Object.getOwnPropertyDescriptor !== 'function') {
            return true;
        }
        while (obj !== null) {
            if (typeof obj !== 'object' && typeof obj !== 'function') {
                return false;
            }
            var desc = Object.getOwnPropertyDescriptor(obj, prop);
            if (desc !== undefined) {
                if (isGetter && typeof desc.get === 'function') {
                    return true;
                }
                if (!isGetter && typeof desc.set === 'function') {
                    return true;
                }
            } else if (HOP(obj, prop)) {
                return false;
            }
            obj = obj.__proto__;
        }
        return false;
    };

    Constants.debugPrint = function (s) {
        if (sandbox.Config.DEBUG) {
            console.log("***" + s);
        }
    };

    Constants.warnPrint = function (iid, s) {
        if (sandbox.Config.WARN && iid !== 0) {
            console.log("        at " + iid + " " + s);
        }
    };

    Constants.seriousWarnPrint = function (iid, s) {
        if (sandbox.Config.SERIOUS_WARN && iid !== 0) {
            console.log("        at " + iid + " Serious " + s);
        }
    };

})(J$$);



/***/ }),

/***/ "./src/iidToLocation.js":
/*!******************************!*\
  !*** ./src/iidToLocation.js ***!
  \******************************/
/***/ (() => {

/*
 * Copyright 2013-2014 Samsung Information Systems America, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Author: Koushik Sen
// do not remove the following comment
// JALANGI DO NOT INSTRUMENT

if (typeof J$$ === 'undefined') {
  J$$ = {};
}

(function (sandbox) {
  if (typeof sandbox.iidToLocation !== 'undefined') {
      return;
  }
  sandbox.iidToLocation = function (sid, iid) {
      var ret, arr, gid=sid;
      if (sandbox.smap) {
          if (typeof sid === 'string' && sid.indexOf(':')>=0) {
              sid = sid.split(':');
              iid = parseInt(sid[1]);
              sid = parseInt(sid[0]);
          } else {
              gid = sid+":"+iid;
          }
          if ((ret = sandbox.smap[sid])) {
              var fname = ret.originalCodeFileName;
              if (ret.evalSid !== undefined) {
                  fname = fname+sandbox.iidToLocation(ret.evalSid, ret.evalIid);
              }
              arr = ret[iid];
              if (arr) {
                  if (sandbox.Results) {
                      return "<a href=\"javascript:iidToDisplayCodeLocation('"+gid+"');\">(" + fname + ":" + arr[0] + ":" + arr[1] + ":" + arr[2] + ":" + arr[3] + ")</a>";
                  } else {
                      return "(" + fname + ":" + arr[0] + ":" + arr[1] + ":" + arr[2] + ":" + arr[3] + ")";
                  }
              } else {
                  return "(" + fname + ":iid" + iid + ")";
              }
          }
      }
      return sid+"";
  };

  sandbox.getGlobalIID = function(iid) {
      return sandbox.sid +":"+iid;
  }

}(J$$));


/***/ }),

/***/ "./src/runtime.js":
/*!************************!*\
  !*** ./src/runtime.js ***!
  \************************/
/***/ (() => {

/*
 * Copyright 2014 Samsung Information Systems America, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Author: Koushik Sen

// do not remove the following comment
// JALANGI DO NOT INSTRUMENT


// wrap in anonymous function to create local namespace when in browser
// create / reset J$$ global variable to hold analysis runtime
if (typeof J$$ === 'undefined') {
  J$$ = {};
}

(function (sandbox) {
  if (typeof sandbox.B !== 'undefined') {
      return;
  }
  //----------------------------------- Begin Jalangi Library backend ---------------------------------

  // stack of return values from instrumented functions.
  // we need to keep a stack since a function may return and then
  // have another function call in a finally block (see test
  // call_in_finally.js)

  var global = this;
  var Function = global.Function;
  var returnStack = [];
  var wrappedExceptionVal;
  var lastVal;
  var switchLeft;
  var switchKeyStack = [];
  var argIndex;
  var EVAL_ORG = eval;
  var lastComputedValue;
  var SPECIAL_PROP_SID = sandbox.Constants.SPECIAL_PROP_SID;
  var SPECIAL_PROP_IID = sandbox.Constants.SPECIAL_PROP_IID;

  function getPropSafe(base, prop){
    if(base === null || base === undefined){
      return undefined;
    }
    return base[prop];
  }

  function decodeBitPattern(i, len) {
      var ret = new Array(len);
      for (var j=0; j<len; j++) {
          var val = (i & 1)?true:false;
          ret[len - j -1] = val;
          i = i >> 1;
      }
      return ret;
  }

  function createBitPattern() {
      var ret = 0;
      var i;
      for (i =0; i< arguments.length; i++) {
          ret = (ret << 1)+(arguments[i]?1:0);
      }
      return ret;
  }


  var sidStack = [], sidCounter = 0;

  function createAndAssignNewSid() {
      sidStack.push(sandbox.sid);
      sandbox.sid = sidCounter = sidCounter + 1;
      if (!sandbox.smap) sandbox.smap = {};
      sandbox.smap[sandbox.sid] = sandbox.iids;
  }

  function rollBackSid() {
      sandbox.sid = sidStack.pop();
  }

  function associateSidWithFunction(f, iid) {
      if (typeof f === 'function') {
          if (Object && Object.defineProperty && typeof Object.defineProperty === 'function') {
              Object.defineProperty(f, SPECIAL_PROP_SID, {
                  enumerable:false,
                  writable:true
              });
              Object.defineProperty(f, SPECIAL_PROP_IID, {
                  enumerable:false,
                  writable:true
              });
          }
          f[SPECIAL_PROP_SID] = sandbox.sid;
          f[SPECIAL_PROP_IID] = iid;
      }
  }

  function updateSid(f) {
      sidStack.push(sandbox.sid);
      sandbox.sid = getPropSafe(f, SPECIAL_PROP_SID);
  }


  // unused
  function isNative(f) {
      return f.toString().indexOf('[native code]') > -1 || f.toString().indexOf('[object ') === 0;
  }

//   function callAsNativeConstructorWithEval(Constructor, args) {
//       var a = [];
//       for (var i = 0; i < args.length; i++)
//           a[i] = 'args[' + i + ']';
//       var eval = EVAL_ORG;
//       return eval('new Constructor(' + a.join() + ')');
//   }
    
    function callAsNativeConstructorWithoutEval(Constructor, args) {
        // Create a function that will call the constructor with the provided arguments
        const func = new Function('Constructor', 'args', 
            `return new Constructor(${args.map((_, i) => 'args[' + i + ']').join(', ')});`);
        // Call the function with the constructor and the arguments
        return func(Constructor, args);
    }

  function callAsNativeConstructor(Constructor, args) {
      if (args.length === 0) {
          return new Constructor();
      }
      if (args.length === 1) {
          return new Constructor(args[0]);
      }
      if (args.length === 2) {
          return new Constructor(args[0], args[1]);
      }
      if (args.length === 3) {
          return new Constructor(args[0], args[1], args[2]);
      }
      if (args.length === 4) {
          return new Constructor(args[0], args[1], args[2], args[3]);
      }
      if (args.length === 5) {
          return new Constructor(args[0], args[1], args[2], args[3], args[4]);
      }
      return callAsNativeConstructorWithoutEval(Constructor, args);
  }

  function callAsConstructor(Constructor, args) {
      var ret;
      if (true) {
          ret = callAsNativeConstructor(Constructor, args);
          return ret;
      } else { var Temp, inst; }
  }

  function invokeEval(base, f, args, iid) {
      return f(sandbox.instrumentEvalCode(args[0], iid, false));
  }

  function invokeFunctionDecl(base, f, args, iid) {
      // Invoke with the original parameters to preserve exceptional behavior if input is invalid
      f.apply(base, args);
      // Otherwise input is valid, so instrument and invoke via eval
      var newArgs = [];
      for (var i = 0; i < args.length-1; i++) {
          newArgs[i] = args[i];
      }
      var code = '(function(' + newArgs.join(', ') + ') { ' + args[args.length-1] + ' })';
      var code = sandbox.instrumentEvalCode(code, iid, false);
      // Using EVAL_ORG instead of eval() is important as it preserves the scoping semantics of Function()
      var out = EVAL_ORG(code);
      return out;
  }

  function callFun(f, base, args, isConstructor, iid) {
      var result;
      pushSwitchKey();
      try {
          if (f === EVAL_ORG) {
              result = invokeEval(base, f, args, iid);
          } else if (f === Function) {
              result = invokeFunctionDecl(base, f, args, iid);
          } else if (isConstructor) {
              result = callAsConstructor(f, args);
          } else {
              result = Function.prototype.apply.call(f, base, args);
          }
          return result;
      } finally {
          popSwitchKey();
      }
  }

  function invokeFun(iid, base, f, args, isConstructor, isMethod) {
      var aret, skip = false, result;

      if (sandbox.analysis && sandbox.analysis.invokeFunPre) {
          aret = sandbox.analysis.invokeFunPre(iid, f, base, args, isConstructor, isMethod, getPropSafe(f, SPECIAL_PROP_IID), getPropSafe(f, SPECIAL_PROP_SID));
          if (aret) {
              f = aret.f;
              base = aret.base;
              args = aret.args;
              skip = aret.skip;
          }
      }
      if (!skip) {
          result = callFun(f, base, args, isConstructor, iid);
      }
      if (sandbox.analysis && sandbox.analysis.invokeFun) {
          aret = sandbox.analysis.invokeFun(iid, f, base, args, result, isConstructor, isMethod, getPropSafe(f, SPECIAL_PROP_IID), getPropSafe(f, SPECIAL_PROP_SID));
          if (aret) {
              result = aret.result;
          }
      }
      return result;
  }

  // Function call (e.g., f())
  function F(iid, f, flags) {
      var bFlags = decodeBitPattern(flags, 1); // [isConstructor]
      return function () {
          var base = this;
          return (lastComputedValue = invokeFun(iid, base, f, arguments, bFlags[0], false));
      }
  }

  // Method call (e.g., e.f())
  function M(iid, base, offset, flags) {
      var bFlags = decodeBitPattern(flags, 2); // [isConstructor, isComputed]
      var f = G(iid + 2, base, offset, createBitPattern(bFlags[1], false, true));
      return function () {
          return (lastComputedValue = invokeFun(iid, base, f, arguments, bFlags[0], true));
      };
  }

  // Ignore argument (identity).
  function I(val) {
      return val;
  }

  var hasGetOwnPropertyDescriptor = typeof Object.getOwnPropertyDescriptor === 'function';
  // object/function/regexp/array Literal
  function T(iid, val, type, hasGetterSetter, internalIid) {
      var aret;
      associateSidWithFunction(val, internalIid);
      if (hasGetterSetter) {
          for (var offset in val) {
              if (hasGetOwnPropertyDescriptor && val.hasOwnProperty(offset)) {
                  var desc = Object.getOwnPropertyDescriptor(val, offset);
                  if (desc !== undefined) {
                      if (typeof desc.get === 'function') {
                          T(iid, desc.get, 12, false, internalIid);
                      }
                      if (typeof desc.set === 'function') {
                          T(iid, desc.set, 12, false, internalIid);
                      }
                  }
              }
          }
      }
      if (sandbox.analysis && sandbox.analysis.literal) {
          aret = sandbox.analysis.literal(iid, val, hasGetterSetter);
          if (aret) {
              val = aret.result;
          }
      }
      return (lastComputedValue = val);
  }

  // wrap object o in for (x in o) { ... }
  function H(iid, val) {
      var aret;
      if (sandbox.analysis && sandbox.analysis.forinObject) {
          aret = sandbox.analysis.forinObject(iid, val);
          if (aret) {
              val = aret.result;
          }
      }
      return val;
  }

  // variable declaration (Init)
  function N(iid, name, val, flags) {
      var bFlags = decodeBitPattern(flags, 3); // [isArgument, isLocalSync, isCatchParam]
      // isLocalSync is only true when we sync variables inside a for-in loop
      var aret;

      if (bFlags[0]) {
          argIndex++;
      }
      if (!bFlags[1] && sandbox.analysis && sandbox.analysis.declare) {
          if (bFlags[0] && argIndex > 1) {
              aret = sandbox.analysis.declare(iid, name, val, bFlags[0], argIndex - 2, bFlags[2]);
          } else {
              aret = sandbox.analysis.declare(iid, name, val, bFlags[0], -1, bFlags[2]);
          }
          if (aret) {
              val = aret.result;
          }
      }
      return val;
  }

  // getField (property read)
  function G(iid, base, offset, flags) {
      var bFlags = decodeBitPattern(flags, 3); // [isComputed, isOpAssign, isMethodCall]

      var aret, skip = false, val;

      if (sandbox.analysis && sandbox.analysis.getFieldPre) {
          aret = sandbox.analysis.getFieldPre(iid, base, offset, bFlags[0], bFlags[1], bFlags[2]);
          if (aret) {
              base = aret.base;
              offset = aret.offset;
              skip = aret.skip;
          }
      }

      if (!skip) {
          val = base[offset];
      }
      if (sandbox.analysis && sandbox.analysis.getField) {
          aret = sandbox.analysis.getField(iid, base, offset, val, bFlags[0], bFlags[1], bFlags[2]);
          if (aret) {
              val = aret.result;
          }
      }
      return (lastComputedValue = val);
  }

  // putField (property write)
  function P(iid, base, offset, val, flags) {
      var bFlags = decodeBitPattern(flags, 2); // [isComputed, isOpAssign]

      var aret, skip = false;

      if (sandbox.analysis && sandbox.analysis.putFieldPre) {
          aret = sandbox.analysis.putFieldPre(iid, base, offset, val, bFlags[0], !!bFlags[1]);
          if (aret) {
              base = aret.base;
              offset = aret.offset;
              val = aret.val;
              skip = aret.skip;
          }
      }

      if (!skip) {
          base[offset] = val;
      }
      if (sandbox.analysis && sandbox.analysis.putField) {
          aret = sandbox.analysis.putField(iid, base, offset, val, bFlags[0], !!bFlags[1]);
          if (aret) {
              val = aret.result;
          }
      }
      return (lastComputedValue = val);
  }

  // variable write
  // isGlobal means that the variable is global and not declared as var
  // isScriptLocal means that the variable is global and is declared as var
  function R(iid, name, val, flags) {
      var aret;
      var bFlags = decodeBitPattern(flags, 2); // [isGlobal, isScriptLocal]

      if (sandbox.analysis && sandbox.analysis.read) {
          aret = sandbox.analysis.read(iid, name, val, bFlags[0], bFlags[1]);
          if (aret) {
              val = aret.result;
          }
      }
      return (lastComputedValue = val);
  }

  // variable write
  function W(iid, name, val, lhs, flags) {
      var bFlags = decodeBitPattern(flags, 3); //[isGlobal, isScriptLocal, isDeclaration]
      var aret;
      if (sandbox.analysis && sandbox.analysis.write) {
          aret = sandbox.analysis.write(iid, name, val, lhs, bFlags[0], bFlags[1]);
          if (aret) {
              val = aret.result;
          }
      }
      if (!bFlags[2]) {
          return (lastComputedValue = val);
      } else {
          lastComputedValue = undefined;
          return val;
      }
  }

  // with statement
  function Wi(iid, val) {
      if (sandbox.analysis && sandbox.analysis._with) {
          aret = sandbox.analysis._with(iid, val);
          if (aret) {
              val = aret.result;
          }
      }
      return val;
  }

  // Uncaught exception
  function Ex(iid, e) {
      wrappedExceptionVal = {exception:e};
  }

  // Throw statement
  function Th(iid, val) {
      var aret;
      if (sandbox.analysis && sandbox.analysis._throw) {
          aret = sandbox.analysis._throw(iid, val);
          if (aret) {
              val = aret.result;
          }
      }
      return (lastComputedValue = val);
  }

  // Return statement
  function Rt(iid, val) {
      var aret;
      if (sandbox.analysis && sandbox.analysis._return) {
          aret = sandbox.analysis._return(iid, val);
          if (aret) {
              val = aret.result;
          }
      }
      returnStack.pop();
      returnStack.push(val);
      return (lastComputedValue = val);
  }

  // Actual return from function, invoked from 'finally' block
  // added around every function by instrumentation.  Reads
  // the return value stored by call to Rt()
  function Ra() {
      var returnVal = returnStack.pop();
      wrappedExceptionVal = undefined;
      return returnVal;
  }

  // Function enter
  function Fe(iid, f, dis /* this */, args) {
      argIndex = 0;
      returnStack.push(undefined);
      wrappedExceptionVal = undefined;
      updateSid(f);
      if (sandbox.analysis && sandbox.analysis.functionEnter) {
          sandbox.analysis.functionEnter(iid, f, dis, args);
      }
  }

  // Function exit
  function Fr(iid) {
      var isBacktrack = false, tmp, aret, returnVal;

      returnVal = returnStack.pop();
      if (sandbox.analysis && sandbox.analysis.functionExit) {
          aret = sandbox.analysis.functionExit(iid, returnVal, wrappedExceptionVal);
          if (aret) {
              returnVal = aret.returnVal;
              wrappedExceptionVal = aret.wrappedExceptionVal;
              isBacktrack = aret.isBacktrack;
          }
      }
      rollBackSid();
      if (!isBacktrack) {
          returnStack.push(returnVal);
      }
      // if there was an uncaught exception, throw it
      // here, to preserve exceptional control flow
      if (wrappedExceptionVal !== undefined) {
          tmp = wrappedExceptionVal.exception;
          wrappedExceptionVal = undefined;
          throw tmp;
      }
      return isBacktrack;
  }

  // Script enter
  function Se(iid, val, origFileName) {
      createAndAssignNewSid();
      if (sandbox.analysis && sandbox.analysis.scriptEnter) {
          sandbox.analysis.scriptEnter(iid, val, origFileName);
      }
      lastComputedValue = undefined;
  }

  // Script exit
  function Sr(iid) {
      var tmp, aret, isBacktrack;
      if (sandbox.analysis && sandbox.analysis.scriptExit) {
          aret = sandbox.analysis.scriptExit(iid, wrappedExceptionVal);
          if (aret) {
              wrappedExceptionVal = aret.wrappedExceptionVal;
              isBacktrack = aret.isBacktrack;
          }
      }
      rollBackSid();
      if (wrappedExceptionVal !== undefined) {
          tmp = wrappedExceptionVal.exception;
          wrappedExceptionVal = undefined;
          throw tmp;
      }
      return isBacktrack;
  }


  // Modify and assign +=, -= ...
  function A(iid, base, offset, op, flags) {
      var bFlags = decodeBitPattern(flags, 1); // [isComputed]
      // avoid iid collision: make sure that iid+2 has the same source map as iid (@todo)
      var oprnd1 = G(iid+2, base, offset, createBitPattern(bFlags[0], true, false));
      return function (oprnd2) {
          // still possible to get iid collision with a mem operation
          var val = B(iid, op, oprnd1, oprnd2, createBitPattern(false, true, false));
          return P(iid, base, offset, val, createBitPattern(bFlags[0], true));
      };
  }

  // Binary operation
  function B(iid, op, left, right, flags) {
      var bFlags = decodeBitPattern(flags, 3); // [isComputed, isOpAssign, isSwitchCaseComparison]
      var result, aret, skip = false;

      if (sandbox.analysis && sandbox.analysis.binaryPre) {
          aret = sandbox.analysis.binaryPre(iid, op, left, right, bFlags[1], bFlags[2], bFlags[0]);
          if (aret) {
              op = aret.op;
              left = aret.left;
              right = aret.right;
              skip = aret.skip;
          }
      }


      if (!skip) {
          switch (op) {
              case "+":
                  result = left + right;
                  break;
              case "-":
                  result = left - right;
                  break;
              case "*":
                  result = left * right;
                  break;
              case "/":
                  result = left / right;
                  break;
              case "%":
                  result = left % right;
                  break;
              case "<<":
                  result = left << right;
                  break;
              case ">>":
                  result = left >> right;
                  break;
              case ">>>":
                  result = left >>> right;
                  break;
              case "<":
                  result = left < right;
                  break;
              case ">":
                  result = left > right;
                  break;
              case "<=":
                  result = left <= right;
                  break;
              case ">=":
                  result = left >= right;
                  break;
              case "==":
                  result = left == right;
                  break;
              case "!=":
                  result = left != right;
                  break;
              case "===":
                  result = left === right;
                  break;
              case "!==":
                  result = left !== right;
                  break;
              case "&":
                  result = left & right;
                  break;
              case "|":
                  result = left | right;
                  break;
              case "^":
                  result = left ^ right;
                  break;
              case "delete":
                  result = delete left[right];
                  break;
              case "instanceof":
                  result = left instanceof right;
                  break;
              case "in":
                  result = left in right;
                  break;
              default:
                  throw new Error(op + " at " + iid + " not found");
                  break;
          }
      }

      if (sandbox.analysis && sandbox.analysis.binary) {
          aret = sandbox.analysis.binary(iid, op, left, right, result, bFlags[1], bFlags[2], bFlags[0]);
          if (aret) {
              result = aret.result;
          }
      }
      return (lastComputedValue = result);
  }


  // Unary operation
  function U(iid, op, left) {
      var result, aret, skip = false;

      if (sandbox.analysis && sandbox.analysis.unaryPre) {
          aret = sandbox.analysis.unaryPre(iid, op, left);
          if (aret) {
              op = aret.op;
              left = aret.left;
              skip = aret.skip
          }
      }

      if (!skip) {
          switch (op) {
              case "+":
                  result = +left;
                  break;
              case "-":
                  result = -left;
                  break;
              case "~":
                  result = ~left;
                  break;
              case "!":
                  result = !left;
                  break;
              case "typeof":
                  result = typeof left;
                  break;
              case "void":
                  result = void(left);
                  break;
              default:
                  throw new Error(op + " at " + iid + " not found");
                  break;
          }
      }

      if (sandbox.analysis && sandbox.analysis.unary) {
          aret = sandbox.analysis.unary(iid, op, left, result);
          if (aret) {
              result = aret.result;
          }
      }
      return (lastComputedValue = result);
  }

  function pushSwitchKey() {
      switchKeyStack.push(switchLeft);
  }

  function popSwitchKey() {
      switchLeft = switchKeyStack.pop();
  }

  function last() {
      return (lastComputedValue = lastVal);
  }

  // Switch key
  // E.g., for 'switch (x) { ... }',
  // C1 is invoked with value of x
  function C1(iid, left) {
      switchLeft = left;
      return (lastComputedValue = left);
  }

  // case label inside switch
  function C2(iid, right) {
      var aret, result;

      // avoid iid collision; iid may not have a map in the sourcemap
      result = B(iid+1, "===", switchLeft, right, createBitPattern(false, false, true));

      if (sandbox.analysis && sandbox.analysis.conditional) {
          aret = sandbox.analysis.conditional(iid, result);
          if (aret) {
              if (result && !aret.result) {
                  right = !right;
              } else if (result && aret.result) {
                  right = switchLeft;
              }
          }
      }
      return (lastComputedValue = right);
  }

  // Expression in conditional
  function C(iid, left) {
      var aret;
      if (sandbox.analysis && sandbox.analysis.conditional) {
          aret = sandbox.analysis.conditional(iid, left);
          if (aret) {
              left = aret.result;
          }
      }

      lastVal = left;
      return (lastComputedValue = left);
  }

  function S(iid, f) {
      if (sandbox.analysis && sandbox.analysis.runInstrumentedFunctionBody) {
          return sandbox.analysis.runInstrumentedFunctionBody(iid, f, getPropSafe(f, SPECIAL_PROP_IID), getPropSafe(f, SPECIAL_PROP_SID));
      }
      return true;
  }

  function L() {
      return lastComputedValue;
  }


  function X1(iid, val) {
      if (sandbox.analysis && sandbox.analysis.endExpression) {
          sandbox.analysis.endExpression(iid);
      }

      return (lastComputedValue = val);
  }

  function endExecution() {
      if (sandbox.analysis && sandbox.analysis.endExecution) {
          return sandbox.analysis.endExecution();
      }
  }


  function log(str) {
      if (sandbox.Results && sandbox.Results.execute) {
          sandbox.Results.execute(function(div, jquery, editor){
              div.append(str+"<br>");
          });
      } else {
          console.log(str);
      }
  }


  //----------------------------------- End Jalangi Library backend ---------------------------------

  sandbox.U = U; // Unary operation
  sandbox.B = B; // Binary operation
  sandbox.C = C; // Condition
  sandbox.C1 = C1; // Switch key
  sandbox.C2 = C2; // case label C1 === C2
  sandbox._ = last;  // Last value passed to C

  sandbox.H = H; // hash in for-in
  sandbox.I = I; // Ignore argument
  sandbox.G = G; // getField
  sandbox.P = P; // putField
  sandbox.R = R; // Read
  sandbox.W = W; // Write
  sandbox.N = N; // Init
  sandbox.T = T; // object/function/regexp/array Literal
  sandbox.F = F; // Function call
  sandbox.M = M; // Method call
  sandbox.A = A; // Modify and assign +=, -= ...
  sandbox.Fe = Fe; // Function enter
  sandbox.Fr = Fr; // Function return
  sandbox.Se = Se; // Script enter
  sandbox.Sr = Sr; // Script return
  sandbox.Rt = Rt; // returned value
  sandbox.Th = Th; // thrown value
  sandbox.Ra = Ra;
  sandbox.Ex = Ex;
  sandbox.L = L;
  sandbox.X1 = X1; // top level expression
  sandbox.Wi = Wi; // with statement
  sandbox.endExecution = endExecution;

  sandbox.S = S;

  sandbox.EVAL_ORG = EVAL_ORG;
  sandbox.log = log;
})(J$$);



/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId](module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
/*!**********************!*\
  !*** ./src/entry.js ***!
  \**********************/
__webpack_require__(/*! ./config.js */ "./src/config.js");
__webpack_require__(/*! ./constants.js */ "./src/constants.js");
__webpack_require__(/*! ./runtime.js */ "./src/runtime.js");
__webpack_require__(/*! ./iidToLocation.js */ "./src/iidToLocation.js");
// require('./astUtil.js');
// require('./esnstrument.js');
})();

/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGhlaHVsay1qYWxhbmdpMi1ydW50aW1lLmJ1bmRsZS5qcyIsIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGdEQUFnRDtBQUNoRCxnREFBZ0Q7QUFDaEQsaURBQWlEO0FBQ2pELHNEQUFzRCxnQkFBZ0I7QUFDdEUsc0RBQXNELGdCQUFnQjtBQUN0RSxzREFBc0Q7QUFDdEQsa0ZBQWtGLGdCQUFnQjtBQUNsRyxxREFBcUQ7QUFDckQsc0RBQXNELGVBQWU7QUFDckUsdURBQXVELGdCQUFnQjtBQUN2RSx3REFBd0QsaUJBQWlCO0FBQ3pFLG1EQUFtRCxnQkFBZ0I7QUFDbkUsQ0FBQzs7Ozs7Ozs7Ozs7QUN0REQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBLDRCQUE0QixLQUE4Qjs7QUFFMUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOztBQUVBOztBQUVBOztBQUVBO0FBQ0Esc0ZBQXNGO0FBQ3RGOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsY0FBYztBQUNkO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQSxDQUFDOzs7Ozs7Ozs7Ozs7QUNwR0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVk7QUFDWjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHVGQUF1RjtBQUN2RixvQkFBb0I7QUFDcEI7QUFDQTtBQUNBLGdCQUFnQjtBQUNoQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBLENBQUM7Ozs7Ozs7Ozs7O0FDOUREO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTs7QUFFQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0Esb0JBQW9CLE9BQU87QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLGlCQUFpQixxQkFBcUI7QUFDdEM7QUFDQTtBQUNBO0FBQ0E7OztBQUdBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsZUFBZTtBQUNmO0FBQ0E7QUFDQTtBQUNBLGVBQWU7QUFDZjtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EseUJBQXlCLGlCQUFpQjtBQUMxQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esc0NBQXNDLGlEQUFpRCxFQUFFO0FBQ3pGO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLFVBQVUsSUFBSTtBQUNkO0FBQ0E7QUFDQSxRQUFRLEtBQUssbUJBT047QUFDUDs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHNCQUFzQixtQkFBbUI7QUFDekM7QUFDQTtBQUNBLDBEQUEwRCw2QkFBNkI7QUFDdkY7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxZQUFZO0FBQ1o7QUFDQSxZQUFZO0FBQ1o7QUFDQSxZQUFZO0FBQ1o7QUFDQTtBQUNBO0FBQ0EsUUFBUTtBQUNSO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLCtDQUErQztBQUMvQztBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSwrQ0FBK0M7QUFDL0M7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQSxxQ0FBcUM7QUFDckM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLCtDQUErQztBQUMvQztBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVk7QUFDWjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSwrQ0FBK0M7O0FBRS9DOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsK0NBQStDOztBQUUvQzs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsK0NBQStDOztBQUUvQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSwrQ0FBK0M7QUFDL0M7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFBUTtBQUNSO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSw2QkFBNkI7QUFDN0I7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7QUFDQTtBQUNBLCtDQUErQztBQUMvQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSwrQ0FBK0M7QUFDL0M7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNkJBQTZCLEtBQUs7QUFDbEM7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUEsOEJBQThCO0FBQzlCOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxnQkFBZ0I7QUFDaEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7O0FBR0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFdBQVc7QUFDWCxRQUFRO0FBQ1I7QUFDQTtBQUNBOzs7QUFHQTs7QUFFQSxpQkFBaUI7QUFDakIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixtQkFBbUI7QUFDbkIsbUJBQW1CO0FBQ25CLHFCQUFxQjs7QUFFckIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixpQkFBaUI7QUFDakIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixpQkFBaUI7QUFDakIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixpQkFBaUI7QUFDakIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixtQkFBbUI7QUFDbkIsbUJBQW1CO0FBQ25CLG1CQUFtQjtBQUNuQixtQkFBbUI7QUFDbkIsbUJBQW1CO0FBQ25CLG1CQUFtQjtBQUNuQjtBQUNBO0FBQ0E7QUFDQSxtQkFBbUI7QUFDbkIsbUJBQW1CO0FBQ25COztBQUVBOztBQUVBO0FBQ0E7QUFDQSxDQUFDOzs7Ozs7OztVQ2p6QkQ7VUFDQTs7VUFFQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTs7VUFFQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTs7Ozs7Ozs7O0FDdEJBLG1CQUFPLENBQUMsb0NBQWE7QUFDckIsbUJBQU8sQ0FBQywwQ0FBZ0I7QUFDeEIsbUJBQU8sQ0FBQyxzQ0FBYztBQUN0QixtQkFBTyxDQUFDLGtEQUFvQjtBQUM1QjtBQUNBLCtCIiwic291cmNlcyI6WyJ3ZWJwYWNrOi8vamFsYW5naTItcnVudGltZS8uL3NyYy9jb25maWcuanMiLCJ3ZWJwYWNrOi8vamFsYW5naTItcnVudGltZS8uL3NyYy9jb25zdGFudHMuanMiLCJ3ZWJwYWNrOi8vamFsYW5naTItcnVudGltZS8uL3NyYy9paWRUb0xvY2F0aW9uLmpzIiwid2VicGFjazovL2phbGFuZ2kyLXJ1bnRpbWUvLi9zcmMvcnVudGltZS5qcyIsIndlYnBhY2s6Ly9qYWxhbmdpMi1ydW50aW1lL3dlYnBhY2svYm9vdHN0cmFwIiwid2VicGFjazovL2phbGFuZ2kyLXJ1bnRpbWUvLi9zcmMvZW50cnkuanMiXSwic291cmNlc0NvbnRlbnQiOlsiLypcbiAqIENvcHlyaWdodCAoYykgMjAxNCBTYW1zdW5nIEVsZWN0cm9uaWNzIENvLiwgTHRkLlxuICpcbiAqIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4gKiB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4gKiBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbiAqXG4gKiAgICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4gKlxuICogVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuICogZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuICogV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4gKiBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4gKiBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbiAqL1xuLy8gZG8gbm90IHJlbW92ZSB0aGUgZm9sbG93aW5nIGNvbW1lbnRcbi8vIEpBTEFOR0kgRE8gTk9UIElOU1RSVU1FTlRcbmlmICh0eXBlb2YgSiQkID09PSAndW5kZWZpbmVkJykge1xuICAgIEokJCA9IHt9O1xufVxuXG4oZnVuY3Rpb24gKHNhbmRib3gpIHtcbiAgICBpZiAodHlwZW9mIHNhbmRib3guQ29uZmlnICE9PSAndW5kZWZpbmVkJykge1xuICAgICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgdmFyIENvbmZpZyA9IHNhbmRib3guQ29uZmlnID0ge307XG5cbiAgICBDb25maWcuREVCVUcgPSBmYWxzZTtcbiAgICBDb25maWcuV0FSTiA9IGZhbHNlO1xuICAgIENvbmZpZy5TRVJJT1VTX1dBUk4gPSBmYWxzZTtcbi8vIG1ha2UgTUFYX0JVRl9TSVpFIHNsaWdodGx5IGxlc3MgdGhhbiAyXjE2LCB0byBhbGxvdyBvdmVyIGxvdy1sZXZlbCBvdmVyaGVhZHNcbiAgICBDb25maWcuTUFYX0JVRl9TSVpFID0gNjQwMDA7XG4gICAgQ29uZmlnLkxPR19BTExfUkVBRFNfQU5EX0JSQU5DSEVTID0gZmFsc2U7XG5cbiAgICAvLyoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbiAgICAvLyAgRnVuY3Rpb25zIGZvciBzZWxlY3RpdmUgaW5zdHJ1bWVudGF0aW9uIG9mIG9wZXJhdGlvbnNcbiAgICAvLyoqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKipcbiAgICAvLyBJbiB0aGUgZm9sbG93aW5nIGZ1bmN0aW9uc1xuICAgIC8vIHJldHVybiB0cnVlIGluIGEgZnVuY3Rpb24sIGlmIHlvdSB3YW50IHRoZSBhc3Qgbm9kZSAocGFzc2VkIGFzIHRoZSBzZWNvbmQgYXJndW1lbnQpIHRvIGJlIGluc3RydW1lbnRlZFxuICAgIC8vIGFzdCBub2RlIGdldHMgaW5zdHJ1bWVudGVkIGlmIHlvdSBkbyBub3QgZGVmaW5lIHRoZSBjb3JyZXNwb25kaW5nIGZ1bmN0aW9uXG4gICAgQ29uZmlnLkVOQUJMRV9TQU1QTElORyA9IGZhbHNlO1xuLy8gICAgQ29uZmlnLklOU1RSX0lOSVQgPSBmdW5jdGlvbihuYW1lLCBhc3QpIHsgcmV0dXJuIGZhbHNlOyB9O1xuLy8gICAgQ29uZmlnLklOU1RSX1JFQUQgPSBmdW5jdGlvbihuYW1lLCBhc3QpIHsgcmV0dXJuIGZhbHNlOyB9O1xuLy8gICAgQ29uZmlnLklOU1RSX1dSSVRFID0gZnVuY3Rpb24obmFtZSwgYXN0KSB7IHJldHVybiB0cnVlOyB9O1xuLy8gICAgQ29uZmlnLklOU1RSX0dFVEZJRUxEID0gZnVuY3Rpb24ob2Zmc2V0LCBhc3QpIHsgcmV0dXJuIHRydWU7IH07IC8vIG9mZnNldCBpcyBudWxsIGlmIHRoZSBwcm9wZXJ0eSBpcyBjb21wdXRlZFxuLy8gICAgQ29uZmlnLklOU1RSX1BVVEZJRUxEID0gZnVuY3Rpb24ob2Zmc2V0LCBhc3QpIHsgcmV0dXJuIHRydWU7IH07IC8vIG9mZnNldCBpcyBudWxsIGlmIHRoZSBwcm9wZXJ0eSBpcyBjb21wdXRlZFxuLy8gICAgQ29uZmlnLklOU1RSX0JJTkFSWSA9IGZ1bmN0aW9uKG9wZXJhdG9yLCBhc3QpIHsgcmV0dXJuIHRydWU7IH07XG4vLyAgICBDb25maWcuSU5TVFJfUFJPUEVSVFlfQklOQVJZX0FTU0lHTk1FTlQgPSBmdW5jdGlvbihvcGVyYXRvciwgb2Zmc2V0LCBhc3QpIHsgcmV0dXJuIHRydWU7IH07IC8vIGEueCArPSBlIG9yIGFbZTFdICs9IGUyXG4vLyAgICBDb25maWcuSU5TVFJfVU5BUlkgPSBmdW5jdGlvbihvcGVyYXRvciwgYXN0KSB7IHJldHVybiB0cnVlOyB9O1xuLy8gICAgQ29uZmlnLklOU1RSX0xJVEVSQUwgPSBmdW5jdGlvbihsaXRlcmFsLCBhc3QpIHsgcmV0dXJuIHRydWU7fTsgLy8gbGl0ZXJhbCBnZXRzIHNvbWUgZHVtbXkgdmFsdWUgaWYgdGhlIHR5cGUgaXMgb2JqZWN0LCBmdW5jdGlvbiwgb3IgYXJyYXlcbi8vICAgIENvbmZpZy5JTlNUUl9DT05ESVRJT05BTCA9IGZ1bmN0aW9uKHR5cGUsIGFzdCkgeyByZXR1cm4gdHJ1ZTsgfTsgLy8gdHlwZSBjb3VsZCBiZSBcIiYmXCIsIFwifHxcIiwgXCJzd2l0Y2hcIiwgXCJvdGhlclwiXG4vLyAgICBDb25maWcuSU5TVFJfVFJZX0NBVENIX0FSR1VNRU5UUyA9IGZ1bmN0aW9uKGFzdCkge3JldHVybiBmYWxzZTsgfTsgLy8gd3JhcCBmdW5jdGlvbiBhbmQgc2NyaXB0IGJvZGllcyB3aXRoIHRyeSBjYXRjaCBibG9jayBhbmQgdXNlIGFyZ3VtZW50cyBpbiBKJC5GZS4gIERPIE5PVCBVU0UgVEhJUy5cbi8vICAgIENvbmZpZy5JTlNUUl9FTkRfRVhQUkVTU0lPTiA9IGZ1bmN0aW9uKGFzdCkge3JldHVybiB0cnVlOyB9OyAvLyB0b3AtbGV2ZWwgZXhwcmVzc2lvbiBtYXJrZXJcbn0oSiQkKSk7XG4iLCIvKlxuICogQ29weXJpZ2h0IChjKSAyMDE0IFNhbXN1bmcgRWxlY3Ryb25pY3MgQ28uLCBMdGQuXG4gKlxuICogTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbiAqIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbiAqIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuICpcbiAqICAgICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbiAqXG4gKiBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4gKiBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4gKiBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbiAqIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbiAqIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxuICovXG4vLyBkbyBub3QgcmVtb3ZlIHRoZSBmb2xsb3dpbmcgY29tbWVudFxuLy8gSkFMQU5HSSBETyBOT1QgSU5TVFJVTUVOVFxuaWYgKHR5cGVvZiBKJCQgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgSiQkID0ge307XG59XG5cbihmdW5jdGlvbiAoc2FuZGJveCkge1xuICAgIGlmICh0eXBlb2Ygc2FuZGJveC5Db25zdGFudHMgIT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG4gICAgdmFyIENvbnN0YW50cyA9IHNhbmRib3guQ29uc3RhbnRzID0ge307XG5cbiAgICBDb25zdGFudHMuaXNCcm93c2VyID0gISh0eXBlb2YgZXhwb3J0cyAhPT0gJ3VuZGVmaW5lZCcgJiYgdGhpcy5leHBvcnRzICE9PSBleHBvcnRzKTtcblxuICAgIHZhciBBUFBMWSA9IENvbnN0YW50cy5BUFBMWSA9IEZ1bmN0aW9uLnByb3RvdHlwZS5hcHBseTtcbiAgICB2YXIgQ0FMTCA9IENvbnN0YW50cy5DQUxMID0gRnVuY3Rpb24ucHJvdG90eXBlLmNhbGw7XG4gICAgQVBQTFkuYXBwbHkgPSBBUFBMWTtcbiAgICBBUFBMWS5jYWxsID0gQ0FMTDtcbiAgICBDQUxMLmFwcGx5ID0gQVBQTFk7XG4gICAgQ0FMTC5jYWxsID0gQ0FMTDtcblxuICAgIHZhciBIQVNfT1dOX1BST1BFUlRZID0gQ29uc3RhbnRzLkhBU19PV05fUFJPUEVSVFkgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5O1xuICAgIENvbnN0YW50cy5IQVNfT1dOX1BST1BFUlRZX0NBTEwgPSBPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGw7XG5cblxuICAgIHZhciBQUkVGSVgxID0gQ29uc3RhbnRzLkpBTEFOR0lfVkFSID0gXCJKJCRcIjtcbiAgICBDb25zdGFudHMuU1BFQ0lBTF9QUk9QID0gXCIqXCIgKyBQUkVGSVgxICsgXCIqXCI7XG4gICAgQ29uc3RhbnRzLlNQRUNJQUxfUFJPUDIgPSBcIipcIiArIFBSRUZJWDEgKyBcIkkqXCI7XG4gICAgQ29uc3RhbnRzLlNQRUNJQUxfUFJPUDMgPSBcIipcIiArIFBSRUZJWDEgKyBcIkMqXCI7XG4gICAgQ29uc3RhbnRzLlNQRUNJQUxfUFJPUDQgPSBcIipcIiArIFBSRUZJWDEgKyBcIlcqXCI7XG4gICAgQ29uc3RhbnRzLlNQRUNJQUxfUFJPUF9TSUQgPSBcIipcIiArIFBSRUZJWDEgKyBcIlNJRCpcIjtcbiAgICBDb25zdGFudHMuU1BFQ0lBTF9QUk9QX0lJRCA9IFwiKlwiICsgUFJFRklYMSArIFwiSUlEKlwiO1xuXG4gICAgQ29uc3RhbnRzLlVOS05PV04gPSAtMTtcblxuICAgIC8vLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gRW5kIGNvbnN0YW50cyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIC8vLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gQ29uc3RhbnQgZnVuY3Rpb25zIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbiAgICB2YXIgSE9QID0gQ29uc3RhbnRzLkhPUCA9IGZ1bmN0aW9uIChvYmosIHByb3ApIHtcbiAgICAgICAgcmV0dXJuIChwcm9wICsgXCJcIiA9PT0gJ19fcHJvdG9fXycpIHx8IENBTEwuY2FsbChIQVNfT1dOX1BST1BFUlRZLCBvYmosIHByb3ApOyAvL0NvbnN0YW50cy5IQVNfT1dOX1BST1BFUlRZX0NBTEwuYXBwbHkoQ29uc3RhbnRzLkhBU19PV05fUFJPUEVSVFksIFtvYmosIHByb3BdKTtcbiAgICB9O1xuXG4gICAgQ29uc3RhbnRzLmhhc0dldHRlclNldHRlciA9IGZ1bmN0aW9uIChvYmosIHByb3AsIGlzR2V0dGVyKSB7XG4gICAgICAgIGlmICh0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvciAhPT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgIH1cbiAgICAgICAgd2hpbGUgKG9iaiAhPT0gbnVsbCkge1xuICAgICAgICAgICAgaWYgKHR5cGVvZiBvYmogIT09ICdvYmplY3QnICYmIHR5cGVvZiBvYmogIT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICB2YXIgZGVzYyA9IE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3Iob2JqLCBwcm9wKTtcbiAgICAgICAgICAgIGlmIChkZXNjICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICBpZiAoaXNHZXR0ZXIgJiYgdHlwZW9mIGRlc2MuZ2V0ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICBpZiAoIWlzR2V0dGVyICYmIHR5cGVvZiBkZXNjLnNldCA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICB9IGVsc2UgaWYgKEhPUChvYmosIHByb3ApKSB7XG4gICAgICAgICAgICAgICAgcmV0dXJuIGZhbHNlO1xuICAgICAgICAgICAgfVxuICAgICAgICAgICAgb2JqID0gb2JqLl9fcHJvdG9fXztcbiAgICAgICAgfVxuICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgfTtcblxuICAgIENvbnN0YW50cy5kZWJ1Z1ByaW50ID0gZnVuY3Rpb24gKHMpIHtcbiAgICAgICAgaWYgKHNhbmRib3guQ29uZmlnLkRFQlVHKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIioqKlwiICsgcyk7XG4gICAgICAgIH1cbiAgICB9O1xuXG4gICAgQ29uc3RhbnRzLndhcm5QcmludCA9IGZ1bmN0aW9uIChpaWQsIHMpIHtcbiAgICAgICAgaWYgKHNhbmRib3guQ29uZmlnLldBUk4gJiYgaWlkICE9PSAwKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIiAgICAgICAgYXQgXCIgKyBpaWQgKyBcIiBcIiArIHMpO1xuICAgICAgICB9XG4gICAgfTtcblxuICAgIENvbnN0YW50cy5zZXJpb3VzV2FyblByaW50ID0gZnVuY3Rpb24gKGlpZCwgcykge1xuICAgICAgICBpZiAoc2FuZGJveC5Db25maWcuU0VSSU9VU19XQVJOICYmIGlpZCAhPT0gMCkge1xuICAgICAgICAgICAgY29uc29sZS5sb2coXCIgICAgICAgIGF0IFwiICsgaWlkICsgXCIgU2VyaW91cyBcIiArIHMpO1xuICAgICAgICB9XG4gICAgfTtcblxufSkoSiQkKTtcblxuIiwiLypcbiAqIENvcHlyaWdodCAyMDEzLTIwMTQgU2Ftc3VuZyBJbmZvcm1hdGlvbiBTeXN0ZW1zIEFtZXJpY2EsIEluYy5cbiAqXG4gKiBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuICogeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuICogWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4gKlxuICogICAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuICpcbiAqIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbiAqIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbiAqIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuICogU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuICogbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG4gKi9cblxuLy8gQXV0aG9yOiBLb3VzaGlrIFNlblxuLy8gZG8gbm90IHJlbW92ZSB0aGUgZm9sbG93aW5nIGNvbW1lbnRcbi8vIEpBTEFOR0kgRE8gTk9UIElOU1RSVU1FTlRcblxuaWYgKHR5cGVvZiBKJCQgPT09ICd1bmRlZmluZWQnKSB7XG4gIEokJCA9IHt9O1xufVxuXG4oZnVuY3Rpb24gKHNhbmRib3gpIHtcbiAgaWYgKHR5cGVvZiBzYW5kYm94LmlpZFRvTG9jYXRpb24gIT09ICd1bmRlZmluZWQnKSB7XG4gICAgICByZXR1cm47XG4gIH1cbiAgc2FuZGJveC5paWRUb0xvY2F0aW9uID0gZnVuY3Rpb24gKHNpZCwgaWlkKSB7XG4gICAgICB2YXIgcmV0LCBhcnIsIGdpZD1zaWQ7XG4gICAgICBpZiAoc2FuZGJveC5zbWFwKSB7XG4gICAgICAgICAgaWYgKHR5cGVvZiBzaWQgPT09ICdzdHJpbmcnICYmIHNpZC5pbmRleE9mKCc6Jyk+PTApIHtcbiAgICAgICAgICAgICAgc2lkID0gc2lkLnNwbGl0KCc6Jyk7XG4gICAgICAgICAgICAgIGlpZCA9IHBhcnNlSW50KHNpZFsxXSk7XG4gICAgICAgICAgICAgIHNpZCA9IHBhcnNlSW50KHNpZFswXSk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgZ2lkID0gc2lkK1wiOlwiK2lpZDtcbiAgICAgICAgICB9XG4gICAgICAgICAgaWYgKChyZXQgPSBzYW5kYm94LnNtYXBbc2lkXSkpIHtcbiAgICAgICAgICAgICAgdmFyIGZuYW1lID0gcmV0Lm9yaWdpbmFsQ29kZUZpbGVOYW1lO1xuICAgICAgICAgICAgICBpZiAocmV0LmV2YWxTaWQgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgICAgZm5hbWUgPSBmbmFtZStzYW5kYm94LmlpZFRvTG9jYXRpb24ocmV0LmV2YWxTaWQsIHJldC5ldmFsSWlkKTtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICBhcnIgPSByZXRbaWlkXTtcbiAgICAgICAgICAgICAgaWYgKGFycikge1xuICAgICAgICAgICAgICAgICAgaWYgKHNhbmRib3guUmVzdWx0cykge1xuICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIjxhIGhyZWY9XFxcImphdmFzY3JpcHQ6aWlkVG9EaXNwbGF5Q29kZUxvY2F0aW9uKCdcIitnaWQrXCInKTtcXFwiPihcIiArIGZuYW1lICsgXCI6XCIgKyBhcnJbMF0gKyBcIjpcIiArIGFyclsxXSArIFwiOlwiICsgYXJyWzJdICsgXCI6XCIgKyBhcnJbM10gKyBcIik8L2E+XCI7XG4gICAgICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgICAgIHJldHVybiBcIihcIiArIGZuYW1lICsgXCI6XCIgKyBhcnJbMF0gKyBcIjpcIiArIGFyclsxXSArIFwiOlwiICsgYXJyWzJdICsgXCI6XCIgKyBhcnJbM10gKyBcIilcIjtcbiAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgICAgIHJldHVybiBcIihcIiArIGZuYW1lICsgXCI6aWlkXCIgKyBpaWQgKyBcIilcIjtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiBzaWQrXCJcIjtcbiAgfTtcblxuICBzYW5kYm94LmdldEdsb2JhbElJRCA9IGZ1bmN0aW9uKGlpZCkge1xuICAgICAgcmV0dXJuIHNhbmRib3guc2lkICtcIjpcIitpaWQ7XG4gIH1cblxufShKJCQpKTtcbiIsIi8qXG4gKiBDb3B5cmlnaHQgMjAxNCBTYW1zdW5nIEluZm9ybWF0aW9uIFN5c3RlbXMgQW1lcmljYSwgSW5jLlxuICpcbiAqIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4gKiB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4gKiBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbiAqXG4gKiAgICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4gKlxuICogVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuICogZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuICogV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4gKiBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4gKiBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbiAqL1xuXG4vLyBBdXRob3I6IEtvdXNoaWsgU2VuXG5cbi8vIGRvIG5vdCByZW1vdmUgdGhlIGZvbGxvd2luZyBjb21tZW50XG4vLyBKQUxBTkdJIERPIE5PVCBJTlNUUlVNRU5UXG5cblxuLy8gd3JhcCBpbiBhbm9ueW1vdXMgZnVuY3Rpb24gdG8gY3JlYXRlIGxvY2FsIG5hbWVzcGFjZSB3aGVuIGluIGJyb3dzZXJcbi8vIGNyZWF0ZSAvIHJlc2V0IEokJCBnbG9iYWwgdmFyaWFibGUgdG8gaG9sZCBhbmFseXNpcyBydW50aW1lXG5pZiAodHlwZW9mIEokJCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgSiQkID0ge307XG59XG5cbihmdW5jdGlvbiAoc2FuZGJveCkge1xuICBpZiAodHlwZW9mIHNhbmRib3guQiAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIHJldHVybjtcbiAgfVxuICAvLy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIEJlZ2luIEphbGFuZ2kgTGlicmFyeSBiYWNrZW5kIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gIC8vIHN0YWNrIG9mIHJldHVybiB2YWx1ZXMgZnJvbSBpbnN0cnVtZW50ZWQgZnVuY3Rpb25zLlxuICAvLyB3ZSBuZWVkIHRvIGtlZXAgYSBzdGFjayBzaW5jZSBhIGZ1bmN0aW9uIG1heSByZXR1cm4gYW5kIHRoZW5cbiAgLy8gaGF2ZSBhbm90aGVyIGZ1bmN0aW9uIGNhbGwgaW4gYSBmaW5hbGx5IGJsb2NrIChzZWUgdGVzdFxuICAvLyBjYWxsX2luX2ZpbmFsbHkuanMpXG5cbiAgdmFyIGdsb2JhbCA9IHRoaXM7XG4gIHZhciBGdW5jdGlvbiA9IGdsb2JhbC5GdW5jdGlvbjtcbiAgdmFyIHJldHVyblN0YWNrID0gW107XG4gIHZhciB3cmFwcGVkRXhjZXB0aW9uVmFsO1xuICB2YXIgbGFzdFZhbDtcbiAgdmFyIHN3aXRjaExlZnQ7XG4gIHZhciBzd2l0Y2hLZXlTdGFjayA9IFtdO1xuICB2YXIgYXJnSW5kZXg7XG4gIHZhciBFVkFMX09SRyA9IGV2YWw7XG4gIHZhciBsYXN0Q29tcHV0ZWRWYWx1ZTtcbiAgdmFyIFNQRUNJQUxfUFJPUF9TSUQgPSBzYW5kYm94LkNvbnN0YW50cy5TUEVDSUFMX1BST1BfU0lEO1xuICB2YXIgU1BFQ0lBTF9QUk9QX0lJRCA9IHNhbmRib3guQ29uc3RhbnRzLlNQRUNJQUxfUFJPUF9JSUQ7XG5cbiAgZnVuY3Rpb24gZ2V0UHJvcFNhZmUoYmFzZSwgcHJvcCl7XG4gICAgaWYoYmFzZSA9PT0gbnVsbCB8fCBiYXNlID09PSB1bmRlZmluZWQpe1xuICAgICAgcmV0dXJuIHVuZGVmaW5lZDtcbiAgICB9XG4gICAgcmV0dXJuIGJhc2VbcHJvcF07XG4gIH1cblxuICBmdW5jdGlvbiBkZWNvZGVCaXRQYXR0ZXJuKGksIGxlbikge1xuICAgICAgdmFyIHJldCA9IG5ldyBBcnJheShsZW4pO1xuICAgICAgZm9yICh2YXIgaj0wOyBqPGxlbjsgaisrKSB7XG4gICAgICAgICAgdmFyIHZhbCA9IChpICYgMSk/dHJ1ZTpmYWxzZTtcbiAgICAgICAgICByZXRbbGVuIC0gaiAtMV0gPSB2YWw7XG4gICAgICAgICAgaSA9IGkgPj4gMTtcbiAgICAgIH1cbiAgICAgIHJldHVybiByZXQ7XG4gIH1cblxuICBmdW5jdGlvbiBjcmVhdGVCaXRQYXR0ZXJuKCkge1xuICAgICAgdmFyIHJldCA9IDA7XG4gICAgICB2YXIgaTtcbiAgICAgIGZvciAoaSA9MDsgaTwgYXJndW1lbnRzLmxlbmd0aDsgaSsrKSB7XG4gICAgICAgICAgcmV0ID0gKHJldCA8PCAxKSsoYXJndW1lbnRzW2ldPzE6MCk7XG4gICAgICB9XG4gICAgICByZXR1cm4gcmV0O1xuICB9XG5cblxuICB2YXIgc2lkU3RhY2sgPSBbXSwgc2lkQ291bnRlciA9IDA7XG5cbiAgZnVuY3Rpb24gY3JlYXRlQW5kQXNzaWduTmV3U2lkKCkge1xuICAgICAgc2lkU3RhY2sucHVzaChzYW5kYm94LnNpZCk7XG4gICAgICBzYW5kYm94LnNpZCA9IHNpZENvdW50ZXIgPSBzaWRDb3VudGVyICsgMTtcbiAgICAgIGlmICghc2FuZGJveC5zbWFwKSBzYW5kYm94LnNtYXAgPSB7fTtcbiAgICAgIHNhbmRib3guc21hcFtzYW5kYm94LnNpZF0gPSBzYW5kYm94LmlpZHM7XG4gIH1cblxuICBmdW5jdGlvbiByb2xsQmFja1NpZCgpIHtcbiAgICAgIHNhbmRib3guc2lkID0gc2lkU3RhY2sucG9wKCk7XG4gIH1cblxuICBmdW5jdGlvbiBhc3NvY2lhdGVTaWRXaXRoRnVuY3Rpb24oZiwgaWlkKSB7XG4gICAgICBpZiAodHlwZW9mIGYgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICBpZiAoT2JqZWN0ICYmIE9iamVjdC5kZWZpbmVQcm9wZXJ0eSAmJiB0eXBlb2YgT2JqZWN0LmRlZmluZVByb3BlcnR5ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICAgIE9iamVjdC5kZWZpbmVQcm9wZXJ0eShmLCBTUEVDSUFMX1BST1BfU0lELCB7XG4gICAgICAgICAgICAgICAgICBlbnVtZXJhYmxlOmZhbHNlLFxuICAgICAgICAgICAgICAgICAgd3JpdGFibGU6dHJ1ZVxuICAgICAgICAgICAgICB9KTtcbiAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KGYsIFNQRUNJQUxfUFJPUF9JSUQsIHtcbiAgICAgICAgICAgICAgICAgIGVudW1lcmFibGU6ZmFsc2UsXG4gICAgICAgICAgICAgICAgICB3cml0YWJsZTp0cnVlXG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICBmW1NQRUNJQUxfUFJPUF9TSURdID0gc2FuZGJveC5zaWQ7XG4gICAgICAgICAgZltTUEVDSUFMX1BST1BfSUlEXSA9IGlpZDtcbiAgICAgIH1cbiAgfVxuXG4gIGZ1bmN0aW9uIHVwZGF0ZVNpZChmKSB7XG4gICAgICBzaWRTdGFjay5wdXNoKHNhbmRib3guc2lkKTtcbiAgICAgIHNhbmRib3guc2lkID0gZ2V0UHJvcFNhZmUoZiwgU1BFQ0lBTF9QUk9QX1NJRCk7XG4gIH1cblxuXG4gIC8vIHVudXNlZFxuICBmdW5jdGlvbiBpc05hdGl2ZShmKSB7XG4gICAgICByZXR1cm4gZi50b1N0cmluZygpLmluZGV4T2YoJ1tuYXRpdmUgY29kZV0nKSA+IC0xIHx8IGYudG9TdHJpbmcoKS5pbmRleE9mKCdbb2JqZWN0ICcpID09PSAwO1xuICB9XG5cbi8vICAgZnVuY3Rpb24gY2FsbEFzTmF0aXZlQ29uc3RydWN0b3JXaXRoRXZhbChDb25zdHJ1Y3RvciwgYXJncykge1xuLy8gICAgICAgdmFyIGEgPSBbXTtcbi8vICAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJncy5sZW5ndGg7IGkrKylcbi8vICAgICAgICAgICBhW2ldID0gJ2FyZ3NbJyArIGkgKyAnXSc7XG4vLyAgICAgICB2YXIgZXZhbCA9IEVWQUxfT1JHO1xuLy8gICAgICAgcmV0dXJuIGV2YWwoJ25ldyBDb25zdHJ1Y3RvcignICsgYS5qb2luKCkgKyAnKScpO1xuLy8gICB9XG4gICAgXG4gICAgZnVuY3Rpb24gY2FsbEFzTmF0aXZlQ29uc3RydWN0b3JXaXRob3V0RXZhbChDb25zdHJ1Y3RvciwgYXJncykge1xuICAgICAgICAvLyBDcmVhdGUgYSBmdW5jdGlvbiB0aGF0IHdpbGwgY2FsbCB0aGUgY29uc3RydWN0b3Igd2l0aCB0aGUgcHJvdmlkZWQgYXJndW1lbnRzXG4gICAgICAgIGNvbnN0IGZ1bmMgPSBuZXcgRnVuY3Rpb24oJ0NvbnN0cnVjdG9yJywgJ2FyZ3MnLCBcbiAgICAgICAgICAgIGByZXR1cm4gbmV3IENvbnN0cnVjdG9yKCR7YXJncy5tYXAoKF8sIGkpID0+ICdhcmdzWycgKyBpICsgJ10nKS5qb2luKCcsICcpfSk7YCk7XG4gICAgICAgIC8vIENhbGwgdGhlIGZ1bmN0aW9uIHdpdGggdGhlIGNvbnN0cnVjdG9yIGFuZCB0aGUgYXJndW1lbnRzXG4gICAgICAgIHJldHVybiBmdW5jKENvbnN0cnVjdG9yLCBhcmdzKTtcbiAgICB9XG5cbiAgZnVuY3Rpb24gY2FsbEFzTmF0aXZlQ29uc3RydWN0b3IoQ29uc3RydWN0b3IsIGFyZ3MpIHtcbiAgICAgIGlmIChhcmdzLmxlbmd0aCA9PT0gMCkge1xuICAgICAgICAgIHJldHVybiBuZXcgQ29uc3RydWN0b3IoKTtcbiAgICAgIH1cbiAgICAgIGlmIChhcmdzLmxlbmd0aCA9PT0gMSkge1xuICAgICAgICAgIHJldHVybiBuZXcgQ29uc3RydWN0b3IoYXJnc1swXSk7XG4gICAgICB9XG4gICAgICBpZiAoYXJncy5sZW5ndGggPT09IDIpIHtcbiAgICAgICAgICByZXR1cm4gbmV3IENvbnN0cnVjdG9yKGFyZ3NbMF0sIGFyZ3NbMV0pO1xuICAgICAgfVxuICAgICAgaWYgKGFyZ3MubGVuZ3RoID09PSAzKSB7XG4gICAgICAgICAgcmV0dXJuIG5ldyBDb25zdHJ1Y3RvcihhcmdzWzBdLCBhcmdzWzFdLCBhcmdzWzJdKTtcbiAgICAgIH1cbiAgICAgIGlmIChhcmdzLmxlbmd0aCA9PT0gNCkge1xuICAgICAgICAgIHJldHVybiBuZXcgQ29uc3RydWN0b3IoYXJnc1swXSwgYXJnc1sxXSwgYXJnc1syXSwgYXJnc1szXSk7XG4gICAgICB9XG4gICAgICBpZiAoYXJncy5sZW5ndGggPT09IDUpIHtcbiAgICAgICAgICByZXR1cm4gbmV3IENvbnN0cnVjdG9yKGFyZ3NbMF0sIGFyZ3NbMV0sIGFyZ3NbMl0sIGFyZ3NbM10sIGFyZ3NbNF0pO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGNhbGxBc05hdGl2ZUNvbnN0cnVjdG9yV2l0aG91dEV2YWwoQ29uc3RydWN0b3IsIGFyZ3MpO1xuICB9XG5cbiAgZnVuY3Rpb24gY2FsbEFzQ29uc3RydWN0b3IoQ29uc3RydWN0b3IsIGFyZ3MpIHtcbiAgICAgIHZhciByZXQ7XG4gICAgICBpZiAodHJ1ZSkge1xuICAgICAgICAgIHJldCA9IGNhbGxBc05hdGl2ZUNvbnN0cnVjdG9yKENvbnN0cnVjdG9yLCBhcmdzKTtcbiAgICAgICAgICByZXR1cm4gcmV0O1xuICAgICAgfSBlbHNlIHsgLy8gZWxzZSBicmFuY2ggaXMgYSBtb3JlIGVsZWdhbnQgdG8gY2FsbCBhIGNvbnN0cnVjdG9yIHJlZmxlY3RpdmVseSwgYnV0IGl0IGxlYWRzIHRvIG1lbW9yeSBsZWFrIGluIHY4LlxuICAgICAgICAgIHZhciBUZW1wID0gZnVuY3Rpb24gKCkge1xuICAgICAgICAgIH0sIGluc3Q7XG4gICAgICAgICAgVGVtcC5wcm90b3R5cGUgPSBDb25zdHJ1Y3Rvci5wcm90b3R5cGU7XG4gICAgICAgICAgaW5zdCA9IG5ldyBUZW1wO1xuICAgICAgICAgIHJldCA9IENvbnN0cnVjdG9yLmFwcGx5KGluc3QsIGFyZ3MpO1xuICAgICAgICAgIHJldHVybiBPYmplY3QocmV0KSA9PT0gcmV0ID8gcmV0IDogaW5zdDtcbiAgICAgIH1cbiAgfVxuXG4gIGZ1bmN0aW9uIGludm9rZUV2YWwoYmFzZSwgZiwgYXJncywgaWlkKSB7XG4gICAgICByZXR1cm4gZihzYW5kYm94Lmluc3RydW1lbnRFdmFsQ29kZShhcmdzWzBdLCBpaWQsIGZhbHNlKSk7XG4gIH1cblxuICBmdW5jdGlvbiBpbnZva2VGdW5jdGlvbkRlY2woYmFzZSwgZiwgYXJncywgaWlkKSB7XG4gICAgICAvLyBJbnZva2Ugd2l0aCB0aGUgb3JpZ2luYWwgcGFyYW1ldGVycyB0byBwcmVzZXJ2ZSBleGNlcHRpb25hbCBiZWhhdmlvciBpZiBpbnB1dCBpcyBpbnZhbGlkXG4gICAgICBmLmFwcGx5KGJhc2UsIGFyZ3MpO1xuICAgICAgLy8gT3RoZXJ3aXNlIGlucHV0IGlzIHZhbGlkLCBzbyBpbnN0cnVtZW50IGFuZCBpbnZva2UgdmlhIGV2YWxcbiAgICAgIHZhciBuZXdBcmdzID0gW107XG4gICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGFyZ3MubGVuZ3RoLTE7IGkrKykge1xuICAgICAgICAgIG5ld0FyZ3NbaV0gPSBhcmdzW2ldO1xuICAgICAgfVxuICAgICAgdmFyIGNvZGUgPSAnKGZ1bmN0aW9uKCcgKyBuZXdBcmdzLmpvaW4oJywgJykgKyAnKSB7ICcgKyBhcmdzW2FyZ3MubGVuZ3RoLTFdICsgJyB9KSc7XG4gICAgICB2YXIgY29kZSA9IHNhbmRib3guaW5zdHJ1bWVudEV2YWxDb2RlKGNvZGUsIGlpZCwgZmFsc2UpO1xuICAgICAgLy8gVXNpbmcgRVZBTF9PUkcgaW5zdGVhZCBvZiBldmFsKCkgaXMgaW1wb3J0YW50IGFzIGl0IHByZXNlcnZlcyB0aGUgc2NvcGluZyBzZW1hbnRpY3Mgb2YgRnVuY3Rpb24oKVxuICAgICAgdmFyIG91dCA9IEVWQUxfT1JHKGNvZGUpO1xuICAgICAgcmV0dXJuIG91dDtcbiAgfVxuXG4gIGZ1bmN0aW9uIGNhbGxGdW4oZiwgYmFzZSwgYXJncywgaXNDb25zdHJ1Y3RvciwgaWlkKSB7XG4gICAgICB2YXIgcmVzdWx0O1xuICAgICAgcHVzaFN3aXRjaEtleSgpO1xuICAgICAgdHJ5IHtcbiAgICAgICAgICBpZiAoZiA9PT0gRVZBTF9PUkcpIHtcbiAgICAgICAgICAgICAgcmVzdWx0ID0gaW52b2tlRXZhbChiYXNlLCBmLCBhcmdzLCBpaWQpO1xuICAgICAgICAgIH0gZWxzZSBpZiAoZiA9PT0gRnVuY3Rpb24pIHtcbiAgICAgICAgICAgICAgcmVzdWx0ID0gaW52b2tlRnVuY3Rpb25EZWNsKGJhc2UsIGYsIGFyZ3MsIGlpZCk7XG4gICAgICAgICAgfSBlbHNlIGlmIChpc0NvbnN0cnVjdG9yKSB7XG4gICAgICAgICAgICAgIHJlc3VsdCA9IGNhbGxBc0NvbnN0cnVjdG9yKGYsIGFyZ3MpO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIHJlc3VsdCA9IEZ1bmN0aW9uLnByb3RvdHlwZS5hcHBseS5jYWxsKGYsIGJhc2UsIGFyZ3MpO1xuICAgICAgICAgIH1cbiAgICAgICAgICByZXR1cm4gcmVzdWx0O1xuICAgICAgfSBmaW5hbGx5IHtcbiAgICAgICAgICBwb3BTd2l0Y2hLZXkoKTtcbiAgICAgIH1cbiAgfVxuXG4gIGZ1bmN0aW9uIGludm9rZUZ1bihpaWQsIGJhc2UsIGYsIGFyZ3MsIGlzQ29uc3RydWN0b3IsIGlzTWV0aG9kKSB7XG4gICAgICB2YXIgYXJldCwgc2tpcCA9IGZhbHNlLCByZXN1bHQ7XG5cbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuaW52b2tlRnVuUHJlKSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuaW52b2tlRnVuUHJlKGlpZCwgZiwgYmFzZSwgYXJncywgaXNDb25zdHJ1Y3RvciwgaXNNZXRob2QsIGdldFByb3BTYWZlKGYsIFNQRUNJQUxfUFJPUF9JSUQpLCBnZXRQcm9wU2FmZShmLCBTUEVDSUFMX1BST1BfU0lEKSk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgZiA9IGFyZXQuZjtcbiAgICAgICAgICAgICAgYmFzZSA9IGFyZXQuYmFzZTtcbiAgICAgICAgICAgICAgYXJncyA9IGFyZXQuYXJncztcbiAgICAgICAgICAgICAgc2tpcCA9IGFyZXQuc2tpcDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICBpZiAoIXNraXApIHtcbiAgICAgICAgICByZXN1bHQgPSBjYWxsRnVuKGYsIGJhc2UsIGFyZ3MsIGlzQ29uc3RydWN0b3IsIGlpZCk7XG4gICAgICB9XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLmludm9rZUZ1bikge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLmludm9rZUZ1bihpaWQsIGYsIGJhc2UsIGFyZ3MsIHJlc3VsdCwgaXNDb25zdHJ1Y3RvciwgaXNNZXRob2QsIGdldFByb3BTYWZlKGYsIFNQRUNJQUxfUFJPUF9JSUQpLCBnZXRQcm9wU2FmZShmLCBTUEVDSUFMX1BST1BfU0lEKSk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgcmVzdWx0ID0gYXJldC5yZXN1bHQ7XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIHJlc3VsdDtcbiAgfVxuXG4gIC8vIEZ1bmN0aW9uIGNhbGwgKGUuZy4sIGYoKSlcbiAgZnVuY3Rpb24gRihpaWQsIGYsIGZsYWdzKSB7XG4gICAgICB2YXIgYkZsYWdzID0gZGVjb2RlQml0UGF0dGVybihmbGFncywgMSk7IC8vIFtpc0NvbnN0cnVjdG9yXVxuICAgICAgcmV0dXJuIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICB2YXIgYmFzZSA9IHRoaXM7XG4gICAgICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IGludm9rZUZ1bihpaWQsIGJhc2UsIGYsIGFyZ3VtZW50cywgYkZsYWdzWzBdLCBmYWxzZSkpO1xuICAgICAgfVxuICB9XG5cbiAgLy8gTWV0aG9kIGNhbGwgKGUuZy4sIGUuZigpKVxuICBmdW5jdGlvbiBNKGlpZCwgYmFzZSwgb2Zmc2V0LCBmbGFncykge1xuICAgICAgdmFyIGJGbGFncyA9IGRlY29kZUJpdFBhdHRlcm4oZmxhZ3MsIDIpOyAvLyBbaXNDb25zdHJ1Y3RvciwgaXNDb21wdXRlZF1cbiAgICAgIHZhciBmID0gRyhpaWQgKyAyLCBiYXNlLCBvZmZzZXQsIGNyZWF0ZUJpdFBhdHRlcm4oYkZsYWdzWzFdLCBmYWxzZSwgdHJ1ZSkpO1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uICgpIHtcbiAgICAgICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gaW52b2tlRnVuKGlpZCwgYmFzZSwgZiwgYXJndW1lbnRzLCBiRmxhZ3NbMF0sIHRydWUpKTtcbiAgICAgIH07XG4gIH1cblxuICAvLyBJZ25vcmUgYXJndW1lbnQgKGlkZW50aXR5KS5cbiAgZnVuY3Rpb24gSSh2YWwpIHtcbiAgICAgIHJldHVybiB2YWw7XG4gIH1cblxuICB2YXIgaGFzR2V0T3duUHJvcGVydHlEZXNjcmlwdG9yID0gdHlwZW9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IgPT09ICdmdW5jdGlvbic7XG4gIC8vIG9iamVjdC9mdW5jdGlvbi9yZWdleHAvYXJyYXkgTGl0ZXJhbFxuICBmdW5jdGlvbiBUKGlpZCwgdmFsLCB0eXBlLCBoYXNHZXR0ZXJTZXR0ZXIsIGludGVybmFsSWlkKSB7XG4gICAgICB2YXIgYXJldDtcbiAgICAgIGFzc29jaWF0ZVNpZFdpdGhGdW5jdGlvbih2YWwsIGludGVybmFsSWlkKTtcbiAgICAgIGlmIChoYXNHZXR0ZXJTZXR0ZXIpIHtcbiAgICAgICAgICBmb3IgKHZhciBvZmZzZXQgaW4gdmFsKSB7XG4gICAgICAgICAgICAgIGlmIChoYXNHZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IgJiYgdmFsLmhhc093blByb3BlcnR5KG9mZnNldCkpIHtcbiAgICAgICAgICAgICAgICAgIHZhciBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcih2YWwsIG9mZnNldCk7XG4gICAgICAgICAgICAgICAgICBpZiAoZGVzYyAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgICAgICAgaWYgKHR5cGVvZiBkZXNjLmdldCA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgICAgICAgICAgICAgICBUKGlpZCwgZGVzYy5nZXQsIDEyLCBmYWxzZSwgaW50ZXJuYWxJaWQpO1xuICAgICAgICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGRlc2Muc2V0ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIFQoaWlkLCBkZXNjLnNldCwgMTIsIGZhbHNlLCBpbnRlcm5hbElpZCk7XG4gICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5saXRlcmFsKSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMubGl0ZXJhbChpaWQsIHZhbCwgaGFzR2V0dGVyU2V0dGVyKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICB2YWwgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gdmFsKTtcbiAgfVxuXG4gIC8vIHdyYXAgb2JqZWN0IG8gaW4gZm9yICh4IGluIG8pIHsgLi4uIH1cbiAgZnVuY3Rpb24gSChpaWQsIHZhbCkge1xuICAgICAgdmFyIGFyZXQ7XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLmZvcmluT2JqZWN0KSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuZm9yaW5PYmplY3QoaWlkLCB2YWwpO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiB2YWw7XG4gIH1cblxuICAvLyB2YXJpYWJsZSBkZWNsYXJhdGlvbiAoSW5pdClcbiAgZnVuY3Rpb24gTihpaWQsIG5hbWUsIHZhbCwgZmxhZ3MpIHtcbiAgICAgIHZhciBiRmxhZ3MgPSBkZWNvZGVCaXRQYXR0ZXJuKGZsYWdzLCAzKTsgLy8gW2lzQXJndW1lbnQsIGlzTG9jYWxTeW5jLCBpc0NhdGNoUGFyYW1dXG4gICAgICAvLyBpc0xvY2FsU3luYyBpcyBvbmx5IHRydWUgd2hlbiB3ZSBzeW5jIHZhcmlhYmxlcyBpbnNpZGUgYSBmb3ItaW4gbG9vcFxuICAgICAgdmFyIGFyZXQ7XG5cbiAgICAgIGlmIChiRmxhZ3NbMF0pIHtcbiAgICAgICAgICBhcmdJbmRleCsrO1xuICAgICAgfVxuICAgICAgaWYgKCFiRmxhZ3NbMV0gJiYgc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLmRlY2xhcmUpIHtcbiAgICAgICAgICBpZiAoYkZsYWdzWzBdICYmIGFyZ0luZGV4ID4gMSkge1xuICAgICAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5kZWNsYXJlKGlpZCwgbmFtZSwgdmFsLCBiRmxhZ3NbMF0sIGFyZ0luZGV4IC0gMiwgYkZsYWdzWzJdKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5kZWNsYXJlKGlpZCwgbmFtZSwgdmFsLCBiRmxhZ3NbMF0sIC0xLCBiRmxhZ3NbMl0pO1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICB2YWwgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gdmFsO1xuICB9XG5cbiAgLy8gZ2V0RmllbGQgKHByb3BlcnR5IHJlYWQpXG4gIGZ1bmN0aW9uIEcoaWlkLCBiYXNlLCBvZmZzZXQsIGZsYWdzKSB7XG4gICAgICB2YXIgYkZsYWdzID0gZGVjb2RlQml0UGF0dGVybihmbGFncywgMyk7IC8vIFtpc0NvbXB1dGVkLCBpc09wQXNzaWduLCBpc01ldGhvZENhbGxdXG5cbiAgICAgIHZhciBhcmV0LCBza2lwID0gZmFsc2UsIHZhbDtcblxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5nZXRGaWVsZFByZSkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLmdldEZpZWxkUHJlKGlpZCwgYmFzZSwgb2Zmc2V0LCBiRmxhZ3NbMF0sIGJGbGFnc1sxXSwgYkZsYWdzWzJdKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICBiYXNlID0gYXJldC5iYXNlO1xuICAgICAgICAgICAgICBvZmZzZXQgPSBhcmV0Lm9mZnNldDtcbiAgICAgICAgICAgICAgc2tpcCA9IGFyZXQuc2tpcDtcbiAgICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmICghc2tpcCkge1xuICAgICAgICAgIHZhbCA9IGJhc2Vbb2Zmc2V0XTtcbiAgICAgIH1cbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuZ2V0RmllbGQpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5nZXRGaWVsZChpaWQsIGJhc2UsIG9mZnNldCwgdmFsLCBiRmxhZ3NbMF0sIGJGbGFnc1sxXSwgYkZsYWdzWzJdKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICB2YWwgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gdmFsKTtcbiAgfVxuXG4gIC8vIHB1dEZpZWxkIChwcm9wZXJ0eSB3cml0ZSlcbiAgZnVuY3Rpb24gUChpaWQsIGJhc2UsIG9mZnNldCwgdmFsLCBmbGFncykge1xuICAgICAgdmFyIGJGbGFncyA9IGRlY29kZUJpdFBhdHRlcm4oZmxhZ3MsIDIpOyAvLyBbaXNDb21wdXRlZCwgaXNPcEFzc2lnbl1cblxuICAgICAgdmFyIGFyZXQsIHNraXAgPSBmYWxzZTtcblxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5wdXRGaWVsZFByZSkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLnB1dEZpZWxkUHJlKGlpZCwgYmFzZSwgb2Zmc2V0LCB2YWwsIGJGbGFnc1swXSwgISFiRmxhZ3NbMV0pO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIGJhc2UgPSBhcmV0LmJhc2U7XG4gICAgICAgICAgICAgIG9mZnNldCA9IGFyZXQub2Zmc2V0O1xuICAgICAgICAgICAgICB2YWwgPSBhcmV0LnZhbDtcbiAgICAgICAgICAgICAgc2tpcCA9IGFyZXQuc2tpcDtcbiAgICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmICghc2tpcCkge1xuICAgICAgICAgIGJhc2Vbb2Zmc2V0XSA9IHZhbDtcbiAgICAgIH1cbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMucHV0RmllbGQpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5wdXRGaWVsZChpaWQsIGJhc2UsIG9mZnNldCwgdmFsLCBiRmxhZ3NbMF0sICEhYkZsYWdzWzFdKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICB2YWwgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gdmFsKTtcbiAgfVxuXG4gIC8vIHZhcmlhYmxlIHdyaXRlXG4gIC8vIGlzR2xvYmFsIG1lYW5zIHRoYXQgdGhlIHZhcmlhYmxlIGlzIGdsb2JhbCBhbmQgbm90IGRlY2xhcmVkIGFzIHZhclxuICAvLyBpc1NjcmlwdExvY2FsIG1lYW5zIHRoYXQgdGhlIHZhcmlhYmxlIGlzIGdsb2JhbCBhbmQgaXMgZGVjbGFyZWQgYXMgdmFyXG4gIGZ1bmN0aW9uIFIoaWlkLCBuYW1lLCB2YWwsIGZsYWdzKSB7XG4gICAgICB2YXIgYXJldDtcbiAgICAgIHZhciBiRmxhZ3MgPSBkZWNvZGVCaXRQYXR0ZXJuKGZsYWdzLCAyKTsgLy8gW2lzR2xvYmFsLCBpc1NjcmlwdExvY2FsXVxuXG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLnJlYWQpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5yZWFkKGlpZCwgbmFtZSwgdmFsLCBiRmxhZ3NbMF0sIGJGbGFnc1sxXSk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgdmFsID0gYXJldC5yZXN1bHQ7XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IHZhbCk7XG4gIH1cblxuICAvLyB2YXJpYWJsZSB3cml0ZVxuICBmdW5jdGlvbiBXKGlpZCwgbmFtZSwgdmFsLCBsaHMsIGZsYWdzKSB7XG4gICAgICB2YXIgYkZsYWdzID0gZGVjb2RlQml0UGF0dGVybihmbGFncywgMyk7IC8vW2lzR2xvYmFsLCBpc1NjcmlwdExvY2FsLCBpc0RlY2xhcmF0aW9uXVxuICAgICAgdmFyIGFyZXQ7XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLndyaXRlKSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMud3JpdGUoaWlkLCBuYW1lLCB2YWwsIGxocywgYkZsYWdzWzBdLCBiRmxhZ3NbMV0pO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmICghYkZsYWdzWzJdKSB7XG4gICAgICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IHZhbCk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAgIGxhc3RDb21wdXRlZFZhbHVlID0gdW5kZWZpbmVkO1xuICAgICAgICAgIHJldHVybiB2YWw7XG4gICAgICB9XG4gIH1cblxuICAvLyB3aXRoIHN0YXRlbWVudFxuICBmdW5jdGlvbiBXaShpaWQsIHZhbCkge1xuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5fd2l0aCkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLl93aXRoKGlpZCwgdmFsKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICB2YWwgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gdmFsO1xuICB9XG5cbiAgLy8gVW5jYXVnaHQgZXhjZXB0aW9uXG4gIGZ1bmN0aW9uIEV4KGlpZCwgZSkge1xuICAgICAgd3JhcHBlZEV4Y2VwdGlvblZhbCA9IHtleGNlcHRpb246ZX07XG4gIH1cblxuICAvLyBUaHJvdyBzdGF0ZW1lbnRcbiAgZnVuY3Rpb24gVGgoaWlkLCB2YWwpIHtcbiAgICAgIHZhciBhcmV0O1xuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5fdGhyb3cpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5fdGhyb3coaWlkLCB2YWwpO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSB2YWwpO1xuICB9XG5cbiAgLy8gUmV0dXJuIHN0YXRlbWVudFxuICBmdW5jdGlvbiBSdChpaWQsIHZhbCkge1xuICAgICAgdmFyIGFyZXQ7XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLl9yZXR1cm4pIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5fcmV0dXJuKGlpZCwgdmFsKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICB2YWwgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm5TdGFjay5wb3AoKTtcbiAgICAgIHJldHVyblN0YWNrLnB1c2godmFsKTtcbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSB2YWwpO1xuICB9XG5cbiAgLy8gQWN0dWFsIHJldHVybiBmcm9tIGZ1bmN0aW9uLCBpbnZva2VkIGZyb20gJ2ZpbmFsbHknIGJsb2NrXG4gIC8vIGFkZGVkIGFyb3VuZCBldmVyeSBmdW5jdGlvbiBieSBpbnN0cnVtZW50YXRpb24uICBSZWFkc1xuICAvLyB0aGUgcmV0dXJuIHZhbHVlIHN0b3JlZCBieSBjYWxsIHRvIFJ0KClcbiAgZnVuY3Rpb24gUmEoKSB7XG4gICAgICB2YXIgcmV0dXJuVmFsID0gcmV0dXJuU3RhY2sucG9wKCk7XG4gICAgICB3cmFwcGVkRXhjZXB0aW9uVmFsID0gdW5kZWZpbmVkO1xuICAgICAgcmV0dXJuIHJldHVyblZhbDtcbiAgfVxuXG4gIC8vIEZ1bmN0aW9uIGVudGVyXG4gIGZ1bmN0aW9uIEZlKGlpZCwgZiwgZGlzIC8qIHRoaXMgKi8sIGFyZ3MpIHtcbiAgICAgIGFyZ0luZGV4ID0gMDtcbiAgICAgIHJldHVyblN0YWNrLnB1c2godW5kZWZpbmVkKTtcbiAgICAgIHdyYXBwZWRFeGNlcHRpb25WYWwgPSB1bmRlZmluZWQ7XG4gICAgICB1cGRhdGVTaWQoZik7XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLmZ1bmN0aW9uRW50ZXIpIHtcbiAgICAgICAgICBzYW5kYm94LmFuYWx5c2lzLmZ1bmN0aW9uRW50ZXIoaWlkLCBmLCBkaXMsIGFyZ3MpO1xuICAgICAgfVxuICB9XG5cbiAgLy8gRnVuY3Rpb24gZXhpdFxuICBmdW5jdGlvbiBGcihpaWQpIHtcbiAgICAgIHZhciBpc0JhY2t0cmFjayA9IGZhbHNlLCB0bXAsIGFyZXQsIHJldHVyblZhbDtcblxuICAgICAgcmV0dXJuVmFsID0gcmV0dXJuU3RhY2sucG9wKCk7XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLmZ1bmN0aW9uRXhpdCkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLmZ1bmN0aW9uRXhpdChpaWQsIHJldHVyblZhbCwgd3JhcHBlZEV4Y2VwdGlvblZhbCk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgcmV0dXJuVmFsID0gYXJldC5yZXR1cm5WYWw7XG4gICAgICAgICAgICAgIHdyYXBwZWRFeGNlcHRpb25WYWwgPSBhcmV0LndyYXBwZWRFeGNlcHRpb25WYWw7XG4gICAgICAgICAgICAgIGlzQmFja3RyYWNrID0gYXJldC5pc0JhY2t0cmFjaztcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByb2xsQmFja1NpZCgpO1xuICAgICAgaWYgKCFpc0JhY2t0cmFjaykge1xuICAgICAgICAgIHJldHVyblN0YWNrLnB1c2gocmV0dXJuVmFsKTtcbiAgICAgIH1cbiAgICAgIC8vIGlmIHRoZXJlIHdhcyBhbiB1bmNhdWdodCBleGNlcHRpb24sIHRocm93IGl0XG4gICAgICAvLyBoZXJlLCB0byBwcmVzZXJ2ZSBleGNlcHRpb25hbCBjb250cm9sIGZsb3dcbiAgICAgIGlmICh3cmFwcGVkRXhjZXB0aW9uVmFsICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICB0bXAgPSB3cmFwcGVkRXhjZXB0aW9uVmFsLmV4Y2VwdGlvbjtcbiAgICAgICAgICB3cmFwcGVkRXhjZXB0aW9uVmFsID0gdW5kZWZpbmVkO1xuICAgICAgICAgIHRocm93IHRtcDtcbiAgICAgIH1cbiAgICAgIHJldHVybiBpc0JhY2t0cmFjaztcbiAgfVxuXG4gIC8vIFNjcmlwdCBlbnRlclxuICBmdW5jdGlvbiBTZShpaWQsIHZhbCwgb3JpZ0ZpbGVOYW1lKSB7XG4gICAgICBjcmVhdGVBbmRBc3NpZ25OZXdTaWQoKTtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuc2NyaXB0RW50ZXIpIHtcbiAgICAgICAgICBzYW5kYm94LmFuYWx5c2lzLnNjcmlwdEVudGVyKGlpZCwgdmFsLCBvcmlnRmlsZU5hbWUpO1xuICAgICAgfVxuICAgICAgbGFzdENvbXB1dGVkVmFsdWUgPSB1bmRlZmluZWQ7XG4gIH1cblxuICAvLyBTY3JpcHQgZXhpdFxuICBmdW5jdGlvbiBTcihpaWQpIHtcbiAgICAgIHZhciB0bXAsIGFyZXQsIGlzQmFja3RyYWNrO1xuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5zY3JpcHRFeGl0KSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuc2NyaXB0RXhpdChpaWQsIHdyYXBwZWRFeGNlcHRpb25WYWwpO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHdyYXBwZWRFeGNlcHRpb25WYWwgPSBhcmV0LndyYXBwZWRFeGNlcHRpb25WYWw7XG4gICAgICAgICAgICAgIGlzQmFja3RyYWNrID0gYXJldC5pc0JhY2t0cmFjaztcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByb2xsQmFja1NpZCgpO1xuICAgICAgaWYgKHdyYXBwZWRFeGNlcHRpb25WYWwgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgIHRtcCA9IHdyYXBwZWRFeGNlcHRpb25WYWwuZXhjZXB0aW9uO1xuICAgICAgICAgIHdyYXBwZWRFeGNlcHRpb25WYWwgPSB1bmRlZmluZWQ7XG4gICAgICAgICAgdGhyb3cgdG1wO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGlzQmFja3RyYWNrO1xuICB9XG5cblxuICAvLyBNb2RpZnkgYW5kIGFzc2lnbiArPSwgLT0gLi4uXG4gIGZ1bmN0aW9uIEEoaWlkLCBiYXNlLCBvZmZzZXQsIG9wLCBmbGFncykge1xuICAgICAgdmFyIGJGbGFncyA9IGRlY29kZUJpdFBhdHRlcm4oZmxhZ3MsIDEpOyAvLyBbaXNDb21wdXRlZF1cbiAgICAgIC8vIGF2b2lkIGlpZCBjb2xsaXNpb246IG1ha2Ugc3VyZSB0aGF0IGlpZCsyIGhhcyB0aGUgc2FtZSBzb3VyY2UgbWFwIGFzIGlpZCAoQHRvZG8pXG4gICAgICB2YXIgb3BybmQxID0gRyhpaWQrMiwgYmFzZSwgb2Zmc2V0LCBjcmVhdGVCaXRQYXR0ZXJuKGJGbGFnc1swXSwgdHJ1ZSwgZmFsc2UpKTtcbiAgICAgIHJldHVybiBmdW5jdGlvbiAob3BybmQyKSB7XG4gICAgICAgICAgLy8gc3RpbGwgcG9zc2libGUgdG8gZ2V0IGlpZCBjb2xsaXNpb24gd2l0aCBhIG1lbSBvcGVyYXRpb25cbiAgICAgICAgICB2YXIgdmFsID0gQihpaWQsIG9wLCBvcHJuZDEsIG9wcm5kMiwgY3JlYXRlQml0UGF0dGVybihmYWxzZSwgdHJ1ZSwgZmFsc2UpKTtcbiAgICAgICAgICByZXR1cm4gUChpaWQsIGJhc2UsIG9mZnNldCwgdmFsLCBjcmVhdGVCaXRQYXR0ZXJuKGJGbGFnc1swXSwgdHJ1ZSkpO1xuICAgICAgfTtcbiAgfVxuXG4gIC8vIEJpbmFyeSBvcGVyYXRpb25cbiAgZnVuY3Rpb24gQihpaWQsIG9wLCBsZWZ0LCByaWdodCwgZmxhZ3MpIHtcbiAgICAgIHZhciBiRmxhZ3MgPSBkZWNvZGVCaXRQYXR0ZXJuKGZsYWdzLCAzKTsgLy8gW2lzQ29tcHV0ZWQsIGlzT3BBc3NpZ24sIGlzU3dpdGNoQ2FzZUNvbXBhcmlzb25dXG4gICAgICB2YXIgcmVzdWx0LCBhcmV0LCBza2lwID0gZmFsc2U7XG5cbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuYmluYXJ5UHJlKSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuYmluYXJ5UHJlKGlpZCwgb3AsIGxlZnQsIHJpZ2h0LCBiRmxhZ3NbMV0sIGJGbGFnc1syXSwgYkZsYWdzWzBdKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICBvcCA9IGFyZXQub3A7XG4gICAgICAgICAgICAgIGxlZnQgPSBhcmV0LmxlZnQ7XG4gICAgICAgICAgICAgIHJpZ2h0ID0gYXJldC5yaWdodDtcbiAgICAgICAgICAgICAgc2tpcCA9IGFyZXQuc2tpcDtcbiAgICAgICAgICB9XG4gICAgICB9XG5cblxuICAgICAgaWYgKCFza2lwKSB7XG4gICAgICAgICAgc3dpdGNoIChvcCkge1xuICAgICAgICAgICAgICBjYXNlIFwiK1wiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCArIHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCItXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0IC0gcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIipcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgKiByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiL1wiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCAvIHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCIlXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0ICUgcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIjw8XCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0IDw8IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCI+PlwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCA+PiByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiPj4+XCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0ID4+PiByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiPFwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCA8IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCI+XCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0ID4gcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIjw9XCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0IDw9IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCI+PVwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCA+PSByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiPT1cIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgPT0gcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIiE9XCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0ICE9IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCI9PT1cIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgPT09IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCIhPT1cIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgIT09IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCImXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0ICYgcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcInxcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgfCByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiXlwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCBeIHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCJkZWxldGVcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGRlbGV0ZSBsZWZ0W3JpZ2h0XTtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiaW5zdGFuY2VvZlwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCBpbnN0YW5jZW9mIHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCJpblwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCBpbiByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBkZWZhdWx0OlxuICAgICAgICAgICAgICAgICAgdGhyb3cgbmV3IEVycm9yKG9wICsgXCIgYXQgXCIgKyBpaWQgKyBcIiBub3QgZm91bmRcIik7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuYmluYXJ5KSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuYmluYXJ5KGlpZCwgb3AsIGxlZnQsIHJpZ2h0LCByZXN1bHQsIGJGbGFnc1sxXSwgYkZsYWdzWzJdLCBiRmxhZ3NbMF0pO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHJlc3VsdCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSByZXN1bHQpO1xuICB9XG5cblxuICAvLyBVbmFyeSBvcGVyYXRpb25cbiAgZnVuY3Rpb24gVShpaWQsIG9wLCBsZWZ0KSB7XG4gICAgICB2YXIgcmVzdWx0LCBhcmV0LCBza2lwID0gZmFsc2U7XG5cbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMudW5hcnlQcmUpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy51bmFyeVByZShpaWQsIG9wLCBsZWZ0KTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICBvcCA9IGFyZXQub3A7XG4gICAgICAgICAgICAgIGxlZnQgPSBhcmV0LmxlZnQ7XG4gICAgICAgICAgICAgIHNraXAgPSBhcmV0LnNraXBcbiAgICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGlmICghc2tpcCkge1xuICAgICAgICAgIHN3aXRjaCAob3ApIHtcbiAgICAgICAgICAgICAgY2FzZSBcIitcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9ICtsZWZ0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCItXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSAtbGVmdDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiflwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gfmxlZnQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIiFcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9ICFsZWZ0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCJ0eXBlb2ZcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IHR5cGVvZiBsZWZ0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCJ2b2lkXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSB2b2lkKGxlZnQpO1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3Iob3AgKyBcIiBhdCBcIiArIGlpZCArIFwiIG5vdCBmb3VuZFwiKTtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy51bmFyeSkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLnVuYXJ5KGlpZCwgb3AsIGxlZnQsIHJlc3VsdCk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgcmVzdWx0ID0gYXJldC5yZXN1bHQ7XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IHJlc3VsdCk7XG4gIH1cblxuICBmdW5jdGlvbiBwdXNoU3dpdGNoS2V5KCkge1xuICAgICAgc3dpdGNoS2V5U3RhY2sucHVzaChzd2l0Y2hMZWZ0KTtcbiAgfVxuXG4gIGZ1bmN0aW9uIHBvcFN3aXRjaEtleSgpIHtcbiAgICAgIHN3aXRjaExlZnQgPSBzd2l0Y2hLZXlTdGFjay5wb3AoKTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGxhc3QoKSB7XG4gICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gbGFzdFZhbCk7XG4gIH1cblxuICAvLyBTd2l0Y2gga2V5XG4gIC8vIEUuZy4sIGZvciAnc3dpdGNoICh4KSB7IC4uLiB9JyxcbiAgLy8gQzEgaXMgaW52b2tlZCB3aXRoIHZhbHVlIG9mIHhcbiAgZnVuY3Rpb24gQzEoaWlkLCBsZWZ0KSB7XG4gICAgICBzd2l0Y2hMZWZ0ID0gbGVmdDtcbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSBsZWZ0KTtcbiAgfVxuXG4gIC8vIGNhc2UgbGFiZWwgaW5zaWRlIHN3aXRjaFxuICBmdW5jdGlvbiBDMihpaWQsIHJpZ2h0KSB7XG4gICAgICB2YXIgYXJldCwgcmVzdWx0O1xuXG4gICAgICAvLyBhdm9pZCBpaWQgY29sbGlzaW9uOyBpaWQgbWF5IG5vdCBoYXZlIGEgbWFwIGluIHRoZSBzb3VyY2VtYXBcbiAgICAgIHJlc3VsdCA9IEIoaWlkKzEsIFwiPT09XCIsIHN3aXRjaExlZnQsIHJpZ2h0LCBjcmVhdGVCaXRQYXR0ZXJuKGZhbHNlLCBmYWxzZSwgdHJ1ZSkpO1xuXG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLmNvbmRpdGlvbmFsKSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuY29uZGl0aW9uYWwoaWlkLCByZXN1bHQpO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIGlmIChyZXN1bHQgJiYgIWFyZXQucmVzdWx0KSB7XG4gICAgICAgICAgICAgICAgICByaWdodCA9ICFyaWdodDtcbiAgICAgICAgICAgICAgfSBlbHNlIGlmIChyZXN1bHQgJiYgYXJldC5yZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgIHJpZ2h0ID0gc3dpdGNoTGVmdDtcbiAgICAgICAgICAgICAgfVxuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSByaWdodCk7XG4gIH1cblxuICAvLyBFeHByZXNzaW9uIGluIGNvbmRpdGlvbmFsXG4gIGZ1bmN0aW9uIEMoaWlkLCBsZWZ0KSB7XG4gICAgICB2YXIgYXJldDtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuY29uZGl0aW9uYWwpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5jb25kaXRpb25hbChpaWQsIGxlZnQpO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIGxlZnQgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG5cbiAgICAgIGxhc3RWYWwgPSBsZWZ0O1xuICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IGxlZnQpO1xuICB9XG5cbiAgZnVuY3Rpb24gUyhpaWQsIGYpIHtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMucnVuSW5zdHJ1bWVudGVkRnVuY3Rpb25Cb2R5KSB7XG4gICAgICAgICAgcmV0dXJuIHNhbmRib3guYW5hbHlzaXMucnVuSW5zdHJ1bWVudGVkRnVuY3Rpb25Cb2R5KGlpZCwgZiwgZ2V0UHJvcFNhZmUoZiwgU1BFQ0lBTF9QUk9QX0lJRCksIGdldFByb3BTYWZlKGYsIFNQRUNJQUxfUFJPUF9TSUQpKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiB0cnVlO1xuICB9XG5cbiAgZnVuY3Rpb24gTCgpIHtcbiAgICAgIHJldHVybiBsYXN0Q29tcHV0ZWRWYWx1ZTtcbiAgfVxuXG5cbiAgZnVuY3Rpb24gWDEoaWlkLCB2YWwpIHtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuZW5kRXhwcmVzc2lvbikge1xuICAgICAgICAgIHNhbmRib3guYW5hbHlzaXMuZW5kRXhwcmVzc2lvbihpaWQpO1xuICAgICAgfVxuXG4gICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gdmFsKTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGVuZEV4ZWN1dGlvbigpIHtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuZW5kRXhlY3V0aW9uKSB7XG4gICAgICAgICAgcmV0dXJuIHNhbmRib3guYW5hbHlzaXMuZW5kRXhlY3V0aW9uKCk7XG4gICAgICB9XG4gIH1cblxuXG4gIGZ1bmN0aW9uIGxvZyhzdHIpIHtcbiAgICAgIGlmIChzYW5kYm94LlJlc3VsdHMgJiYgc2FuZGJveC5SZXN1bHRzLmV4ZWN1dGUpIHtcbiAgICAgICAgICBzYW5kYm94LlJlc3VsdHMuZXhlY3V0ZShmdW5jdGlvbihkaXYsIGpxdWVyeSwgZWRpdG9yKXtcbiAgICAgICAgICAgICAgZGl2LmFwcGVuZChzdHIrXCI8YnI+XCIpO1xuICAgICAgICAgIH0pO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgICBjb25zb2xlLmxvZyhzdHIpO1xuICAgICAgfVxuICB9XG5cblxuICAvLy0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tIEVuZCBKYWxhbmdpIExpYnJhcnkgYmFja2VuZCAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICBzYW5kYm94LlUgPSBVOyAvLyBVbmFyeSBvcGVyYXRpb25cbiAgc2FuZGJveC5CID0gQjsgLy8gQmluYXJ5IG9wZXJhdGlvblxuICBzYW5kYm94LkMgPSBDOyAvLyBDb25kaXRpb25cbiAgc2FuZGJveC5DMSA9IEMxOyAvLyBTd2l0Y2gga2V5XG4gIHNhbmRib3guQzIgPSBDMjsgLy8gY2FzZSBsYWJlbCBDMSA9PT0gQzJcbiAgc2FuZGJveC5fID0gbGFzdDsgIC8vIExhc3QgdmFsdWUgcGFzc2VkIHRvIENcblxuICBzYW5kYm94LkggPSBIOyAvLyBoYXNoIGluIGZvci1pblxuICBzYW5kYm94LkkgPSBJOyAvLyBJZ25vcmUgYXJndW1lbnRcbiAgc2FuZGJveC5HID0gRzsgLy8gZ2V0RmllbGRcbiAgc2FuZGJveC5QID0gUDsgLy8gcHV0RmllbGRcbiAgc2FuZGJveC5SID0gUjsgLy8gUmVhZFxuICBzYW5kYm94LlcgPSBXOyAvLyBXcml0ZVxuICBzYW5kYm94Lk4gPSBOOyAvLyBJbml0XG4gIHNhbmRib3guVCA9IFQ7IC8vIG9iamVjdC9mdW5jdGlvbi9yZWdleHAvYXJyYXkgTGl0ZXJhbFxuICBzYW5kYm94LkYgPSBGOyAvLyBGdW5jdGlvbiBjYWxsXG4gIHNhbmRib3guTSA9IE07IC8vIE1ldGhvZCBjYWxsXG4gIHNhbmRib3guQSA9IEE7IC8vIE1vZGlmeSBhbmQgYXNzaWduICs9LCAtPSAuLi5cbiAgc2FuZGJveC5GZSA9IEZlOyAvLyBGdW5jdGlvbiBlbnRlclxuICBzYW5kYm94LkZyID0gRnI7IC8vIEZ1bmN0aW9uIHJldHVyblxuICBzYW5kYm94LlNlID0gU2U7IC8vIFNjcmlwdCBlbnRlclxuICBzYW5kYm94LlNyID0gU3I7IC8vIFNjcmlwdCByZXR1cm5cbiAgc2FuZGJveC5SdCA9IFJ0OyAvLyByZXR1cm5lZCB2YWx1ZVxuICBzYW5kYm94LlRoID0gVGg7IC8vIHRocm93biB2YWx1ZVxuICBzYW5kYm94LlJhID0gUmE7XG4gIHNhbmRib3guRXggPSBFeDtcbiAgc2FuZGJveC5MID0gTDtcbiAgc2FuZGJveC5YMSA9IFgxOyAvLyB0b3AgbGV2ZWwgZXhwcmVzc2lvblxuICBzYW5kYm94LldpID0gV2k7IC8vIHdpdGggc3RhdGVtZW50XG4gIHNhbmRib3guZW5kRXhlY3V0aW9uID0gZW5kRXhlY3V0aW9uO1xuXG4gIHNhbmRib3guUyA9IFM7XG5cbiAgc2FuZGJveC5FVkFMX09SRyA9IEVWQUxfT1JHO1xuICBzYW5kYm94LmxvZyA9IGxvZztcbn0pKEokJCk7XG5cbiIsIi8vIFRoZSBtb2R1bGUgY2FjaGVcbnZhciBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX18gPSB7fTtcblxuLy8gVGhlIHJlcXVpcmUgZnVuY3Rpb25cbmZ1bmN0aW9uIF9fd2VicGFja19yZXF1aXJlX18obW9kdWxlSWQpIHtcblx0Ly8gQ2hlY2sgaWYgbW9kdWxlIGlzIGluIGNhY2hlXG5cdHZhciBjYWNoZWRNb2R1bGUgPSBfX3dlYnBhY2tfbW9kdWxlX2NhY2hlX19bbW9kdWxlSWRdO1xuXHRpZiAoY2FjaGVkTW9kdWxlICE9PSB1bmRlZmluZWQpIHtcblx0XHRyZXR1cm4gY2FjaGVkTW9kdWxlLmV4cG9ydHM7XG5cdH1cblx0Ly8gQ3JlYXRlIGEgbmV3IG1vZHVsZSAoYW5kIHB1dCBpdCBpbnRvIHRoZSBjYWNoZSlcblx0dmFyIG1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF0gPSB7XG5cdFx0Ly8gbm8gbW9kdWxlLmlkIG5lZWRlZFxuXHRcdC8vIG5vIG1vZHVsZS5sb2FkZWQgbmVlZGVkXG5cdFx0ZXhwb3J0czoge31cblx0fTtcblxuXHQvLyBFeGVjdXRlIHRoZSBtb2R1bGUgZnVuY3Rpb25cblx0X193ZWJwYWNrX21vZHVsZXNfX1ttb2R1bGVJZF0obW9kdWxlLCBtb2R1bGUuZXhwb3J0cywgX193ZWJwYWNrX3JlcXVpcmVfXyk7XG5cblx0Ly8gUmV0dXJuIHRoZSBleHBvcnRzIG9mIHRoZSBtb2R1bGVcblx0cmV0dXJuIG1vZHVsZS5leHBvcnRzO1xufVxuXG4iLCJyZXF1aXJlKCcuL2NvbmZpZy5qcycpO1xucmVxdWlyZSgnLi9jb25zdGFudHMuanMnKTtcbnJlcXVpcmUoJy4vcnVudGltZS5qcycpO1xucmVxdWlyZSgnLi9paWRUb0xvY2F0aW9uLmpzJyk7XG4vLyByZXF1aXJlKCcuL2FzdFV0aWwuanMnKTtcbi8vIHJlcXVpcmUoJy4vZXNuc3RydW1lbnQuanMnKTsiXSwibmFtZXMiOltdLCJzb3VyY2VSb290IjoiIn0=