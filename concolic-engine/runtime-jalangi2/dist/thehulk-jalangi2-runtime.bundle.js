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
// If we use commmonJS with require, the webpack will not recongnize the source map?
__webpack_require__(/*! ./config.js */ "./src/config.js");
__webpack_require__(/*! ./constants.js */ "./src/constants.js");
__webpack_require__(/*! ./runtime.js */ "./src/runtime.js");
__webpack_require__(/*! ./iidToLocation.js */ "./src/iidToLocation.js");
// require('./astUtil.js');
// require('./esnstrument.js');

// import './config.js';
// import './constants.js';
// import './runtime.js';
// import './iidToLocation.js';
})();

/******/ })()
;
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoidGhlaHVsay1qYWxhbmdpMi1ydW50aW1lLmJ1bmRsZS5qcyIsIm1hcHBpbmdzIjoiOzs7Ozs7Ozs7QUFBQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLGdEQUFnRDtBQUNoRCxnREFBZ0Q7QUFDaEQsaURBQWlEO0FBQ2pELHNEQUFzRCxnQkFBZ0I7QUFDdEUsc0RBQXNELGdCQUFnQjtBQUN0RSxzREFBc0Q7QUFDdEQsa0ZBQWtGLGdCQUFnQjtBQUNsRyxxREFBcUQ7QUFDckQsc0RBQXNELGVBQWU7QUFDckUsdURBQXVELGdCQUFnQjtBQUN2RSx3REFBd0QsaUJBQWlCO0FBQ3pFLG1EQUFtRCxnQkFBZ0I7QUFDbkUsQ0FBQzs7Ozs7Ozs7Ozs7QUN0REQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBLDRCQUE0QixLQUE4Qjs7QUFFMUQ7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7OztBQUdBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBOztBQUVBOztBQUVBOztBQUVBO0FBQ0Esc0ZBQXNGO0FBQ3RGOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsY0FBYztBQUNkO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQSxDQUFDOzs7Ozs7Ozs7Ozs7QUNwR0Q7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVk7QUFDWjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHVGQUF1RjtBQUN2RixvQkFBb0I7QUFDcEI7QUFDQTtBQUNBLGdCQUFnQjtBQUNoQjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBLENBQUM7Ozs7Ozs7Ozs7O0FDOUREO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTs7QUFFQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0Esb0JBQW9CLE9BQU87QUFDM0I7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBLGlCQUFpQixxQkFBcUI7QUFDdEM7QUFDQTtBQUNBO0FBQ0E7OztBQUdBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsZUFBZTtBQUNmO0FBQ0E7QUFDQTtBQUNBLGVBQWU7QUFDZjtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EseUJBQXlCLGlCQUFpQjtBQUMxQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0Esc0NBQXNDLGlEQUFpRCxFQUFFO0FBQ3pGO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLFVBQVUsSUFBSTtBQUNkO0FBQ0E7QUFDQSxRQUFRLEtBQUssbUJBT047QUFDUDs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLHNCQUFzQixtQkFBbUI7QUFDekM7QUFDQTtBQUNBLDBEQUEwRCw2QkFBNkI7QUFDdkY7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxZQUFZO0FBQ1o7QUFDQSxZQUFZO0FBQ1o7QUFDQSxZQUFZO0FBQ1o7QUFDQTtBQUNBO0FBQ0EsUUFBUTtBQUNSO0FBQ0E7QUFDQTs7QUFFQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLCtDQUErQztBQUMvQztBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSwrQ0FBK0M7QUFDL0M7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQSxxQ0FBcUM7QUFDckM7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBLCtDQUErQztBQUMvQztBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFlBQVk7QUFDWjtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSwrQ0FBK0M7O0FBRS9DOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0EsK0NBQStDOztBQUUvQzs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsK0NBQStDOztBQUUvQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSwrQ0FBK0M7QUFDL0M7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EsUUFBUTtBQUNSO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSw2QkFBNkI7QUFDN0I7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FBR0E7QUFDQTtBQUNBLCtDQUErQztBQUMvQztBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQSwrQ0FBK0M7QUFDL0M7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBOztBQUVBO0FBQ0EsNkJBQTZCLEtBQUs7QUFDbEM7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUEsOEJBQThCO0FBQzlCOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQSxnQkFBZ0I7QUFDaEI7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOztBQUVBO0FBQ0E7QUFDQTs7O0FBR0E7QUFDQTtBQUNBO0FBQ0E7O0FBRUE7QUFDQTs7QUFFQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUFHQTtBQUNBO0FBQ0E7QUFDQTtBQUNBLFdBQVc7QUFDWCxRQUFRO0FBQ1I7QUFDQTtBQUNBOzs7QUFHQTs7QUFFQSxpQkFBaUI7QUFDakIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixtQkFBbUI7QUFDbkIsbUJBQW1CO0FBQ25CLHFCQUFxQjs7QUFFckIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixpQkFBaUI7QUFDakIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixpQkFBaUI7QUFDakIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixpQkFBaUI7QUFDakIsaUJBQWlCO0FBQ2pCLGlCQUFpQjtBQUNqQixtQkFBbUI7QUFDbkIsbUJBQW1CO0FBQ25CLG1CQUFtQjtBQUNuQixtQkFBbUI7QUFDbkIsbUJBQW1CO0FBQ25CLG1CQUFtQjtBQUNuQjtBQUNBO0FBQ0E7QUFDQSxtQkFBbUI7QUFDbkIsbUJBQW1CO0FBQ25COztBQUVBOztBQUVBO0FBQ0E7QUFDQSxDQUFDOzs7Ozs7OztVQ2p6QkQ7VUFDQTs7VUFFQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTtVQUNBO1VBQ0E7VUFDQTs7VUFFQTtVQUNBOztVQUVBO1VBQ0E7VUFDQTs7Ozs7Ozs7O0FDdEJBO0FBQ0EsbUJBQU8sQ0FBQyxvQ0FBYTtBQUNyQixtQkFBTyxDQUFDLDBDQUFnQjtBQUN4QixtQkFBTyxDQUFDLHNDQUFjO0FBQ3RCLG1CQUFPLENBQUMsa0RBQW9CO0FBQzVCO0FBQ0E7O0FBRUE7QUFDQTtBQUNBO0FBQ0EsK0IiLCJzb3VyY2VzIjpbIndlYnBhY2s6Ly9qYWxhbmdpMi1ydW50aW1lLy4vc3JjL2NvbmZpZy5qcyIsIndlYnBhY2s6Ly9qYWxhbmdpMi1ydW50aW1lLy4vc3JjL2NvbnN0YW50cy5qcyIsIndlYnBhY2s6Ly9qYWxhbmdpMi1ydW50aW1lLy4vc3JjL2lpZFRvTG9jYXRpb24uanMiLCJ3ZWJwYWNrOi8vamFsYW5naTItcnVudGltZS8uL3NyYy9ydW50aW1lLmpzIiwid2VicGFjazovL2phbGFuZ2kyLXJ1bnRpbWUvd2VicGFjay9ib290c3RyYXAiLCJ3ZWJwYWNrOi8vamFsYW5naTItcnVudGltZS8uL3NyYy9lbnRyeS5qcyJdLCJzb3VyY2VzQ29udGVudCI6WyIvKlxuICogQ29weXJpZ2h0IChjKSAyMDE0IFNhbXN1bmcgRWxlY3Ryb25pY3MgQ28uLCBMdGQuXG4gKlxuICogTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbiAqIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbiAqIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuICpcbiAqICAgICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbiAqXG4gKiBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4gKiBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4gKiBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbiAqIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbiAqIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxuICovXG4vLyBkbyBub3QgcmVtb3ZlIHRoZSBmb2xsb3dpbmcgY29tbWVudFxuLy8gSkFMQU5HSSBETyBOT1QgSU5TVFJVTUVOVFxuaWYgKHR5cGVvZiBKJCQgPT09ICd1bmRlZmluZWQnKSB7XG4gICAgSiQkID0ge307XG59XG5cbihmdW5jdGlvbiAoc2FuZGJveCkge1xuICAgIGlmICh0eXBlb2Ygc2FuZGJveC5Db25maWcgIT09ICd1bmRlZmluZWQnKSB7XG4gICAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICB2YXIgQ29uZmlnID0gc2FuZGJveC5Db25maWcgPSB7fTtcblxuICAgIENvbmZpZy5ERUJVRyA9IGZhbHNlO1xuICAgIENvbmZpZy5XQVJOID0gZmFsc2U7XG4gICAgQ29uZmlnLlNFUklPVVNfV0FSTiA9IGZhbHNlO1xuLy8gbWFrZSBNQVhfQlVGX1NJWkUgc2xpZ2h0bHkgbGVzcyB0aGFuIDJeMTYsIHRvIGFsbG93IG92ZXIgbG93LWxldmVsIG92ZXJoZWFkc1xuICAgIENvbmZpZy5NQVhfQlVGX1NJWkUgPSA2NDAwMDtcbiAgICBDb25maWcuTE9HX0FMTF9SRUFEU19BTkRfQlJBTkNIRVMgPSBmYWxzZTtcblxuICAgIC8vKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuICAgIC8vICBGdW5jdGlvbnMgZm9yIHNlbGVjdGl2ZSBpbnN0cnVtZW50YXRpb24gb2Ygb3BlcmF0aW9uc1xuICAgIC8vKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKlxuICAgIC8vIEluIHRoZSBmb2xsb3dpbmcgZnVuY3Rpb25zXG4gICAgLy8gcmV0dXJuIHRydWUgaW4gYSBmdW5jdGlvbiwgaWYgeW91IHdhbnQgdGhlIGFzdCBub2RlIChwYXNzZWQgYXMgdGhlIHNlY29uZCBhcmd1bWVudCkgdG8gYmUgaW5zdHJ1bWVudGVkXG4gICAgLy8gYXN0IG5vZGUgZ2V0cyBpbnN0cnVtZW50ZWQgaWYgeW91IGRvIG5vdCBkZWZpbmUgdGhlIGNvcnJlc3BvbmRpbmcgZnVuY3Rpb25cbiAgICBDb25maWcuRU5BQkxFX1NBTVBMSU5HID0gZmFsc2U7XG4vLyAgICBDb25maWcuSU5TVFJfSU5JVCA9IGZ1bmN0aW9uKG5hbWUsIGFzdCkgeyByZXR1cm4gZmFsc2U7IH07XG4vLyAgICBDb25maWcuSU5TVFJfUkVBRCA9IGZ1bmN0aW9uKG5hbWUsIGFzdCkgeyByZXR1cm4gZmFsc2U7IH07XG4vLyAgICBDb25maWcuSU5TVFJfV1JJVEUgPSBmdW5jdGlvbihuYW1lLCBhc3QpIHsgcmV0dXJuIHRydWU7IH07XG4vLyAgICBDb25maWcuSU5TVFJfR0VURklFTEQgPSBmdW5jdGlvbihvZmZzZXQsIGFzdCkgeyByZXR1cm4gdHJ1ZTsgfTsgLy8gb2Zmc2V0IGlzIG51bGwgaWYgdGhlIHByb3BlcnR5IGlzIGNvbXB1dGVkXG4vLyAgICBDb25maWcuSU5TVFJfUFVURklFTEQgPSBmdW5jdGlvbihvZmZzZXQsIGFzdCkgeyByZXR1cm4gdHJ1ZTsgfTsgLy8gb2Zmc2V0IGlzIG51bGwgaWYgdGhlIHByb3BlcnR5IGlzIGNvbXB1dGVkXG4vLyAgICBDb25maWcuSU5TVFJfQklOQVJZID0gZnVuY3Rpb24ob3BlcmF0b3IsIGFzdCkgeyByZXR1cm4gdHJ1ZTsgfTtcbi8vICAgIENvbmZpZy5JTlNUUl9QUk9QRVJUWV9CSU5BUllfQVNTSUdOTUVOVCA9IGZ1bmN0aW9uKG9wZXJhdG9yLCBvZmZzZXQsIGFzdCkgeyByZXR1cm4gdHJ1ZTsgfTsgLy8gYS54ICs9IGUgb3IgYVtlMV0gKz0gZTJcbi8vICAgIENvbmZpZy5JTlNUUl9VTkFSWSA9IGZ1bmN0aW9uKG9wZXJhdG9yLCBhc3QpIHsgcmV0dXJuIHRydWU7IH07XG4vLyAgICBDb25maWcuSU5TVFJfTElURVJBTCA9IGZ1bmN0aW9uKGxpdGVyYWwsIGFzdCkgeyByZXR1cm4gdHJ1ZTt9OyAvLyBsaXRlcmFsIGdldHMgc29tZSBkdW1teSB2YWx1ZSBpZiB0aGUgdHlwZSBpcyBvYmplY3QsIGZ1bmN0aW9uLCBvciBhcnJheVxuLy8gICAgQ29uZmlnLklOU1RSX0NPTkRJVElPTkFMID0gZnVuY3Rpb24odHlwZSwgYXN0KSB7IHJldHVybiB0cnVlOyB9OyAvLyB0eXBlIGNvdWxkIGJlIFwiJiZcIiwgXCJ8fFwiLCBcInN3aXRjaFwiLCBcIm90aGVyXCJcbi8vICAgIENvbmZpZy5JTlNUUl9UUllfQ0FUQ0hfQVJHVU1FTlRTID0gZnVuY3Rpb24oYXN0KSB7cmV0dXJuIGZhbHNlOyB9OyAvLyB3cmFwIGZ1bmN0aW9uIGFuZCBzY3JpcHQgYm9kaWVzIHdpdGggdHJ5IGNhdGNoIGJsb2NrIGFuZCB1c2UgYXJndW1lbnRzIGluIEokLkZlLiAgRE8gTk9UIFVTRSBUSElTLlxuLy8gICAgQ29uZmlnLklOU1RSX0VORF9FWFBSRVNTSU9OID0gZnVuY3Rpb24oYXN0KSB7cmV0dXJuIHRydWU7IH07IC8vIHRvcC1sZXZlbCBleHByZXNzaW9uIG1hcmtlclxufShKJCQpKTtcbiIsIi8qXG4gKiBDb3B5cmlnaHQgKGMpIDIwMTQgU2Ftc3VuZyBFbGVjdHJvbmljcyBDby4sIEx0ZC5cbiAqXG4gKiBMaWNlbnNlZCB1bmRlciB0aGUgQXBhY2hlIExpY2Vuc2UsIFZlcnNpb24gMi4wICh0aGUgXCJMaWNlbnNlXCIpO1xuICogeW91IG1heSBub3QgdXNlIHRoaXMgZmlsZSBleGNlcHQgaW4gY29tcGxpYW5jZSB3aXRoIHRoZSBMaWNlbnNlLlxuICogWW91IG1heSBvYnRhaW4gYSBjb3B5IG9mIHRoZSBMaWNlbnNlIGF0XG4gKlxuICogICAgICAgIGh0dHA6Ly93d3cuYXBhY2hlLm9yZy9saWNlbnNlcy9MSUNFTlNFLTIuMFxuICpcbiAqIFVubGVzcyByZXF1aXJlZCBieSBhcHBsaWNhYmxlIGxhdyBvciBhZ3JlZWQgdG8gaW4gd3JpdGluZywgc29mdHdhcmVcbiAqIGRpc3RyaWJ1dGVkIHVuZGVyIHRoZSBMaWNlbnNlIGlzIGRpc3RyaWJ1dGVkIG9uIGFuIFwiQVMgSVNcIiBCQVNJUyxcbiAqIFdJVEhPVVQgV0FSUkFOVElFUyBPUiBDT05ESVRJT05TIE9GIEFOWSBLSU5ELCBlaXRoZXIgZXhwcmVzcyBvciBpbXBsaWVkLlxuICogU2VlIHRoZSBMaWNlbnNlIGZvciB0aGUgc3BlY2lmaWMgbGFuZ3VhZ2UgZ292ZXJuaW5nIHBlcm1pc3Npb25zIGFuZFxuICogbGltaXRhdGlvbnMgdW5kZXIgdGhlIExpY2Vuc2UuXG4gKi9cbi8vIGRvIG5vdCByZW1vdmUgdGhlIGZvbGxvd2luZyBjb21tZW50XG4vLyBKQUxBTkdJIERPIE5PVCBJTlNUUlVNRU5UXG5pZiAodHlwZW9mIEokJCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgICBKJCQgPSB7fTtcbn1cblxuKGZ1bmN0aW9uIChzYW5kYm94KSB7XG4gICAgaWYgKHR5cGVvZiBzYW5kYm94LkNvbnN0YW50cyAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgICAgcmV0dXJuO1xuICAgIH1cbiAgICB2YXIgQ29uc3RhbnRzID0gc2FuZGJveC5Db25zdGFudHMgPSB7fTtcblxuICAgIENvbnN0YW50cy5pc0Jyb3dzZXIgPSAhKHR5cGVvZiBleHBvcnRzICE9PSAndW5kZWZpbmVkJyAmJiB0aGlzLmV4cG9ydHMgIT09IGV4cG9ydHMpO1xuXG4gICAgdmFyIEFQUExZID0gQ29uc3RhbnRzLkFQUExZID0gRnVuY3Rpb24ucHJvdG90eXBlLmFwcGx5O1xuICAgIHZhciBDQUxMID0gQ29uc3RhbnRzLkNBTEwgPSBGdW5jdGlvbi5wcm90b3R5cGUuY2FsbDtcbiAgICBBUFBMWS5hcHBseSA9IEFQUExZO1xuICAgIEFQUExZLmNhbGwgPSBDQUxMO1xuICAgIENBTEwuYXBwbHkgPSBBUFBMWTtcbiAgICBDQUxMLmNhbGwgPSBDQUxMO1xuXG4gICAgdmFyIEhBU19PV05fUFJPUEVSVFkgPSBDb25zdGFudHMuSEFTX09XTl9QUk9QRVJUWSA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHk7XG4gICAgQ29uc3RhbnRzLkhBU19PV05fUFJPUEVSVFlfQ0FMTCA9IE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbDtcblxuXG4gICAgdmFyIFBSRUZJWDEgPSBDb25zdGFudHMuSkFMQU5HSV9WQVIgPSBcIkokJFwiO1xuICAgIENvbnN0YW50cy5TUEVDSUFMX1BST1AgPSBcIipcIiArIFBSRUZJWDEgKyBcIipcIjtcbiAgICBDb25zdGFudHMuU1BFQ0lBTF9QUk9QMiA9IFwiKlwiICsgUFJFRklYMSArIFwiSSpcIjtcbiAgICBDb25zdGFudHMuU1BFQ0lBTF9QUk9QMyA9IFwiKlwiICsgUFJFRklYMSArIFwiQypcIjtcbiAgICBDb25zdGFudHMuU1BFQ0lBTF9QUk9QNCA9IFwiKlwiICsgUFJFRklYMSArIFwiVypcIjtcbiAgICBDb25zdGFudHMuU1BFQ0lBTF9QUk9QX1NJRCA9IFwiKlwiICsgUFJFRklYMSArIFwiU0lEKlwiO1xuICAgIENvbnN0YW50cy5TUEVDSUFMX1BST1BfSUlEID0gXCIqXCIgKyBQUkVGSVgxICsgXCJJSUQqXCI7XG5cbiAgICBDb25zdGFudHMuVU5LTk9XTiA9IC0xO1xuXG4gICAgLy8tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBFbmQgY29uc3RhbnRzIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gICAgLy8tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLSBDb25zdGFudCBmdW5jdGlvbnMgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cblxuICAgIHZhciBIT1AgPSBDb25zdGFudHMuSE9QID0gZnVuY3Rpb24gKG9iaiwgcHJvcCkge1xuICAgICAgICByZXR1cm4gKHByb3AgKyBcIlwiID09PSAnX19wcm90b19fJykgfHwgQ0FMTC5jYWxsKEhBU19PV05fUFJPUEVSVFksIG9iaiwgcHJvcCk7IC8vQ29uc3RhbnRzLkhBU19PV05fUFJPUEVSVFlfQ0FMTC5hcHBseShDb25zdGFudHMuSEFTX09XTl9QUk9QRVJUWSwgW29iaiwgcHJvcF0pO1xuICAgIH07XG5cbiAgICBDb25zdGFudHMuaGFzR2V0dGVyU2V0dGVyID0gZnVuY3Rpb24gKG9iaiwgcHJvcCwgaXNHZXR0ZXIpIHtcbiAgICAgICAgaWYgKHR5cGVvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yICE9PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICByZXR1cm4gdHJ1ZTtcbiAgICAgICAgfVxuICAgICAgICB3aGlsZSAob2JqICE9PSBudWxsKSB7XG4gICAgICAgICAgICBpZiAodHlwZW9mIG9iaiAhPT0gJ29iamVjdCcgJiYgdHlwZW9mIG9iaiAhPT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgICAgICAgIHJldHVybiBmYWxzZTtcbiAgICAgICAgICAgIH1cbiAgICAgICAgICAgIHZhciBkZXNjID0gT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvcihvYmosIHByb3ApO1xuICAgICAgICAgICAgaWYgKGRlc2MgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgICAgICAgIGlmIChpc0dldHRlciAmJiB0eXBlb2YgZGVzYy5nZXQgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICAgICAgICAgICAgcmV0dXJuIHRydWU7XG4gICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgIGlmICghaXNHZXR0ZXIgJiYgdHlwZW9mIGRlc2Muc2V0ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICAgICAgICAgIHJldHVybiB0cnVlO1xuICAgICAgICAgICAgICAgIH1cbiAgICAgICAgICAgIH0gZWxzZSBpZiAoSE9QKG9iaiwgcHJvcCkpIHtcbiAgICAgICAgICAgICAgICByZXR1cm4gZmFsc2U7XG4gICAgICAgICAgICB9XG4gICAgICAgICAgICBvYmogPSBvYmouX19wcm90b19fO1xuICAgICAgICB9XG4gICAgICAgIHJldHVybiBmYWxzZTtcbiAgICB9O1xuXG4gICAgQ29uc3RhbnRzLmRlYnVnUHJpbnQgPSBmdW5jdGlvbiAocykge1xuICAgICAgICBpZiAoc2FuZGJveC5Db25maWcuREVCVUcpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiKioqXCIgKyBzKTtcbiAgICAgICAgfVxuICAgIH07XG5cbiAgICBDb25zdGFudHMud2FyblByaW50ID0gZnVuY3Rpb24gKGlpZCwgcykge1xuICAgICAgICBpZiAoc2FuZGJveC5Db25maWcuV0FSTiAmJiBpaWQgIT09IDApIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiICAgICAgICBhdCBcIiArIGlpZCArIFwiIFwiICsgcyk7XG4gICAgICAgIH1cbiAgICB9O1xuXG4gICAgQ29uc3RhbnRzLnNlcmlvdXNXYXJuUHJpbnQgPSBmdW5jdGlvbiAoaWlkLCBzKSB7XG4gICAgICAgIGlmIChzYW5kYm94LkNvbmZpZy5TRVJJT1VTX1dBUk4gJiYgaWlkICE9PSAwKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIiAgICAgICAgYXQgXCIgKyBpaWQgKyBcIiBTZXJpb3VzIFwiICsgcyk7XG4gICAgICAgIH1cbiAgICB9O1xuXG59KShKJCQpO1xuXG4iLCIvKlxuICogQ29weXJpZ2h0IDIwMTMtMjAxNCBTYW1zdW5nIEluZm9ybWF0aW9uIFN5c3RlbXMgQW1lcmljYSwgSW5jLlxuICpcbiAqIExpY2Vuc2VkIHVuZGVyIHRoZSBBcGFjaGUgTGljZW5zZSwgVmVyc2lvbiAyLjAgKHRoZSBcIkxpY2Vuc2VcIik7XG4gKiB5b3UgbWF5IG5vdCB1c2UgdGhpcyBmaWxlIGV4Y2VwdCBpbiBjb21wbGlhbmNlIHdpdGggdGhlIExpY2Vuc2UuXG4gKiBZb3UgbWF5IG9idGFpbiBhIGNvcHkgb2YgdGhlIExpY2Vuc2UgYXRcbiAqXG4gKiAgICAgICAgaHR0cDovL3d3dy5hcGFjaGUub3JnL2xpY2Vuc2VzL0xJQ0VOU0UtMi4wXG4gKlxuICogVW5sZXNzIHJlcXVpcmVkIGJ5IGFwcGxpY2FibGUgbGF3IG9yIGFncmVlZCB0byBpbiB3cml0aW5nLCBzb2Z0d2FyZVxuICogZGlzdHJpYnV0ZWQgdW5kZXIgdGhlIExpY2Vuc2UgaXMgZGlzdHJpYnV0ZWQgb24gYW4gXCJBUyBJU1wiIEJBU0lTLFxuICogV0lUSE9VVCBXQVJSQU5USUVTIE9SIENPTkRJVElPTlMgT0YgQU5ZIEtJTkQsIGVpdGhlciBleHByZXNzIG9yIGltcGxpZWQuXG4gKiBTZWUgdGhlIExpY2Vuc2UgZm9yIHRoZSBzcGVjaWZpYyBsYW5ndWFnZSBnb3Zlcm5pbmcgcGVybWlzc2lvbnMgYW5kXG4gKiBsaW1pdGF0aW9ucyB1bmRlciB0aGUgTGljZW5zZS5cbiAqL1xuXG4vLyBBdXRob3I6IEtvdXNoaWsgU2VuXG4vLyBkbyBub3QgcmVtb3ZlIHRoZSBmb2xsb3dpbmcgY29tbWVudFxuLy8gSkFMQU5HSSBETyBOT1QgSU5TVFJVTUVOVFxuXG5pZiAodHlwZW9mIEokJCA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgSiQkID0ge307XG59XG5cbihmdW5jdGlvbiAoc2FuZGJveCkge1xuICBpZiAodHlwZW9mIHNhbmRib3guaWlkVG9Mb2NhdGlvbiAhPT0gJ3VuZGVmaW5lZCcpIHtcbiAgICAgIHJldHVybjtcbiAgfVxuICBzYW5kYm94LmlpZFRvTG9jYXRpb24gPSBmdW5jdGlvbiAoc2lkLCBpaWQpIHtcbiAgICAgIHZhciByZXQsIGFyciwgZ2lkPXNpZDtcbiAgICAgIGlmIChzYW5kYm94LnNtYXApIHtcbiAgICAgICAgICBpZiAodHlwZW9mIHNpZCA9PT0gJ3N0cmluZycgJiYgc2lkLmluZGV4T2YoJzonKT49MCkge1xuICAgICAgICAgICAgICBzaWQgPSBzaWQuc3BsaXQoJzonKTtcbiAgICAgICAgICAgICAgaWlkID0gcGFyc2VJbnQoc2lkWzFdKTtcbiAgICAgICAgICAgICAgc2lkID0gcGFyc2VJbnQoc2lkWzBdKTtcbiAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICBnaWQgPSBzaWQrXCI6XCIraWlkO1xuICAgICAgICAgIH1cbiAgICAgICAgICBpZiAoKHJldCA9IHNhbmRib3guc21hcFtzaWRdKSkge1xuICAgICAgICAgICAgICB2YXIgZm5hbWUgPSByZXQub3JpZ2luYWxDb2RlRmlsZU5hbWU7XG4gICAgICAgICAgICAgIGlmIChyZXQuZXZhbFNpZCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgICAgICAgICBmbmFtZSA9IGZuYW1lK3NhbmRib3guaWlkVG9Mb2NhdGlvbihyZXQuZXZhbFNpZCwgcmV0LmV2YWxJaWQpO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIGFyciA9IHJldFtpaWRdO1xuICAgICAgICAgICAgICBpZiAoYXJyKSB7XG4gICAgICAgICAgICAgICAgICBpZiAoc2FuZGJveC5SZXN1bHRzKSB7XG4gICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiPGEgaHJlZj1cXFwiamF2YXNjcmlwdDppaWRUb0Rpc3BsYXlDb2RlTG9jYXRpb24oJ1wiK2dpZCtcIicpO1xcXCI+KFwiICsgZm5hbWUgKyBcIjpcIiArIGFyclswXSArIFwiOlwiICsgYXJyWzFdICsgXCI6XCIgKyBhcnJbMl0gKyBcIjpcIiArIGFyclszXSArIFwiKTwvYT5cIjtcbiAgICAgICAgICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiKFwiICsgZm5hbWUgKyBcIjpcIiArIGFyclswXSArIFwiOlwiICsgYXJyWzFdICsgXCI6XCIgKyBhcnJbMl0gKyBcIjpcIiArIGFyclszXSArIFwiKVwiO1xuICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICB9IGVsc2Uge1xuICAgICAgICAgICAgICAgICAgcmV0dXJuIFwiKFwiICsgZm5hbWUgKyBcIjppaWRcIiArIGlpZCArIFwiKVwiO1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIHNpZCtcIlwiO1xuICB9O1xuXG4gIHNhbmRib3guZ2V0R2xvYmFsSUlEID0gZnVuY3Rpb24oaWlkKSB7XG4gICAgICByZXR1cm4gc2FuZGJveC5zaWQgK1wiOlwiK2lpZDtcbiAgfVxuXG59KEokJCkpO1xuIiwiLypcbiAqIENvcHlyaWdodCAyMDE0IFNhbXN1bmcgSW5mb3JtYXRpb24gU3lzdGVtcyBBbWVyaWNhLCBJbmMuXG4gKlxuICogTGljZW5zZWQgdW5kZXIgdGhlIEFwYWNoZSBMaWNlbnNlLCBWZXJzaW9uIDIuMCAodGhlIFwiTGljZW5zZVwiKTtcbiAqIHlvdSBtYXkgbm90IHVzZSB0aGlzIGZpbGUgZXhjZXB0IGluIGNvbXBsaWFuY2Ugd2l0aCB0aGUgTGljZW5zZS5cbiAqIFlvdSBtYXkgb2J0YWluIGEgY29weSBvZiB0aGUgTGljZW5zZSBhdFxuICpcbiAqICAgICAgICBodHRwOi8vd3d3LmFwYWNoZS5vcmcvbGljZW5zZXMvTElDRU5TRS0yLjBcbiAqXG4gKiBVbmxlc3MgcmVxdWlyZWQgYnkgYXBwbGljYWJsZSBsYXcgb3IgYWdyZWVkIHRvIGluIHdyaXRpbmcsIHNvZnR3YXJlXG4gKiBkaXN0cmlidXRlZCB1bmRlciB0aGUgTGljZW5zZSBpcyBkaXN0cmlidXRlZCBvbiBhbiBcIkFTIElTXCIgQkFTSVMsXG4gKiBXSVRIT1VUIFdBUlJBTlRJRVMgT1IgQ09ORElUSU9OUyBPRiBBTlkgS0lORCwgZWl0aGVyIGV4cHJlc3Mgb3IgaW1wbGllZC5cbiAqIFNlZSB0aGUgTGljZW5zZSBmb3IgdGhlIHNwZWNpZmljIGxhbmd1YWdlIGdvdmVybmluZyBwZXJtaXNzaW9ucyBhbmRcbiAqIGxpbWl0YXRpb25zIHVuZGVyIHRoZSBMaWNlbnNlLlxuICovXG5cbi8vIEF1dGhvcjogS291c2hpayBTZW5cblxuLy8gZG8gbm90IHJlbW92ZSB0aGUgZm9sbG93aW5nIGNvbW1lbnRcbi8vIEpBTEFOR0kgRE8gTk9UIElOU1RSVU1FTlRcblxuXG4vLyB3cmFwIGluIGFub255bW91cyBmdW5jdGlvbiB0byBjcmVhdGUgbG9jYWwgbmFtZXNwYWNlIHdoZW4gaW4gYnJvd3NlclxuLy8gY3JlYXRlIC8gcmVzZXQgSiQkIGdsb2JhbCB2YXJpYWJsZSB0byBob2xkIGFuYWx5c2lzIHJ1bnRpbWVcbmlmICh0eXBlb2YgSiQkID09PSAndW5kZWZpbmVkJykge1xuICBKJCQgPSB7fTtcbn1cblxuKGZ1bmN0aW9uIChzYW5kYm94KSB7XG4gIGlmICh0eXBlb2Ygc2FuZGJveC5CICE9PSAndW5kZWZpbmVkJykge1xuICAgICAgcmV0dXJuO1xuICB9XG4gIC8vLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gQmVnaW4gSmFsYW5naSBMaWJyYXJ5IGJhY2tlbmQgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG5cbiAgLy8gc3RhY2sgb2YgcmV0dXJuIHZhbHVlcyBmcm9tIGluc3RydW1lbnRlZCBmdW5jdGlvbnMuXG4gIC8vIHdlIG5lZWQgdG8ga2VlcCBhIHN0YWNrIHNpbmNlIGEgZnVuY3Rpb24gbWF5IHJldHVybiBhbmQgdGhlblxuICAvLyBoYXZlIGFub3RoZXIgZnVuY3Rpb24gY2FsbCBpbiBhIGZpbmFsbHkgYmxvY2sgKHNlZSB0ZXN0XG4gIC8vIGNhbGxfaW5fZmluYWxseS5qcylcblxuICB2YXIgZ2xvYmFsID0gdGhpcztcbiAgdmFyIEZ1bmN0aW9uID0gZ2xvYmFsLkZ1bmN0aW9uO1xuICB2YXIgcmV0dXJuU3RhY2sgPSBbXTtcbiAgdmFyIHdyYXBwZWRFeGNlcHRpb25WYWw7XG4gIHZhciBsYXN0VmFsO1xuICB2YXIgc3dpdGNoTGVmdDtcbiAgdmFyIHN3aXRjaEtleVN0YWNrID0gW107XG4gIHZhciBhcmdJbmRleDtcbiAgdmFyIEVWQUxfT1JHID0gZXZhbDtcbiAgdmFyIGxhc3RDb21wdXRlZFZhbHVlO1xuICB2YXIgU1BFQ0lBTF9QUk9QX1NJRCA9IHNhbmRib3guQ29uc3RhbnRzLlNQRUNJQUxfUFJPUF9TSUQ7XG4gIHZhciBTUEVDSUFMX1BST1BfSUlEID0gc2FuZGJveC5Db25zdGFudHMuU1BFQ0lBTF9QUk9QX0lJRDtcblxuICBmdW5jdGlvbiBnZXRQcm9wU2FmZShiYXNlLCBwcm9wKXtcbiAgICBpZihiYXNlID09PSBudWxsIHx8IGJhc2UgPT09IHVuZGVmaW5lZCl7XG4gICAgICByZXR1cm4gdW5kZWZpbmVkO1xuICAgIH1cbiAgICByZXR1cm4gYmFzZVtwcm9wXTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGRlY29kZUJpdFBhdHRlcm4oaSwgbGVuKSB7XG4gICAgICB2YXIgcmV0ID0gbmV3IEFycmF5KGxlbik7XG4gICAgICBmb3IgKHZhciBqPTA7IGo8bGVuOyBqKyspIHtcbiAgICAgICAgICB2YXIgdmFsID0gKGkgJiAxKT90cnVlOmZhbHNlO1xuICAgICAgICAgIHJldFtsZW4gLSBqIC0xXSA9IHZhbDtcbiAgICAgICAgICBpID0gaSA+PiAxO1xuICAgICAgfVxuICAgICAgcmV0dXJuIHJldDtcbiAgfVxuXG4gIGZ1bmN0aW9uIGNyZWF0ZUJpdFBhdHRlcm4oKSB7XG4gICAgICB2YXIgcmV0ID0gMDtcbiAgICAgIHZhciBpO1xuICAgICAgZm9yIChpID0wOyBpPCBhcmd1bWVudHMubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICByZXQgPSAocmV0IDw8IDEpKyhhcmd1bWVudHNbaV0/MTowKTtcbiAgICAgIH1cbiAgICAgIHJldHVybiByZXQ7XG4gIH1cblxuXG4gIHZhciBzaWRTdGFjayA9IFtdLCBzaWRDb3VudGVyID0gMDtcblxuICBmdW5jdGlvbiBjcmVhdGVBbmRBc3NpZ25OZXdTaWQoKSB7XG4gICAgICBzaWRTdGFjay5wdXNoKHNhbmRib3guc2lkKTtcbiAgICAgIHNhbmRib3guc2lkID0gc2lkQ291bnRlciA9IHNpZENvdW50ZXIgKyAxO1xuICAgICAgaWYgKCFzYW5kYm94LnNtYXApIHNhbmRib3guc21hcCA9IHt9O1xuICAgICAgc2FuZGJveC5zbWFwW3NhbmRib3guc2lkXSA9IHNhbmRib3guaWlkcztcbiAgfVxuXG4gIGZ1bmN0aW9uIHJvbGxCYWNrU2lkKCkge1xuICAgICAgc2FuZGJveC5zaWQgPSBzaWRTdGFjay5wb3AoKTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGFzc29jaWF0ZVNpZFdpdGhGdW5jdGlvbihmLCBpaWQpIHtcbiAgICAgIGlmICh0eXBlb2YgZiA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgICAgIGlmIChPYmplY3QgJiYgT2JqZWN0LmRlZmluZVByb3BlcnR5ICYmIHR5cGVvZiBPYmplY3QuZGVmaW5lUHJvcGVydHkgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICAgICAgT2JqZWN0LmRlZmluZVByb3BlcnR5KGYsIFNQRUNJQUxfUFJPUF9TSUQsIHtcbiAgICAgICAgICAgICAgICAgIGVudW1lcmFibGU6ZmFsc2UsXG4gICAgICAgICAgICAgICAgICB3cml0YWJsZTp0cnVlXG4gICAgICAgICAgICAgIH0pO1xuICAgICAgICAgICAgICBPYmplY3QuZGVmaW5lUHJvcGVydHkoZiwgU1BFQ0lBTF9QUk9QX0lJRCwge1xuICAgICAgICAgICAgICAgICAgZW51bWVyYWJsZTpmYWxzZSxcbiAgICAgICAgICAgICAgICAgIHdyaXRhYmxlOnRydWVcbiAgICAgICAgICAgICAgfSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGZbU1BFQ0lBTF9QUk9QX1NJRF0gPSBzYW5kYm94LnNpZDtcbiAgICAgICAgICBmW1NQRUNJQUxfUFJPUF9JSURdID0gaWlkO1xuICAgICAgfVxuICB9XG5cbiAgZnVuY3Rpb24gdXBkYXRlU2lkKGYpIHtcbiAgICAgIHNpZFN0YWNrLnB1c2goc2FuZGJveC5zaWQpO1xuICAgICAgc2FuZGJveC5zaWQgPSBnZXRQcm9wU2FmZShmLCBTUEVDSUFMX1BST1BfU0lEKTtcbiAgfVxuXG5cbiAgLy8gdW51c2VkXG4gIGZ1bmN0aW9uIGlzTmF0aXZlKGYpIHtcbiAgICAgIHJldHVybiBmLnRvU3RyaW5nKCkuaW5kZXhPZignW25hdGl2ZSBjb2RlXScpID4gLTEgfHwgZi50b1N0cmluZygpLmluZGV4T2YoJ1tvYmplY3QgJykgPT09IDA7XG4gIH1cblxuLy8gICBmdW5jdGlvbiBjYWxsQXNOYXRpdmVDb25zdHJ1Y3RvcldpdGhFdmFsKENvbnN0cnVjdG9yLCBhcmdzKSB7XG4vLyAgICAgICB2YXIgYSA9IFtdO1xuLy8gICAgICAgZm9yICh2YXIgaSA9IDA7IGkgPCBhcmdzLmxlbmd0aDsgaSsrKVxuLy8gICAgICAgICAgIGFbaV0gPSAnYXJnc1snICsgaSArICddJztcbi8vICAgICAgIHZhciBldmFsID0gRVZBTF9PUkc7XG4vLyAgICAgICByZXR1cm4gZXZhbCgnbmV3IENvbnN0cnVjdG9yKCcgKyBhLmpvaW4oKSArICcpJyk7XG4vLyAgIH1cbiAgICBcbiAgICBmdW5jdGlvbiBjYWxsQXNOYXRpdmVDb25zdHJ1Y3RvcldpdGhvdXRFdmFsKENvbnN0cnVjdG9yLCBhcmdzKSB7XG4gICAgICAgIC8vIENyZWF0ZSBhIGZ1bmN0aW9uIHRoYXQgd2lsbCBjYWxsIHRoZSBjb25zdHJ1Y3RvciB3aXRoIHRoZSBwcm92aWRlZCBhcmd1bWVudHNcbiAgICAgICAgY29uc3QgZnVuYyA9IG5ldyBGdW5jdGlvbignQ29uc3RydWN0b3InLCAnYXJncycsIFxuICAgICAgICAgICAgYHJldHVybiBuZXcgQ29uc3RydWN0b3IoJHthcmdzLm1hcCgoXywgaSkgPT4gJ2FyZ3NbJyArIGkgKyAnXScpLmpvaW4oJywgJyl9KTtgKTtcbiAgICAgICAgLy8gQ2FsbCB0aGUgZnVuY3Rpb24gd2l0aCB0aGUgY29uc3RydWN0b3IgYW5kIHRoZSBhcmd1bWVudHNcbiAgICAgICAgcmV0dXJuIGZ1bmMoQ29uc3RydWN0b3IsIGFyZ3MpO1xuICAgIH1cblxuICBmdW5jdGlvbiBjYWxsQXNOYXRpdmVDb25zdHJ1Y3RvcihDb25zdHJ1Y3RvciwgYXJncykge1xuICAgICAgaWYgKGFyZ3MubGVuZ3RoID09PSAwKSB7XG4gICAgICAgICAgcmV0dXJuIG5ldyBDb25zdHJ1Y3RvcigpO1xuICAgICAgfVxuICAgICAgaWYgKGFyZ3MubGVuZ3RoID09PSAxKSB7XG4gICAgICAgICAgcmV0dXJuIG5ldyBDb25zdHJ1Y3RvcihhcmdzWzBdKTtcbiAgICAgIH1cbiAgICAgIGlmIChhcmdzLmxlbmd0aCA9PT0gMikge1xuICAgICAgICAgIHJldHVybiBuZXcgQ29uc3RydWN0b3IoYXJnc1swXSwgYXJnc1sxXSk7XG4gICAgICB9XG4gICAgICBpZiAoYXJncy5sZW5ndGggPT09IDMpIHtcbiAgICAgICAgICByZXR1cm4gbmV3IENvbnN0cnVjdG9yKGFyZ3NbMF0sIGFyZ3NbMV0sIGFyZ3NbMl0pO1xuICAgICAgfVxuICAgICAgaWYgKGFyZ3MubGVuZ3RoID09PSA0KSB7XG4gICAgICAgICAgcmV0dXJuIG5ldyBDb25zdHJ1Y3RvcihhcmdzWzBdLCBhcmdzWzFdLCBhcmdzWzJdLCBhcmdzWzNdKTtcbiAgICAgIH1cbiAgICAgIGlmIChhcmdzLmxlbmd0aCA9PT0gNSkge1xuICAgICAgICAgIHJldHVybiBuZXcgQ29uc3RydWN0b3IoYXJnc1swXSwgYXJnc1sxXSwgYXJnc1syXSwgYXJnc1szXSwgYXJnc1s0XSk7XG4gICAgICB9XG4gICAgICByZXR1cm4gY2FsbEFzTmF0aXZlQ29uc3RydWN0b3JXaXRob3V0RXZhbChDb25zdHJ1Y3RvciwgYXJncyk7XG4gIH1cblxuICBmdW5jdGlvbiBjYWxsQXNDb25zdHJ1Y3RvcihDb25zdHJ1Y3RvciwgYXJncykge1xuICAgICAgdmFyIHJldDtcbiAgICAgIGlmICh0cnVlKSB7XG4gICAgICAgICAgcmV0ID0gY2FsbEFzTmF0aXZlQ29uc3RydWN0b3IoQ29uc3RydWN0b3IsIGFyZ3MpO1xuICAgICAgICAgIHJldHVybiByZXQ7XG4gICAgICB9IGVsc2UgeyAvLyBlbHNlIGJyYW5jaCBpcyBhIG1vcmUgZWxlZ2FudCB0byBjYWxsIGEgY29uc3RydWN0b3IgcmVmbGVjdGl2ZWx5LCBidXQgaXQgbGVhZHMgdG8gbWVtb3J5IGxlYWsgaW4gdjguXG4gICAgICAgICAgdmFyIFRlbXAgPSBmdW5jdGlvbiAoKSB7XG4gICAgICAgICAgfSwgaW5zdDtcbiAgICAgICAgICBUZW1wLnByb3RvdHlwZSA9IENvbnN0cnVjdG9yLnByb3RvdHlwZTtcbiAgICAgICAgICBpbnN0ID0gbmV3IFRlbXA7XG4gICAgICAgICAgcmV0ID0gQ29uc3RydWN0b3IuYXBwbHkoaW5zdCwgYXJncyk7XG4gICAgICAgICAgcmV0dXJuIE9iamVjdChyZXQpID09PSByZXQgPyByZXQgOiBpbnN0O1xuICAgICAgfVxuICB9XG5cbiAgZnVuY3Rpb24gaW52b2tlRXZhbChiYXNlLCBmLCBhcmdzLCBpaWQpIHtcbiAgICAgIHJldHVybiBmKHNhbmRib3guaW5zdHJ1bWVudEV2YWxDb2RlKGFyZ3NbMF0sIGlpZCwgZmFsc2UpKTtcbiAgfVxuXG4gIGZ1bmN0aW9uIGludm9rZUZ1bmN0aW9uRGVjbChiYXNlLCBmLCBhcmdzLCBpaWQpIHtcbiAgICAgIC8vIEludm9rZSB3aXRoIHRoZSBvcmlnaW5hbCBwYXJhbWV0ZXJzIHRvIHByZXNlcnZlIGV4Y2VwdGlvbmFsIGJlaGF2aW9yIGlmIGlucHV0IGlzIGludmFsaWRcbiAgICAgIGYuYXBwbHkoYmFzZSwgYXJncyk7XG4gICAgICAvLyBPdGhlcndpc2UgaW5wdXQgaXMgdmFsaWQsIHNvIGluc3RydW1lbnQgYW5kIGludm9rZSB2aWEgZXZhbFxuICAgICAgdmFyIG5ld0FyZ3MgPSBbXTtcbiAgICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYXJncy5sZW5ndGgtMTsgaSsrKSB7XG4gICAgICAgICAgbmV3QXJnc1tpXSA9IGFyZ3NbaV07XG4gICAgICB9XG4gICAgICB2YXIgY29kZSA9ICcoZnVuY3Rpb24oJyArIG5ld0FyZ3Muam9pbignLCAnKSArICcpIHsgJyArIGFyZ3NbYXJncy5sZW5ndGgtMV0gKyAnIH0pJztcbiAgICAgIHZhciBjb2RlID0gc2FuZGJveC5pbnN0cnVtZW50RXZhbENvZGUoY29kZSwgaWlkLCBmYWxzZSk7XG4gICAgICAvLyBVc2luZyBFVkFMX09SRyBpbnN0ZWFkIG9mIGV2YWwoKSBpcyBpbXBvcnRhbnQgYXMgaXQgcHJlc2VydmVzIHRoZSBzY29waW5nIHNlbWFudGljcyBvZiBGdW5jdGlvbigpXG4gICAgICB2YXIgb3V0ID0gRVZBTF9PUkcoY29kZSk7XG4gICAgICByZXR1cm4gb3V0O1xuICB9XG5cbiAgZnVuY3Rpb24gY2FsbEZ1bihmLCBiYXNlLCBhcmdzLCBpc0NvbnN0cnVjdG9yLCBpaWQpIHtcbiAgICAgIHZhciByZXN1bHQ7XG4gICAgICBwdXNoU3dpdGNoS2V5KCk7XG4gICAgICB0cnkge1xuICAgICAgICAgIGlmIChmID09PSBFVkFMX09SRykge1xuICAgICAgICAgICAgICByZXN1bHQgPSBpbnZva2VFdmFsKGJhc2UsIGYsIGFyZ3MsIGlpZCk7XG4gICAgICAgICAgfSBlbHNlIGlmIChmID09PSBGdW5jdGlvbikge1xuICAgICAgICAgICAgICByZXN1bHQgPSBpbnZva2VGdW5jdGlvbkRlY2woYmFzZSwgZiwgYXJncywgaWlkKTtcbiAgICAgICAgICB9IGVsc2UgaWYgKGlzQ29uc3RydWN0b3IpIHtcbiAgICAgICAgICAgICAgcmVzdWx0ID0gY2FsbEFzQ29uc3RydWN0b3IoZiwgYXJncyk7XG4gICAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgICAgcmVzdWx0ID0gRnVuY3Rpb24ucHJvdG90eXBlLmFwcGx5LmNhbGwoZiwgYmFzZSwgYXJncyk7XG4gICAgICAgICAgfVxuICAgICAgICAgIHJldHVybiByZXN1bHQ7XG4gICAgICB9IGZpbmFsbHkge1xuICAgICAgICAgIHBvcFN3aXRjaEtleSgpO1xuICAgICAgfVxuICB9XG5cbiAgZnVuY3Rpb24gaW52b2tlRnVuKGlpZCwgYmFzZSwgZiwgYXJncywgaXNDb25zdHJ1Y3RvciwgaXNNZXRob2QpIHtcbiAgICAgIHZhciBhcmV0LCBza2lwID0gZmFsc2UsIHJlc3VsdDtcblxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5pbnZva2VGdW5QcmUpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5pbnZva2VGdW5QcmUoaWlkLCBmLCBiYXNlLCBhcmdzLCBpc0NvbnN0cnVjdG9yLCBpc01ldGhvZCwgZ2V0UHJvcFNhZmUoZiwgU1BFQ0lBTF9QUk9QX0lJRCksIGdldFByb3BTYWZlKGYsIFNQRUNJQUxfUFJPUF9TSUQpKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICBmID0gYXJldC5mO1xuICAgICAgICAgICAgICBiYXNlID0gYXJldC5iYXNlO1xuICAgICAgICAgICAgICBhcmdzID0gYXJldC5hcmdzO1xuICAgICAgICAgICAgICBza2lwID0gYXJldC5za2lwO1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIGlmICghc2tpcCkge1xuICAgICAgICAgIHJlc3VsdCA9IGNhbGxGdW4oZiwgYmFzZSwgYXJncywgaXNDb25zdHJ1Y3RvciwgaWlkKTtcbiAgICAgIH1cbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuaW52b2tlRnVuKSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuaW52b2tlRnVuKGlpZCwgZiwgYmFzZSwgYXJncywgcmVzdWx0LCBpc0NvbnN0cnVjdG9yLCBpc01ldGhvZCwgZ2V0UHJvcFNhZmUoZiwgU1BFQ0lBTF9QUk9QX0lJRCksIGdldFByb3BTYWZlKGYsIFNQRUNJQUxfUFJPUF9TSUQpKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICByZXN1bHQgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gcmVzdWx0O1xuICB9XG5cbiAgLy8gRnVuY3Rpb24gY2FsbCAoZS5nLiwgZigpKVxuICBmdW5jdGlvbiBGKGlpZCwgZiwgZmxhZ3MpIHtcbiAgICAgIHZhciBiRmxhZ3MgPSBkZWNvZGVCaXRQYXR0ZXJuKGZsYWdzLCAxKTsgLy8gW2lzQ29uc3RydWN0b3JdXG4gICAgICByZXR1cm4gZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHZhciBiYXNlID0gdGhpcztcbiAgICAgICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gaW52b2tlRnVuKGlpZCwgYmFzZSwgZiwgYXJndW1lbnRzLCBiRmxhZ3NbMF0sIGZhbHNlKSk7XG4gICAgICB9XG4gIH1cblxuICAvLyBNZXRob2QgY2FsbCAoZS5nLiwgZS5mKCkpXG4gIGZ1bmN0aW9uIE0oaWlkLCBiYXNlLCBvZmZzZXQsIGZsYWdzKSB7XG4gICAgICB2YXIgYkZsYWdzID0gZGVjb2RlQml0UGF0dGVybihmbGFncywgMik7IC8vIFtpc0NvbnN0cnVjdG9yLCBpc0NvbXB1dGVkXVxuICAgICAgdmFyIGYgPSBHKGlpZCArIDIsIGJhc2UsIG9mZnNldCwgY3JlYXRlQml0UGF0dGVybihiRmxhZ3NbMV0sIGZhbHNlLCB0cnVlKSk7XG4gICAgICByZXR1cm4gZnVuY3Rpb24gKCkge1xuICAgICAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSBpbnZva2VGdW4oaWlkLCBiYXNlLCBmLCBhcmd1bWVudHMsIGJGbGFnc1swXSwgdHJ1ZSkpO1xuICAgICAgfTtcbiAgfVxuXG4gIC8vIElnbm9yZSBhcmd1bWVudCAoaWRlbnRpdHkpLlxuICBmdW5jdGlvbiBJKHZhbCkge1xuICAgICAgcmV0dXJuIHZhbDtcbiAgfVxuXG4gIHZhciBoYXNHZXRPd25Qcm9wZXJ0eURlc2NyaXB0b3IgPSB0eXBlb2YgT2JqZWN0LmdldE93blByb3BlcnR5RGVzY3JpcHRvciA9PT0gJ2Z1bmN0aW9uJztcbiAgLy8gb2JqZWN0L2Z1bmN0aW9uL3JlZ2V4cC9hcnJheSBMaXRlcmFsXG4gIGZ1bmN0aW9uIFQoaWlkLCB2YWwsIHR5cGUsIGhhc0dldHRlclNldHRlciwgaW50ZXJuYWxJaWQpIHtcbiAgICAgIHZhciBhcmV0O1xuICAgICAgYXNzb2NpYXRlU2lkV2l0aEZ1bmN0aW9uKHZhbCwgaW50ZXJuYWxJaWQpO1xuICAgICAgaWYgKGhhc0dldHRlclNldHRlcikge1xuICAgICAgICAgIGZvciAodmFyIG9mZnNldCBpbiB2YWwpIHtcbiAgICAgICAgICAgICAgaWYgKGhhc0dldE93blByb3BlcnR5RGVzY3JpcHRvciAmJiB2YWwuaGFzT3duUHJvcGVydHkob2Zmc2V0KSkge1xuICAgICAgICAgICAgICAgICAgdmFyIGRlc2MgPSBPYmplY3QuZ2V0T3duUHJvcGVydHlEZXNjcmlwdG9yKHZhbCwgb2Zmc2V0KTtcbiAgICAgICAgICAgICAgICAgIGlmIChkZXNjICE9PSB1bmRlZmluZWQpIHtcbiAgICAgICAgICAgICAgICAgICAgICBpZiAodHlwZW9mIGRlc2MuZ2V0ID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICAgICAgICAgICAgICAgICAgICAgIFQoaWlkLCBkZXNjLmdldCwgMTIsIGZhbHNlLCBpbnRlcm5hbElpZCk7XG4gICAgICAgICAgICAgICAgICAgICAgfVxuICAgICAgICAgICAgICAgICAgICAgIGlmICh0eXBlb2YgZGVzYy5zZXQgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgICAgICAgICAgICAgICAgICAgICAgVChpaWQsIGRlc2Muc2V0LCAxMiwgZmFsc2UsIGludGVybmFsSWlkKTtcbiAgICAgICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgICAgICB9XG4gICAgICAgICAgICAgIH1cbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLmxpdGVyYWwpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5saXRlcmFsKGlpZCwgdmFsLCBoYXNHZXR0ZXJTZXR0ZXIpO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSB2YWwpO1xuICB9XG5cbiAgLy8gd3JhcCBvYmplY3QgbyBpbiBmb3IgKHggaW4gbykgeyAuLi4gfVxuICBmdW5jdGlvbiBIKGlpZCwgdmFsKSB7XG4gICAgICB2YXIgYXJldDtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuZm9yaW5PYmplY3QpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5mb3Jpbk9iamVjdChpaWQsIHZhbCk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgdmFsID0gYXJldC5yZXN1bHQ7XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIHZhbDtcbiAgfVxuXG4gIC8vIHZhcmlhYmxlIGRlY2xhcmF0aW9uIChJbml0KVxuICBmdW5jdGlvbiBOKGlpZCwgbmFtZSwgdmFsLCBmbGFncykge1xuICAgICAgdmFyIGJGbGFncyA9IGRlY29kZUJpdFBhdHRlcm4oZmxhZ3MsIDMpOyAvLyBbaXNBcmd1bWVudCwgaXNMb2NhbFN5bmMsIGlzQ2F0Y2hQYXJhbV1cbiAgICAgIC8vIGlzTG9jYWxTeW5jIGlzIG9ubHkgdHJ1ZSB3aGVuIHdlIHN5bmMgdmFyaWFibGVzIGluc2lkZSBhIGZvci1pbiBsb29wXG4gICAgICB2YXIgYXJldDtcblxuICAgICAgaWYgKGJGbGFnc1swXSkge1xuICAgICAgICAgIGFyZ0luZGV4Kys7XG4gICAgICB9XG4gICAgICBpZiAoIWJGbGFnc1sxXSAmJiBzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuZGVjbGFyZSkge1xuICAgICAgICAgIGlmIChiRmxhZ3NbMF0gJiYgYXJnSW5kZXggPiAxKSB7XG4gICAgICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLmRlY2xhcmUoaWlkLCBuYW1lLCB2YWwsIGJGbGFnc1swXSwgYXJnSW5kZXggLSAyLCBiRmxhZ3NbMl0pO1xuICAgICAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLmRlY2xhcmUoaWlkLCBuYW1lLCB2YWwsIGJGbGFnc1swXSwgLTEsIGJGbGFnc1syXSk7XG4gICAgICAgICAgfVxuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiB2YWw7XG4gIH1cblxuICAvLyBnZXRGaWVsZCAocHJvcGVydHkgcmVhZClcbiAgZnVuY3Rpb24gRyhpaWQsIGJhc2UsIG9mZnNldCwgZmxhZ3MpIHtcbiAgICAgIHZhciBiRmxhZ3MgPSBkZWNvZGVCaXRQYXR0ZXJuKGZsYWdzLCAzKTsgLy8gW2lzQ29tcHV0ZWQsIGlzT3BBc3NpZ24sIGlzTWV0aG9kQ2FsbF1cblxuICAgICAgdmFyIGFyZXQsIHNraXAgPSBmYWxzZSwgdmFsO1xuXG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLmdldEZpZWxkUHJlKSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuZ2V0RmllbGRQcmUoaWlkLCBiYXNlLCBvZmZzZXQsIGJGbGFnc1swXSwgYkZsYWdzWzFdLCBiRmxhZ3NbMl0pO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIGJhc2UgPSBhcmV0LmJhc2U7XG4gICAgICAgICAgICAgIG9mZnNldCA9IGFyZXQub2Zmc2V0O1xuICAgICAgICAgICAgICBza2lwID0gYXJldC5za2lwO1xuICAgICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKCFza2lwKSB7XG4gICAgICAgICAgdmFsID0gYmFzZVtvZmZzZXRdO1xuICAgICAgfVxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5nZXRGaWVsZCkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLmdldEZpZWxkKGlpZCwgYmFzZSwgb2Zmc2V0LCB2YWwsIGJGbGFnc1swXSwgYkZsYWdzWzFdLCBiRmxhZ3NbMl0pO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSB2YWwpO1xuICB9XG5cbiAgLy8gcHV0RmllbGQgKHByb3BlcnR5IHdyaXRlKVxuICBmdW5jdGlvbiBQKGlpZCwgYmFzZSwgb2Zmc2V0LCB2YWwsIGZsYWdzKSB7XG4gICAgICB2YXIgYkZsYWdzID0gZGVjb2RlQml0UGF0dGVybihmbGFncywgMik7IC8vIFtpc0NvbXB1dGVkLCBpc09wQXNzaWduXVxuXG4gICAgICB2YXIgYXJldCwgc2tpcCA9IGZhbHNlO1xuXG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLnB1dEZpZWxkUHJlKSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMucHV0RmllbGRQcmUoaWlkLCBiYXNlLCBvZmZzZXQsIHZhbCwgYkZsYWdzWzBdLCAhIWJGbGFnc1sxXSk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgYmFzZSA9IGFyZXQuYmFzZTtcbiAgICAgICAgICAgICAgb2Zmc2V0ID0gYXJldC5vZmZzZXQ7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQudmFsO1xuICAgICAgICAgICAgICBza2lwID0gYXJldC5za2lwO1xuICAgICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKCFza2lwKSB7XG4gICAgICAgICAgYmFzZVtvZmZzZXRdID0gdmFsO1xuICAgICAgfVxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5wdXRGaWVsZCkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLnB1dEZpZWxkKGlpZCwgYmFzZSwgb2Zmc2V0LCB2YWwsIGJGbGFnc1swXSwgISFiRmxhZ3NbMV0pO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSB2YWwpO1xuICB9XG5cbiAgLy8gdmFyaWFibGUgd3JpdGVcbiAgLy8gaXNHbG9iYWwgbWVhbnMgdGhhdCB0aGUgdmFyaWFibGUgaXMgZ2xvYmFsIGFuZCBub3QgZGVjbGFyZWQgYXMgdmFyXG4gIC8vIGlzU2NyaXB0TG9jYWwgbWVhbnMgdGhhdCB0aGUgdmFyaWFibGUgaXMgZ2xvYmFsIGFuZCBpcyBkZWNsYXJlZCBhcyB2YXJcbiAgZnVuY3Rpb24gUihpaWQsIG5hbWUsIHZhbCwgZmxhZ3MpIHtcbiAgICAgIHZhciBhcmV0O1xuICAgICAgdmFyIGJGbGFncyA9IGRlY29kZUJpdFBhdHRlcm4oZmxhZ3MsIDIpOyAvLyBbaXNHbG9iYWwsIGlzU2NyaXB0TG9jYWxdXG5cbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMucmVhZCkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLnJlYWQoaWlkLCBuYW1lLCB2YWwsIGJGbGFnc1swXSwgYkZsYWdzWzFdKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICB2YWwgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gdmFsKTtcbiAgfVxuXG4gIC8vIHZhcmlhYmxlIHdyaXRlXG4gIGZ1bmN0aW9uIFcoaWlkLCBuYW1lLCB2YWwsIGxocywgZmxhZ3MpIHtcbiAgICAgIHZhciBiRmxhZ3MgPSBkZWNvZGVCaXRQYXR0ZXJuKGZsYWdzLCAzKTsgLy9baXNHbG9iYWwsIGlzU2NyaXB0TG9jYWwsIGlzRGVjbGFyYXRpb25dXG4gICAgICB2YXIgYXJldDtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMud3JpdGUpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy53cml0ZShpaWQsIG5hbWUsIHZhbCwgbGhzLCBiRmxhZ3NbMF0sIGJGbGFnc1sxXSk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgdmFsID0gYXJldC5yZXN1bHQ7XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgaWYgKCFiRmxhZ3NbMl0pIHtcbiAgICAgICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gdmFsKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgICAgbGFzdENvbXB1dGVkVmFsdWUgPSB1bmRlZmluZWQ7XG4gICAgICAgICAgcmV0dXJuIHZhbDtcbiAgICAgIH1cbiAgfVxuXG4gIC8vIHdpdGggc3RhdGVtZW50XG4gIGZ1bmN0aW9uIFdpKGlpZCwgdmFsKSB7XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLl93aXRoKSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuX3dpdGgoaWlkLCB2YWwpO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVybiB2YWw7XG4gIH1cblxuICAvLyBVbmNhdWdodCBleGNlcHRpb25cbiAgZnVuY3Rpb24gRXgoaWlkLCBlKSB7XG4gICAgICB3cmFwcGVkRXhjZXB0aW9uVmFsID0ge2V4Y2VwdGlvbjplfTtcbiAgfVxuXG4gIC8vIFRocm93IHN0YXRlbWVudFxuICBmdW5jdGlvbiBUaChpaWQsIHZhbCkge1xuICAgICAgdmFyIGFyZXQ7XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLl90aHJvdykge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLl90aHJvdyhpaWQsIHZhbCk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgdmFsID0gYXJldC5yZXN1bHQ7XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IHZhbCk7XG4gIH1cblxuICAvLyBSZXR1cm4gc3RhdGVtZW50XG4gIGZ1bmN0aW9uIFJ0KGlpZCwgdmFsKSB7XG4gICAgICB2YXIgYXJldDtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuX3JldHVybikge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLl9yZXR1cm4oaWlkLCB2YWwpO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIHZhbCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJldHVyblN0YWNrLnBvcCgpO1xuICAgICAgcmV0dXJuU3RhY2sucHVzaCh2YWwpO1xuICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IHZhbCk7XG4gIH1cblxuICAvLyBBY3R1YWwgcmV0dXJuIGZyb20gZnVuY3Rpb24sIGludm9rZWQgZnJvbSAnZmluYWxseScgYmxvY2tcbiAgLy8gYWRkZWQgYXJvdW5kIGV2ZXJ5IGZ1bmN0aW9uIGJ5IGluc3RydW1lbnRhdGlvbi4gIFJlYWRzXG4gIC8vIHRoZSByZXR1cm4gdmFsdWUgc3RvcmVkIGJ5IGNhbGwgdG8gUnQoKVxuICBmdW5jdGlvbiBSYSgpIHtcbiAgICAgIHZhciByZXR1cm5WYWwgPSByZXR1cm5TdGFjay5wb3AoKTtcbiAgICAgIHdyYXBwZWRFeGNlcHRpb25WYWwgPSB1bmRlZmluZWQ7XG4gICAgICByZXR1cm4gcmV0dXJuVmFsO1xuICB9XG5cbiAgLy8gRnVuY3Rpb24gZW50ZXJcbiAgZnVuY3Rpb24gRmUoaWlkLCBmLCBkaXMgLyogdGhpcyAqLywgYXJncykge1xuICAgICAgYXJnSW5kZXggPSAwO1xuICAgICAgcmV0dXJuU3RhY2sucHVzaCh1bmRlZmluZWQpO1xuICAgICAgd3JhcHBlZEV4Y2VwdGlvblZhbCA9IHVuZGVmaW5lZDtcbiAgICAgIHVwZGF0ZVNpZChmKTtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuZnVuY3Rpb25FbnRlcikge1xuICAgICAgICAgIHNhbmRib3guYW5hbHlzaXMuZnVuY3Rpb25FbnRlcihpaWQsIGYsIGRpcywgYXJncyk7XG4gICAgICB9XG4gIH1cblxuICAvLyBGdW5jdGlvbiBleGl0XG4gIGZ1bmN0aW9uIEZyKGlpZCkge1xuICAgICAgdmFyIGlzQmFja3RyYWNrID0gZmFsc2UsIHRtcCwgYXJldCwgcmV0dXJuVmFsO1xuXG4gICAgICByZXR1cm5WYWwgPSByZXR1cm5TdGFjay5wb3AoKTtcbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuZnVuY3Rpb25FeGl0KSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMuZnVuY3Rpb25FeGl0KGlpZCwgcmV0dXJuVmFsLCB3cmFwcGVkRXhjZXB0aW9uVmFsKTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICByZXR1cm5WYWwgPSBhcmV0LnJldHVyblZhbDtcbiAgICAgICAgICAgICAgd3JhcHBlZEV4Y2VwdGlvblZhbCA9IGFyZXQud3JhcHBlZEV4Y2VwdGlvblZhbDtcbiAgICAgICAgICAgICAgaXNCYWNrdHJhY2sgPSBhcmV0LmlzQmFja3RyYWNrO1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJvbGxCYWNrU2lkKCk7XG4gICAgICBpZiAoIWlzQmFja3RyYWNrKSB7XG4gICAgICAgICAgcmV0dXJuU3RhY2sucHVzaChyZXR1cm5WYWwpO1xuICAgICAgfVxuICAgICAgLy8gaWYgdGhlcmUgd2FzIGFuIHVuY2F1Z2h0IGV4Y2VwdGlvbiwgdGhyb3cgaXRcbiAgICAgIC8vIGhlcmUsIHRvIHByZXNlcnZlIGV4Y2VwdGlvbmFsIGNvbnRyb2wgZmxvd1xuICAgICAgaWYgKHdyYXBwZWRFeGNlcHRpb25WYWwgIT09IHVuZGVmaW5lZCkge1xuICAgICAgICAgIHRtcCA9IHdyYXBwZWRFeGNlcHRpb25WYWwuZXhjZXB0aW9uO1xuICAgICAgICAgIHdyYXBwZWRFeGNlcHRpb25WYWwgPSB1bmRlZmluZWQ7XG4gICAgICAgICAgdGhyb3cgdG1wO1xuICAgICAgfVxuICAgICAgcmV0dXJuIGlzQmFja3RyYWNrO1xuICB9XG5cbiAgLy8gU2NyaXB0IGVudGVyXG4gIGZ1bmN0aW9uIFNlKGlpZCwgdmFsLCBvcmlnRmlsZU5hbWUpIHtcbiAgICAgIGNyZWF0ZUFuZEFzc2lnbk5ld1NpZCgpO1xuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5zY3JpcHRFbnRlcikge1xuICAgICAgICAgIHNhbmRib3guYW5hbHlzaXMuc2NyaXB0RW50ZXIoaWlkLCB2YWwsIG9yaWdGaWxlTmFtZSk7XG4gICAgICB9XG4gICAgICBsYXN0Q29tcHV0ZWRWYWx1ZSA9IHVuZGVmaW5lZDtcbiAgfVxuXG4gIC8vIFNjcmlwdCBleGl0XG4gIGZ1bmN0aW9uIFNyKGlpZCkge1xuICAgICAgdmFyIHRtcCwgYXJldCwgaXNCYWNrdHJhY2s7XG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLnNjcmlwdEV4aXQpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5zY3JpcHRFeGl0KGlpZCwgd3JhcHBlZEV4Y2VwdGlvblZhbCk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgd3JhcHBlZEV4Y2VwdGlvblZhbCA9IGFyZXQud3JhcHBlZEV4Y2VwdGlvblZhbDtcbiAgICAgICAgICAgICAgaXNCYWNrdHJhY2sgPSBhcmV0LmlzQmFja3RyYWNrO1xuICAgICAgICAgIH1cbiAgICAgIH1cbiAgICAgIHJvbGxCYWNrU2lkKCk7XG4gICAgICBpZiAod3JhcHBlZEV4Y2VwdGlvblZhbCAhPT0gdW5kZWZpbmVkKSB7XG4gICAgICAgICAgdG1wID0gd3JhcHBlZEV4Y2VwdGlvblZhbC5leGNlcHRpb247XG4gICAgICAgICAgd3JhcHBlZEV4Y2VwdGlvblZhbCA9IHVuZGVmaW5lZDtcbiAgICAgICAgICB0aHJvdyB0bXA7XG4gICAgICB9XG4gICAgICByZXR1cm4gaXNCYWNrdHJhY2s7XG4gIH1cblxuXG4gIC8vIE1vZGlmeSBhbmQgYXNzaWduICs9LCAtPSAuLi5cbiAgZnVuY3Rpb24gQShpaWQsIGJhc2UsIG9mZnNldCwgb3AsIGZsYWdzKSB7XG4gICAgICB2YXIgYkZsYWdzID0gZGVjb2RlQml0UGF0dGVybihmbGFncywgMSk7IC8vIFtpc0NvbXB1dGVkXVxuICAgICAgLy8gYXZvaWQgaWlkIGNvbGxpc2lvbjogbWFrZSBzdXJlIHRoYXQgaWlkKzIgaGFzIHRoZSBzYW1lIHNvdXJjZSBtYXAgYXMgaWlkIChAdG9kbylcbiAgICAgIHZhciBvcHJuZDEgPSBHKGlpZCsyLCBiYXNlLCBvZmZzZXQsIGNyZWF0ZUJpdFBhdHRlcm4oYkZsYWdzWzBdLCB0cnVlLCBmYWxzZSkpO1xuICAgICAgcmV0dXJuIGZ1bmN0aW9uIChvcHJuZDIpIHtcbiAgICAgICAgICAvLyBzdGlsbCBwb3NzaWJsZSB0byBnZXQgaWlkIGNvbGxpc2lvbiB3aXRoIGEgbWVtIG9wZXJhdGlvblxuICAgICAgICAgIHZhciB2YWwgPSBCKGlpZCwgb3AsIG9wcm5kMSwgb3BybmQyLCBjcmVhdGVCaXRQYXR0ZXJuKGZhbHNlLCB0cnVlLCBmYWxzZSkpO1xuICAgICAgICAgIHJldHVybiBQKGlpZCwgYmFzZSwgb2Zmc2V0LCB2YWwsIGNyZWF0ZUJpdFBhdHRlcm4oYkZsYWdzWzBdLCB0cnVlKSk7XG4gICAgICB9O1xuICB9XG5cbiAgLy8gQmluYXJ5IG9wZXJhdGlvblxuICBmdW5jdGlvbiBCKGlpZCwgb3AsIGxlZnQsIHJpZ2h0LCBmbGFncykge1xuICAgICAgdmFyIGJGbGFncyA9IGRlY29kZUJpdFBhdHRlcm4oZmxhZ3MsIDMpOyAvLyBbaXNDb21wdXRlZCwgaXNPcEFzc2lnbiwgaXNTd2l0Y2hDYXNlQ29tcGFyaXNvbl1cbiAgICAgIHZhciByZXN1bHQsIGFyZXQsIHNraXAgPSBmYWxzZTtcblxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5iaW5hcnlQcmUpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5iaW5hcnlQcmUoaWlkLCBvcCwgbGVmdCwgcmlnaHQsIGJGbGFnc1sxXSwgYkZsYWdzWzJdLCBiRmxhZ3NbMF0pO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIG9wID0gYXJldC5vcDtcbiAgICAgICAgICAgICAgbGVmdCA9IGFyZXQubGVmdDtcbiAgICAgICAgICAgICAgcmlnaHQgPSBhcmV0LnJpZ2h0O1xuICAgICAgICAgICAgICBza2lwID0gYXJldC5za2lwO1xuICAgICAgICAgIH1cbiAgICAgIH1cblxuXG4gICAgICBpZiAoIXNraXApIHtcbiAgICAgICAgICBzd2l0Y2ggKG9wKSB7XG4gICAgICAgICAgICAgIGNhc2UgXCIrXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0ICsgcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIi1cIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgLSByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiKlwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCAqIHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCIvXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0IC8gcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIiVcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgJSByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiPDxcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgPDwgcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIj4+XCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0ID4+IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCI+Pj5cIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgPj4+IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCI8XCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0IDwgcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIj5cIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgPiByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiPD1cIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgPD0gcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIj49XCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0ID49IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCI9PVwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCA9PSByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiIT1cIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgIT0gcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIj09PVwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCA9PT0gcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIiE9PVwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCAhPT0gcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIiZcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IGxlZnQgJiByaWdodDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwifFwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gbGVmdCB8IHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCJeXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0IF4gcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcImRlbGV0ZVwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gZGVsZXRlIGxlZnRbcmlnaHRdO1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCJpbnN0YW5jZW9mXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0IGluc3RhbmNlb2YgcmlnaHQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcImluXCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSBsZWZ0IGluIHJpZ2h0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGRlZmF1bHQ6XG4gICAgICAgICAgICAgICAgICB0aHJvdyBuZXcgRXJyb3Iob3AgKyBcIiBhdCBcIiArIGlpZCArIFwiIG5vdCBmb3VuZFwiKTtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5iaW5hcnkpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5iaW5hcnkoaWlkLCBvcCwgbGVmdCwgcmlnaHQsIHJlc3VsdCwgYkZsYWdzWzFdLCBiRmxhZ3NbMl0sIGJGbGFnc1swXSk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgcmVzdWx0ID0gYXJldC5yZXN1bHQ7XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IHJlc3VsdCk7XG4gIH1cblxuXG4gIC8vIFVuYXJ5IG9wZXJhdGlvblxuICBmdW5jdGlvbiBVKGlpZCwgb3AsIGxlZnQpIHtcbiAgICAgIHZhciByZXN1bHQsIGFyZXQsIHNraXAgPSBmYWxzZTtcblxuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy51bmFyeVByZSkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLnVuYXJ5UHJlKGlpZCwgb3AsIGxlZnQpO1xuICAgICAgICAgIGlmIChhcmV0KSB7XG4gICAgICAgICAgICAgIG9wID0gYXJldC5vcDtcbiAgICAgICAgICAgICAgbGVmdCA9IGFyZXQubGVmdDtcbiAgICAgICAgICAgICAgc2tpcCA9IGFyZXQuc2tpcFxuICAgICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgaWYgKCFza2lwKSB7XG4gICAgICAgICAgc3dpdGNoIChvcCkge1xuICAgICAgICAgICAgICBjYXNlIFwiK1wiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gK2xlZnQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcIi1cIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IC1sZWZ0O1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgICAgIGNhc2UgXCJ+XCI6XG4gICAgICAgICAgICAgICAgICByZXN1bHQgPSB+bGVmdDtcbiAgICAgICAgICAgICAgICAgIGJyZWFrO1xuICAgICAgICAgICAgICBjYXNlIFwiIVwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gIWxlZnQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcInR5cGVvZlwiOlxuICAgICAgICAgICAgICAgICAgcmVzdWx0ID0gdHlwZW9mIGxlZnQ7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgY2FzZSBcInZvaWRcIjpcbiAgICAgICAgICAgICAgICAgIHJlc3VsdCA9IHZvaWQobGVmdCk7XG4gICAgICAgICAgICAgICAgICBicmVhaztcbiAgICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihvcCArIFwiIGF0IFwiICsgaWlkICsgXCIgbm90IGZvdW5kXCIpO1xuICAgICAgICAgICAgICAgICAgYnJlYWs7XG4gICAgICAgICAgfVxuICAgICAgfVxuXG4gICAgICBpZiAoc2FuZGJveC5hbmFseXNpcyAmJiBzYW5kYm94LmFuYWx5c2lzLnVuYXJ5KSB7XG4gICAgICAgICAgYXJldCA9IHNhbmRib3guYW5hbHlzaXMudW5hcnkoaWlkLCBvcCwgbGVmdCwgcmVzdWx0KTtcbiAgICAgICAgICBpZiAoYXJldCkge1xuICAgICAgICAgICAgICByZXN1bHQgPSBhcmV0LnJlc3VsdDtcbiAgICAgICAgICB9XG4gICAgICB9XG4gICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gcmVzdWx0KTtcbiAgfVxuXG4gIGZ1bmN0aW9uIHB1c2hTd2l0Y2hLZXkoKSB7XG4gICAgICBzd2l0Y2hLZXlTdGFjay5wdXNoKHN3aXRjaExlZnQpO1xuICB9XG5cbiAgZnVuY3Rpb24gcG9wU3dpdGNoS2V5KCkge1xuICAgICAgc3dpdGNoTGVmdCA9IHN3aXRjaEtleVN0YWNrLnBvcCgpO1xuICB9XG5cbiAgZnVuY3Rpb24gbGFzdCgpIHtcbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSBsYXN0VmFsKTtcbiAgfVxuXG4gIC8vIFN3aXRjaCBrZXlcbiAgLy8gRS5nLiwgZm9yICdzd2l0Y2ggKHgpIHsgLi4uIH0nLFxuICAvLyBDMSBpcyBpbnZva2VkIHdpdGggdmFsdWUgb2YgeFxuICBmdW5jdGlvbiBDMShpaWQsIGxlZnQpIHtcbiAgICAgIHN3aXRjaExlZnQgPSBsZWZ0O1xuICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IGxlZnQpO1xuICB9XG5cbiAgLy8gY2FzZSBsYWJlbCBpbnNpZGUgc3dpdGNoXG4gIGZ1bmN0aW9uIEMyKGlpZCwgcmlnaHQpIHtcbiAgICAgIHZhciBhcmV0LCByZXN1bHQ7XG5cbiAgICAgIC8vIGF2b2lkIGlpZCBjb2xsaXNpb247IGlpZCBtYXkgbm90IGhhdmUgYSBtYXAgaW4gdGhlIHNvdXJjZW1hcFxuICAgICAgcmVzdWx0ID0gQihpaWQrMSwgXCI9PT1cIiwgc3dpdGNoTGVmdCwgcmlnaHQsIGNyZWF0ZUJpdFBhdHRlcm4oZmFsc2UsIGZhbHNlLCB0cnVlKSk7XG5cbiAgICAgIGlmIChzYW5kYm94LmFuYWx5c2lzICYmIHNhbmRib3guYW5hbHlzaXMuY29uZGl0aW9uYWwpIHtcbiAgICAgICAgICBhcmV0ID0gc2FuZGJveC5hbmFseXNpcy5jb25kaXRpb25hbChpaWQsIHJlc3VsdCk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgaWYgKHJlc3VsdCAmJiAhYXJldC5yZXN1bHQpIHtcbiAgICAgICAgICAgICAgICAgIHJpZ2h0ID0gIXJpZ2h0O1xuICAgICAgICAgICAgICB9IGVsc2UgaWYgKHJlc3VsdCAmJiBhcmV0LnJlc3VsdCkge1xuICAgICAgICAgICAgICAgICAgcmlnaHQgPSBzd2l0Y2hMZWZ0O1xuICAgICAgICAgICAgICB9XG4gICAgICAgICAgfVxuICAgICAgfVxuICAgICAgcmV0dXJuIChsYXN0Q29tcHV0ZWRWYWx1ZSA9IHJpZ2h0KTtcbiAgfVxuXG4gIC8vIEV4cHJlc3Npb24gaW4gY29uZGl0aW9uYWxcbiAgZnVuY3Rpb24gQyhpaWQsIGxlZnQpIHtcbiAgICAgIHZhciBhcmV0O1xuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5jb25kaXRpb25hbCkge1xuICAgICAgICAgIGFyZXQgPSBzYW5kYm94LmFuYWx5c2lzLmNvbmRpdGlvbmFsKGlpZCwgbGVmdCk7XG4gICAgICAgICAgaWYgKGFyZXQpIHtcbiAgICAgICAgICAgICAgbGVmdCA9IGFyZXQucmVzdWx0O1xuICAgICAgICAgIH1cbiAgICAgIH1cblxuICAgICAgbGFzdFZhbCA9IGxlZnQ7XG4gICAgICByZXR1cm4gKGxhc3RDb21wdXRlZFZhbHVlID0gbGVmdCk7XG4gIH1cblxuICBmdW5jdGlvbiBTKGlpZCwgZikge1xuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5ydW5JbnN0cnVtZW50ZWRGdW5jdGlvbkJvZHkpIHtcbiAgICAgICAgICByZXR1cm4gc2FuZGJveC5hbmFseXNpcy5ydW5JbnN0cnVtZW50ZWRGdW5jdGlvbkJvZHkoaWlkLCBmLCBnZXRQcm9wU2FmZShmLCBTUEVDSUFMX1BST1BfSUlEKSwgZ2V0UHJvcFNhZmUoZiwgU1BFQ0lBTF9QUk9QX1NJRCkpO1xuICAgICAgfVxuICAgICAgcmV0dXJuIHRydWU7XG4gIH1cblxuICBmdW5jdGlvbiBMKCkge1xuICAgICAgcmV0dXJuIGxhc3RDb21wdXRlZFZhbHVlO1xuICB9XG5cblxuICBmdW5jdGlvbiBYMShpaWQsIHZhbCkge1xuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5lbmRFeHByZXNzaW9uKSB7XG4gICAgICAgICAgc2FuZGJveC5hbmFseXNpcy5lbmRFeHByZXNzaW9uKGlpZCk7XG4gICAgICB9XG5cbiAgICAgIHJldHVybiAobGFzdENvbXB1dGVkVmFsdWUgPSB2YWwpO1xuICB9XG5cbiAgZnVuY3Rpb24gZW5kRXhlY3V0aW9uKCkge1xuICAgICAgaWYgKHNhbmRib3guYW5hbHlzaXMgJiYgc2FuZGJveC5hbmFseXNpcy5lbmRFeGVjdXRpb24pIHtcbiAgICAgICAgICByZXR1cm4gc2FuZGJveC5hbmFseXNpcy5lbmRFeGVjdXRpb24oKTtcbiAgICAgIH1cbiAgfVxuXG5cbiAgZnVuY3Rpb24gbG9nKHN0cikge1xuICAgICAgaWYgKHNhbmRib3guUmVzdWx0cyAmJiBzYW5kYm94LlJlc3VsdHMuZXhlY3V0ZSkge1xuICAgICAgICAgIHNhbmRib3guUmVzdWx0cy5leGVjdXRlKGZ1bmN0aW9uKGRpdiwganF1ZXJ5LCBlZGl0b3Ipe1xuICAgICAgICAgICAgICBkaXYuYXBwZW5kKHN0citcIjxicj5cIik7XG4gICAgICAgICAgfSk7XG4gICAgICB9IGVsc2Uge1xuICAgICAgICAgIGNvbnNvbGUubG9nKHN0cik7XG4gICAgICB9XG4gIH1cblxuXG4gIC8vLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0gRW5kIEphbGFuZ2kgTGlicmFyeSBiYWNrZW5kIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4gIHNhbmRib3guVSA9IFU7IC8vIFVuYXJ5IG9wZXJhdGlvblxuICBzYW5kYm94LkIgPSBCOyAvLyBCaW5hcnkgb3BlcmF0aW9uXG4gIHNhbmRib3guQyA9IEM7IC8vIENvbmRpdGlvblxuICBzYW5kYm94LkMxID0gQzE7IC8vIFN3aXRjaCBrZXlcbiAgc2FuZGJveC5DMiA9IEMyOyAvLyBjYXNlIGxhYmVsIEMxID09PSBDMlxuICBzYW5kYm94Ll8gPSBsYXN0OyAgLy8gTGFzdCB2YWx1ZSBwYXNzZWQgdG8gQ1xuXG4gIHNhbmRib3guSCA9IEg7IC8vIGhhc2ggaW4gZm9yLWluXG4gIHNhbmRib3guSSA9IEk7IC8vIElnbm9yZSBhcmd1bWVudFxuICBzYW5kYm94LkcgPSBHOyAvLyBnZXRGaWVsZFxuICBzYW5kYm94LlAgPSBQOyAvLyBwdXRGaWVsZFxuICBzYW5kYm94LlIgPSBSOyAvLyBSZWFkXG4gIHNhbmRib3guVyA9IFc7IC8vIFdyaXRlXG4gIHNhbmRib3guTiA9IE47IC8vIEluaXRcbiAgc2FuZGJveC5UID0gVDsgLy8gb2JqZWN0L2Z1bmN0aW9uL3JlZ2V4cC9hcnJheSBMaXRlcmFsXG4gIHNhbmRib3guRiA9IEY7IC8vIEZ1bmN0aW9uIGNhbGxcbiAgc2FuZGJveC5NID0gTTsgLy8gTWV0aG9kIGNhbGxcbiAgc2FuZGJveC5BID0gQTsgLy8gTW9kaWZ5IGFuZCBhc3NpZ24gKz0sIC09IC4uLlxuICBzYW5kYm94LkZlID0gRmU7IC8vIEZ1bmN0aW9uIGVudGVyXG4gIHNhbmRib3guRnIgPSBGcjsgLy8gRnVuY3Rpb24gcmV0dXJuXG4gIHNhbmRib3guU2UgPSBTZTsgLy8gU2NyaXB0IGVudGVyXG4gIHNhbmRib3guU3IgPSBTcjsgLy8gU2NyaXB0IHJldHVyblxuICBzYW5kYm94LlJ0ID0gUnQ7IC8vIHJldHVybmVkIHZhbHVlXG4gIHNhbmRib3guVGggPSBUaDsgLy8gdGhyb3duIHZhbHVlXG4gIHNhbmRib3guUmEgPSBSYTtcbiAgc2FuZGJveC5FeCA9IEV4O1xuICBzYW5kYm94LkwgPSBMO1xuICBzYW5kYm94LlgxID0gWDE7IC8vIHRvcCBsZXZlbCBleHByZXNzaW9uXG4gIHNhbmRib3guV2kgPSBXaTsgLy8gd2l0aCBzdGF0ZW1lbnRcbiAgc2FuZGJveC5lbmRFeGVjdXRpb24gPSBlbmRFeGVjdXRpb247XG5cbiAgc2FuZGJveC5TID0gUztcblxuICBzYW5kYm94LkVWQUxfT1JHID0gRVZBTF9PUkc7XG4gIHNhbmRib3gubG9nID0gbG9nO1xufSkoSiQkKTtcblxuIiwiLy8gVGhlIG1vZHVsZSBjYWNoZVxudmFyIF9fd2VicGFja19tb2R1bGVfY2FjaGVfXyA9IHt9O1xuXG4vLyBUaGUgcmVxdWlyZSBmdW5jdGlvblxuZnVuY3Rpb24gX193ZWJwYWNrX3JlcXVpcmVfXyhtb2R1bGVJZCkge1xuXHQvLyBDaGVjayBpZiBtb2R1bGUgaXMgaW4gY2FjaGVcblx0dmFyIGNhY2hlZE1vZHVsZSA9IF9fd2VicGFja19tb2R1bGVfY2FjaGVfX1ttb2R1bGVJZF07XG5cdGlmIChjYWNoZWRNb2R1bGUgIT09IHVuZGVmaW5lZCkge1xuXHRcdHJldHVybiBjYWNoZWRNb2R1bGUuZXhwb3J0cztcblx0fVxuXHQvLyBDcmVhdGUgYSBuZXcgbW9kdWxlIChhbmQgcHV0IGl0IGludG8gdGhlIGNhY2hlKVxuXHR2YXIgbW9kdWxlID0gX193ZWJwYWNrX21vZHVsZV9jYWNoZV9fW21vZHVsZUlkXSA9IHtcblx0XHQvLyBubyBtb2R1bGUuaWQgbmVlZGVkXG5cdFx0Ly8gbm8gbW9kdWxlLmxvYWRlZCBuZWVkZWRcblx0XHRleHBvcnRzOiB7fVxuXHR9O1xuXG5cdC8vIEV4ZWN1dGUgdGhlIG1vZHVsZSBmdW5jdGlvblxuXHRfX3dlYnBhY2tfbW9kdWxlc19fW21vZHVsZUlkXShtb2R1bGUsIG1vZHVsZS5leHBvcnRzLCBfX3dlYnBhY2tfcmVxdWlyZV9fKTtcblxuXHQvLyBSZXR1cm4gdGhlIGV4cG9ydHMgb2YgdGhlIG1vZHVsZVxuXHRyZXR1cm4gbW9kdWxlLmV4cG9ydHM7XG59XG5cbiIsIi8vIElmIHdlIHVzZSBjb21tbW9uSlMgd2l0aCByZXF1aXJlLCB0aGUgd2VicGFjayB3aWxsIG5vdCByZWNvbmduaXplIHRoZSBzb3VyY2UgbWFwP1xucmVxdWlyZSgnLi9jb25maWcuanMnKTtcbnJlcXVpcmUoJy4vY29uc3RhbnRzLmpzJyk7XG5yZXF1aXJlKCcuL3J1bnRpbWUuanMnKTtcbnJlcXVpcmUoJy4vaWlkVG9Mb2NhdGlvbi5qcycpO1xuLy8gcmVxdWlyZSgnLi9hc3RVdGlsLmpzJyk7XG4vLyByZXF1aXJlKCcuL2VzbnN0cnVtZW50LmpzJyk7XG5cbi8vIGltcG9ydCAnLi9jb25maWcuanMnO1xuLy8gaW1wb3J0ICcuL2NvbnN0YW50cy5qcyc7XG4vLyBpbXBvcnQgJy4vcnVudGltZS5qcyc7XG4vLyBpbXBvcnQgJy4vaWlkVG9Mb2NhdGlvbi5qcyc7Il0sIm5hbWVzIjpbXSwic291cmNlUm9vdCI6IiJ9