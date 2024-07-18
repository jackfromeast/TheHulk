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

import { TaintHelper } from '../taint-helper.js';
import { Utils } from '../utils/util.js';

export class CountMostFrequentlyUsedBuiltinsAnalysis {
  constructor(sandbox) {
    // api:count
    this.collectBuiltins = {};
  }

  /**
   * This callback is called before a function, method, or constructor invocation.
   * Note that a method invocation also triggers a {@link MyAnalysis#getFieldPre} and a
   * {@link MyAnalysis#getField} callbacks.
   *
   * @example
   * y.f(a, b, c)
   *
   * // the above call roughly gets instrumented as follows:
   *
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
   * @param {number} iid - Static unique instruction identifier of this callback
   * @param {function} f - The function object that going to be invoked
   * @param {object} base - The receiver object for the function <tt>f</tt>
   * @param {Array} args - The array of arguments passed to <tt>f</tt>
   * @param {boolean} isConstructor - True if <tt>f</tt> is invoked as a constructor
   * @param {boolean} isMethod - True if <tt>f</tt> is invoked as a method
   * @param {number} functionIid - The iid (i.e. the unique instruction identifier) where the function was created
   * @param {number} functionSid - The sid (i.e. the unique script identifier) where the function was created
   * {@link MyAnalysis#functionEnter} when the function <tt>f</tt> is executed.  The <tt>functionIid</tt> can be
   * treated as the static identifier of the function <tt>f</tt>.  Note that a given function code block can
   * create several function objects, but each such object has a common <tt>functionIid</tt>, which is the iid
   * that is passed to {@link MyAnalysis#functionEnter} when the function executes.
   * @returns {{f: function, base: Object, args: Array, skip: boolean}|undefined} - If an object is returned and
   * the <tt>skip</tt> property of the object is true, then the invocation operation is skipped.
   * Original <tt>f</tt>, <tt>base</tt>, and <tt>args</tt> are replaced with that from the returned object if
   * an object is returned.
   *
   */
  invokeFunPre (iid, f, base, args, isConstructor, isMethod, functionIid, functionSid) {
    if (f && Utils.isNativeFunction(f)) {
      let fullName = "unknown";

      if (base && base.constructor && base.constructor.name) {
        fullName = `${base.constructor.name}.${f.name}`;
      }

      if (this.collectBuiltins[fullName]) {
        this.collectBuiltins[fullName]++;
      } else {
        this.collectBuiltins[fullName] = 1;
      }

      console.log("Builtins has been called: ", fullName);
    }

    base = TaintHelper.rconcrete(base);
    args = TaintHelper.rconcrete(args);

    return {f: f, base: base, args: args, skip: false};
  };
}
