/**
 * @Name: type-module-strict
 * @File: type-module-1.js
 * @Import: Yes
 * @Type: module
 * @Refer: 
 *  - URL: https://www.gandi.net/en-US
 */
(function() {
  (function() {
    var e = {
      856: function _(e) {
        e.exports = function() {
                "use strict";
                function e(e) {
                    if (Array.isArray(e)) {
                        for (var t = 0, n = Array(e.length); t < e.length; t++) n[t] = e[t];
                        return n;
                    }
                    return Array.from(e);
                }
                var t = Object.hasOwnProperty,
                    n = Object.setPrototypeOf,
                    o = Object.isFrozen,
                    i = Object.getPrototypeOf,
                    r = Object.getOwnPropertyDescriptor,
                    s = Object.freeze,
                    a = Object.seal,
                    c = Object.create,
                    l = "undefined" != typeof Reflect && Reflect,
                    d = l.apply,
                    u = l.construct;
              }
            }};
      e[856](e);
    })();
})();