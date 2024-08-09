/**
 * @Name: instrument-dynamic-2
 * @File: dynamic-instr-eval.js
 * @Import: Yes
 */
(async function () {
  const codeToInstrument = `
    (function foo(x) {
      with (this) {
        console.log(x+1);
      }
    })(2); // Provide an argument for the function call
  `;

  eval(codeToInstrument);
})();

/**
 * @Name: instrument-dynamic-3
 * @File: dynamic-instr-eval.js
 * @Import: Yes
 */
(async function () {
  with ({a: 1}) {
    console.log(a);
  }
})();