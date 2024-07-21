/**
 * @Name: instrument-dynamic-1
 * @File: dynamic-instr-eval.js
 * @Import: Yes
 */
(async function () {
  const codeToInstrument = `
    function foo(x) {
      return x + 1;
    }

    console.log(foo(41));
  `;

  eval(codeToInstrument);
})();