/**
 * @Name: instrument-dynamic-1
 * @File: dynamic-instr-func.js
 * @Import: Yes
 */
(async function () {
  const codeToInstrument = `
    function foo(x) {
      return x + 1;
    }

    console.log(foo(41));
  `;

  new Function(codeToInstrument)();
})();