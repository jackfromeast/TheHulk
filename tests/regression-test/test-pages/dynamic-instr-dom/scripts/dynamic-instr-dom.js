/**
 * @Name: innerHTML-instrument-1
 * @File: dynamic-instr-dom.js
 * @Import: Yes
 * @Refer:
 *  - URL: https://canva.com/ 
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    var a;
    document.taintedStr = "TAINTED!";
    let code = "console.log('Hello World!');a=document.taintedStr;";

    let scriptEle1 = document.createElement('script');
    scriptEle1.innerHTML = code;
    document.body.appendChild(scriptEle1);

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${a}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();


/**
 * @Name: innerHTML-instrument-2
 * @File: dynamic-instr-dom.js
 * @Import: Yes
 * @Refer:
 *  - URL: https://canva.com/ 
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    var a;
    document.taintedStr = "TAINTED!";
    let code = "<div><script>console.log('Hello World!');a=document.taintedStr;</script></div>";

    let divEle1 = document.createElement('div');
    divEle1.innerHTML = code;
    document.body.appendChild(divEle1);

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${a}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();