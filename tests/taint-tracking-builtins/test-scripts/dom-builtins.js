/**
 * @Name: innerHTML-instrument-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
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
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
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
