/**
 * @Name: array-includes-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValue = J$$.wrapTaint('tainted');
    let arr = ["ABCD", "tainted"];

    if (arr.includes(taintedValue)){
      let scriptEle = document.createElement('script');
      scriptEle.src = `https://example.com/${taintedValue}`;
    }
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();