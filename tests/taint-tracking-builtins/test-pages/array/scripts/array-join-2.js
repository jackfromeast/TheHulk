/**
 * @Name: array-join-2
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValue = J$$.wrapTaint(["tainted1", "tainted2"]);
    let taintedResult = taintedValue.join('');

    if (taintedResult.includes("TaintValue")){
      throw new Error("The toString method of TaintValue should not be called.");
    }

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedValue}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();