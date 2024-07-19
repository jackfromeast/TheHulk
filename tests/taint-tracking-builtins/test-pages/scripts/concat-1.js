/**
 * @Name: concat-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString1 = J$$.wrapTaint('J');
    let taintedString2 = J$$.wrapTaint('$');
    let taintedString3 = J$$.wrapTaint('1');
    let taintedConcat = taintedString1.concat(taintedString2, taintedString3);

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedConcat}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();