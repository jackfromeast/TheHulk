/**
 * @Name: valueOf-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1');
    let taintedValue = taintedString.valueOf();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedValue}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();