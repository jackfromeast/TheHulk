/**
 * @Name: localeCompare-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString1 = J$$.wrapTaint('example');
    let taintedString2 = J$$.wrapTaint('Example');
    let taintedComparison = taintedString1.localeCompare(taintedString2);

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedComparison}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();