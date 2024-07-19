/**
 * @Name: toLocaleUpperCase-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('j$1example');
    let taintedUpperCase = taintedString.toLocaleUpperCase();

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedUpperCase}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();