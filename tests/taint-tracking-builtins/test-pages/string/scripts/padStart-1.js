/**
 * @Name: padStart-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('J$1');
    let taintedPadded = taintedString.padStart(J$$.wrapTaint(10), J$$.wrapTaint('x'));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedPadded}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();