/**
 * @Name: slice-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1');
    let taintedSlice = taintedString.slice(J$$.wrapTaint(0), J$$.wrapTaint(7));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedSlice}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();