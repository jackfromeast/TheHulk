/**
 * @Name: fromCodePoint-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedCodePoints = [74, 36, 49];
    taintedCodePoints = J$$.wrapTaint(taintedCodePoints);

    // Create a new script element
    let scriptEle = document.createElement('script');
    let taintedSrc = String.fromCodePoint.apply(null, taintedCodePoints);
    scriptEle.src = `https://example.com/${taintedSrc}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();