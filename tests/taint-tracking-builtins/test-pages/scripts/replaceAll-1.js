/**
 * @Name: replaceAll-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1exampleJ$1');
    let taintedReplaced = taintedString.replaceAll(J$$.wrapTaint('J$1'), J$$.wrapTaint('J$$'));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedReplaced}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();