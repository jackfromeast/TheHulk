/**
 * @Name: matchAll-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedString = J$$.wrapTaint('exampleJ$1exampleJ$2');
    let taintedMatches = Array.from(taintedString.matchAll(J$$.wrapTaint(/J\$\d/g)));

    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedMatches.join()}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();