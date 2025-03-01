/**
 * @Name: fromCharCode-2
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValue_1 = J$$.wrapTaint(74);
    let taintedValue_2 = J$$.wrapTaint(36);
    let taintedValue_3 = J$$.wrapTaint(49);

    // Create a new script element
    let scriptEle = document.createElement('script');

    // Use fromCharCode to convert tainted values to a string
    let taintedSrc = String.fromCharCode.apply(null, [taintedValue_1, taintedValue_2, taintedValue_3]);

    // Set the src of the new script element
    scriptEle.src = `https://example.com/${taintedSrc}`;;

  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();