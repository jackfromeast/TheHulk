/**
 * @Name: fromCharCode-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValues = [74, 36, 49]; // Example ASCII values for 'J', '$', '1'
    taintedValues = J$$.wrapTaint(taintedValues);

    // Create a new script element
    let scriptEle = document.createElement('script');

    // Use fromCharCode to convert tainted values to a string
    let taintedSrc = String.fromCharCode.apply(null, taintedValues);
    // taintedSrc = String.fromCharCode(taintedValues[0], taintedValues[1], taintedValues[2]);
    // taintedSrc = String.fromCharCode.call(null, taintedValues[0], taintedValues[1], taintedValues[2]);
    // Set the src of the new script element
    scriptEle.src = `https://example.com/${taintedSrc}`;

  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();