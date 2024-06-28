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
    let taintedValue = J$$.wrapTaint(taintedValues);

    // Create a new script element
    let scriptEle = document.createElement('script');

    // Use fromCharCode to convert tainted values to a string
    let taintedSrc = String.fromCharCode.apply(null, taintedValue);

    // Set the src of the new script element
    scriptEle.src = taintedSrc;

    // Append the new script element to the body (optional, if needed for testing the sink)
    document.body.appendChild(scriptEle);
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();