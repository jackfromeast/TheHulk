/**
 * @Name: Add-Custom-toString-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 * @Refer: https://www.google.com/
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValues = {oa: J$$.wrapTaint("TAINT")};
    taintedValues.toString = customToString;

    let taintedSrc = taintedValues + ".js";
    
    // Create a new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedSrc}`;

  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }

  function customToString() {
    return this.oa;
  }
})();