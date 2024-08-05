/**
 * @Name: string-constructor-2
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValues = J$$.wrapTaint('false');

    let taintedSrc = String(taintedValues);

    if (taintedSrc.includes("TaintValue")) {
      throw new Error("Tainted value found in src");
    }

    if (typeof taintedSrc !== 'string') {
      throw new Error("taintedSrc should not be an object");
    }

    // Set the src of the new script element
    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedSrc}`;

  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();