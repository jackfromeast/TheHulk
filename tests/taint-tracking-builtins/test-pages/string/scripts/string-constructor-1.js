/**
 * @Name: string-constructor-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  // Check if J$$ exists
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValues = J$$.wrapTaint("HELLOWORLD");

    let scriptEle = document.createElement('script');

    let taintedSrc = new String(taintedValues);

    if (taintedSrc.includes("TaintValue")) {
      throw new Error("Tainted value found in src");
    }
    // Set the src of the new script element
    scriptEle.src = `https://example.com/${taintedSrc}`;

  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();