/**
 * @Name: json-parse-stringify-multi-layer-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedJSON = J$$.wrapTaint('{"outer": {"inner": {"key": "taintedValue"}}}');
    let parsedObject = JSON.parse(taintedJSON);
    let jsonString = JSON.stringify(parsedObject);
    let taintedResult = jsonString;

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedResult}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();