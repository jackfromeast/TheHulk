/**
 * @Name: json-parse-multi-layer-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedJSON = J$$.wrapTaint('{"outer": {"inner": {"key": "taintedValue"}}}');
    let parsedObject = JSON.parse(taintedJSON);
    let taintedResult = parsedObject.outer.inner.key;

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedResult}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: json-parse-multi-layer-2
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedJSON = J$$.wrapTaint('{"outer": {"inner": {"key": "<script>alert(\'XSS\')</script>"}}}');
    let parsedObject = JSON.parse(taintedJSON);
    let taintedResult = parsedObject.outer.inner.key;

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedResult}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

/**
 * @Name: json-stringify-multi-layer-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValue = J$$.wrapTaint("taintedValue");
    let taintedObject = { outer: { inner: { key: taintedValue } } };
    let jsonString = JSON.stringify(taintedObject);
    let taintedResult = jsonString;

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedResult}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();

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