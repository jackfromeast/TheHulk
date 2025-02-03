/**
 * @Name: promise-resolve-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValue = J$$.wrapTaint('tainted');
    let promise = Promise.resolve(taintedValue);

    promise.then(taintedResult => {
      let scriptEle = document.createElement('script');
      scriptEle.src = `https://example.com/${taintedResult}`;
    });
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();