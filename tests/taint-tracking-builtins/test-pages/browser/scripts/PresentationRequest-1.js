/**
 * @Name: PresentationRequest-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValue = [J$$.wrapTaint('https://google.com')];
    let presentationRequest = new PresentationRequest(taintedValue);

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedValue[0]}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();