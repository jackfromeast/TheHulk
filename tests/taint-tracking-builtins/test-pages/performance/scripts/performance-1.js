/**
 * @Name: performance-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    const myClickEvent = J$$.wrapTaint({ timeStamp: 12345 });
    const myMarker = J$$.wrapTaint({ startTime: 67890 });
    const taintedDetail = J$$.wrapTaint("Login button clicked");

    performance.measure("login-click", {
      detail: taintedDetail,
      start: myClickEvent.timeStamp,
      end: myMarker.startTime
    });

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${J$$.wrapTaint("login-click")}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();