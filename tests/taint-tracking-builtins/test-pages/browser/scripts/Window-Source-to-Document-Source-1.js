/**
 * @Name: Window-Source-to-Document-Source-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    window.document.baseURL = 'https://example.com/my-script.js';
    let document = window.document;
    let url = document.baseURL;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();