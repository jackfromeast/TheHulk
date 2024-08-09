/**
 * @Name: TrustedTypes-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    const scriptPolicy = trustedTypes.createPolicy('default', {
      createScriptURL: (url) => {
        return url; // Original implementation
      }
    });

    const taintedUrl = J$$.wrapTaint("https://example.com/my-script.js");
    const sanitized = scriptPolicy.createScriptURL(taintedUrl);

    let scriptEle = document.createElement('script');
    scriptEle.src = sanitized;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();