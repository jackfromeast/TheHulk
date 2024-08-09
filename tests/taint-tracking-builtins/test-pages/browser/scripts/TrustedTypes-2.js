/**
 * @Name: TrustedTypes-2
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: script.text
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    // Create a policy for TrustedScript
    const scriptPolicy = trustedTypes.createPolicy('default', {
      createScript: (scriptContent) => {
        return scriptContent; // Original implementation
      }
    });

    const taintedScriptContent = J$$.wrapTaint("alert('XSS via TrustedScript');");
    const sanitizedScript = scriptPolicy.createScript(taintedScriptContent);

    let scriptEle = document.createElement('script');
    scriptEle.type = 'application/javascript';
    scriptEle.text = sanitizedScript; 
    document.body.appendChild(scriptEle); // Append to the document
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();