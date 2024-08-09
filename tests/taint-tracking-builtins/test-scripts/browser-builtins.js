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


/**
 * @Name: PresentationRequest-2
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValue = J$$.wrapTaint('https://google.com');
    let presentationRequest = new PresentationRequest(taintedValue);

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedValue}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();


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


/**
 * @Name: TrustedTypes-3
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: element.innerHTML
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    // Create a policy for TrustedHTML
    const htmlPolicy = trustedTypes.createPolicy('default', {
      createHTML: (htmlContent) => {
        return htmlContent; // Original implementation
      }
    });

    const taintedHtmlContent = J$$.wrapTaint("<img src='x' onerror='alert(\"XSS via TrustedHTML\")'>");
    const sanitizedHtml = htmlPolicy.createHTML(taintedHtmlContent);

    let divEle = document.createElement('div');
    divEle.innerHTML = sanitizedHtml; // Assign sanitized HTML content
    document.body.appendChild(divEle); // Append to the document
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();
