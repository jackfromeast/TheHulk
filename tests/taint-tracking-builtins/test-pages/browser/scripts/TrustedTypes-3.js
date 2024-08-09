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