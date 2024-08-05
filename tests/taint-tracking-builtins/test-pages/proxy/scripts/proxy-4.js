/**
 * @Name: proxy-4
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    // Check taint of a proxy could be a bit tricky
    let taintedValue = { a: 'tainted' };
    const handler = {
      get(target, prop, receiver) {
        return "HELLOWORLD";
      },
    };

    let proxy = new Proxy(taintedValue, handler);

    if (J$$.isTainted(proxy)) {
      throw new Error("Not a Tainted value!");
    }

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${J$$.wrapTaint(proxy.a)}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();