/**
 * @Name: proxy-getter-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    let taintedValue = { a: J$$.wrapTaint('tainted') };
    const handler = {
      get(target, prop, receiver) {
        return Reflect.get(...arguments);
      },
    };
    
    let proxy = new Proxy(taintedValue, handler);
    let taintedResult = proxy.a;

    let scriptEle = document.createElement('script');
    scriptEle.src = `https://example.com/${taintedResult}`;
  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();