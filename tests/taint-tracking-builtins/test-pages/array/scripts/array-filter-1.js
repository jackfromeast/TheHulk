/**
 * @Name: array-filter-1
 * @SourceType: ManuallyAdded
 * @SourceCode: J$$.wrapTaint()
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */
(function() {
  if (typeof J$$ !== 'undefined' && J$$.wrapTaint) {
    
    let arr = [1, 2, 3];
    let filteredArr = arr.filter(foo);

    function foo(val) {
      return J$$.wrapTaint(false);
    }

    if (filteredArr.length == 0) {
      let taintedResult = J$$.wrapTaint('tainted');
      let scriptEle = document.createElement('script');
      scriptEle.src = `https://example.com/${taintedResult}`;
    }

  } else {
    console.error("J$$ is not defined or does not have wrapTaint method.");
  }
})();