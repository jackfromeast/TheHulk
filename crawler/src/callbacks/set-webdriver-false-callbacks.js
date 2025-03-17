module.exports = {
  disableWebdriverCheckCb
};

/**
 * The callback function will intakes the visitor and page objects as the argument
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function disableWebdriverCheckCb(visitor, page){
  let disableScript = "Object.defineProperty(navigator, 'webdriver', { get: () => false, });";
  visitor.context.addInitScript({ content: disableScript });
}