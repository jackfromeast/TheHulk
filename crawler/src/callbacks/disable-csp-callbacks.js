module.exports = {
  disableCSPCb
};

/**
 * The callback function will intakes the visitor and page objects as the argument
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function disableCSPCb(visitor, page){
  await page.setBypassCSP(true);
}