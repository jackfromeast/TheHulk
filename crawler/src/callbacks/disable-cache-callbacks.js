module.exports = {
  disableDiskCacheCb
};

/**
 * The callback function will intakes the visitor and page objects as the argument
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function disableDiskCacheCb(visitor, page){
  await visitor.curCDPsession.send('Network.setCacheDisabled', {
    cacheDisabled: true,
  });
  await page.setCacheEnabled(false);
}