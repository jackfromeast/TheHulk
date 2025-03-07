module.exports = {
  manuallyInteractForeverCb
};


/**
* The callback function will wait for 1 hour for waiting user manually interact with the page.
* 
* @param {*} visitor 
* @param {*} page 
*/
async function manuallyInteractForeverCb(visitor, page){
  await page.waitForTimeout(3600000); // mauall wait for 1 hour
}