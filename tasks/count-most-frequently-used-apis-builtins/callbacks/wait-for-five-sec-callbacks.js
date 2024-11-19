module.exports = {
  waitForFiveSecCb
};


/**
* The callback function will wait for 2 minutes for waiting user manually interact with the page.
* 
* @param {*} visitor 
* @param {*} page 
*/
async function waitForFiveSecCb(visitor, page){
  await page.waitForTimeout(10000); // manually wait for 1 minutes
}