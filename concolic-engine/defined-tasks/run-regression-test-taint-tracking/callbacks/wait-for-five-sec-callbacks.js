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
  await page.waitForTimeout(120000); // mauall wait for 1 minutes
}