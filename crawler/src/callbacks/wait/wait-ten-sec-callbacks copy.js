module.exports = {
  waitForTenSecCb
};


/**
* The callback function will wait for 1 hour for waiting user manually interact with the page.
* 
* @param {*} visitor 
* @param {*} page 
*/
async function waitForTenSecCb(visitor, page){
  await page.waitForTimeout(10000); // mauall wait for 10 sec
}