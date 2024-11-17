module.exports = {
  WaitForFiveSecCb
};


/**
* The callback function will wait for 1 hour for waiting user manually interact with the page.
* 
* @param {*} visitor 
* @param {*} page 
*/
async function WaitForFiveSecCb(visitor, page){
  await page.waitForTimeout(5000); // mauall wait for 1 hour
}