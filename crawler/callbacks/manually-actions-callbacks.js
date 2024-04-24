module.exports = {
    manuallyInteractCb
};


/**
 * The callback function will wait for 2 minutes for waiting user manually interact with the page.
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function manuallyInteractCb(visitor, page){
    await page.waitForTimeout(900000); // mauall wait for 30 minutes
}