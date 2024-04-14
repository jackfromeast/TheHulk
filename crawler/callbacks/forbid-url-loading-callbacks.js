module.exports = {
    forbidURLNavigationCb
};


/**
 * The callback function will intakes the visitor and page objects as the argument
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function forbidURLNavigationCb(visitor, page){
    // Enable the Page domain events
    // await visitor.curCDPsession.send('Page.enable');

    // // Listen to Page.frameNavigated event
    // visitor.curCDPsession.on('Page.frameNavigated', ({frame, type}) => {
    //     if (type == 'Navigation' && frame.url != visitor.curURL) {
            
    //     }
    // });
    await page.setRequestInterception(true);
    page.on('request', interceptedRequest => {
        if (interceptedRequest.isNavigationRequest() && interceptedRequest.url() !== visitor.curURL) {
            // Block any navigation requests that are not to visitor.curURL
            // interceptedRequest.abort('aborted');
            this.logger.debug(`Aborted: ${interceptedRequest.url()}`);
            // Instead of aborting, redirect back to the allowed URL
            page.goto(visitor.curURL).catch(error => {
                this.logger.error(`[!] Failed to redirect back to ${visitor.curURL}: ${error}`);
            });
            interceptedRequest.abort('failed');
        } else {
            // Allow all other requests to continue
            interceptedRequest.continue();
        }
    });
}