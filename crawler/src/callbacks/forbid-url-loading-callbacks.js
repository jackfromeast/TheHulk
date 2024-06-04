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
    // TODO:
    // Enable the Page domain events
    // await visitor.curCDPsession.send('Page.enable');

    // // Listen to Page.frameNavigated event
    // visitor.curCDPsession.on('Page.frameNavigated', ({frame, type}) => {
    //     if (type == 'Navigation' && frame.url != visitor.curURL) {
            
    //     }
    // });
	page.evaluate(() => {
		window.addEventListener('beforeunload', (event) => {
			// cancel the event as stated by the standard.
			event.preventDefault();
			// chrome requires returnValue to be set.
			event.returnValue = 'Locking auto-page refresh for DOMC testing.';
			return "";
		});
	});
}