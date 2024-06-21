/**
 * Third-party libraries
 */
// const puppeteer = require('puppeteer');
const fs = require('fs');
const pathModule = require('path');
const elapsed = require("elapsed-time-logger");
const utils = require('./utils.js');
const Logger = require('./logger');
const path = require('path');
const { warn } = require('console');

const puppeteer = require('puppeteer-extra')
const StealthPlugin = require('puppeteer-extra-plugin-stealth')
puppeteer.use(StealthPlugin())

/**
 * 
 * Description:
 * --------------------------------
 * Visitor class
 * handles the visiting of a given domain within a tab
 * it may visit multiple pages within the domain
 * it collects the webpage data based on the configuration and installed callbacks
 * 
 * Limitations:
 * --------------------------------
 * TODO: the visitor will contains the webpage states if needed
 * 
 * Parameters:
 * --------------------------------
 * @param {*} config: the configuareation of the crawler
 * @param {*} url
 * @param {*} domain
 * @param {*} basedir: the directory where the data will be stored
 * @param {list} beforeCbs: the callbacks to be executed before goto the webpage
 * @param {list} afterCbs: the callbacks to be executed after page load
 */
function Visitor(config, url, domain, basedir, maxurls, beforeLoadCbs, userActionCbs, afterLoadCbs, postVisitCbs){
	this.config = config;

	if (config.navigator.BROWSER === "chrome"){
		this.browserExecutablePath = config.chrome.CHROME_EXECUTABLE_PATH;
		this.browserFlags = config.chrome.CHROME_FLAGS;
		this.browserHeadless = config.chrome.HEADLESS;
		this.browserDevtools = config.chrome.DEVTOOLS;
	} else if (config.navigator.BROWSER === "foxhound") {
		this.browserExecutablePath = config.foxhound.FOXHOUND_EXECUTABLE_PATH;
		this.browserFlags = config.foxhound.FOXHOUND_FLAGS;
		this.browserHeadless = config.foxhound.HEADLESS;
		this.browserDevtools = config.chrome.DEVTOOLS;
	} else {
		throw "Configuration Error: Not chrome or foxhound. BROWSER is not supported!"
	}

	this.logger = undefined;
	this.browser = undefined;
	this.startURL = url;
	this.domain = domain;
	this.basedir = basedir;
	this.maxURLNum = maxurls;

	// Remember to update the following data structures when visiting a new page
	this.unvisited = [url];
	this.visited = [];
	this.curURL = url;
	this.curURLHash = utils.hashURL(url);
	this.curCDPsession = undefined;

	// collected data
	this.collected = {}

	// callbacks
	this.beforeLoadCbs = beforeLoadCbs ? beforeLoadCbs : [];
	this.userActionCbs = userActionCbs ? userActionCbs : [];
	this.afterLoadCbs = afterLoadCbs ? afterLoadCbs : [];
	this.postVisitCbs = postVisitCbs ? postVisitCbs : [];

	this.webpageSourceFolder = undefined;
	this.webpageCrawlerFolder = undefined;
}

/**
 * Recursively visit the website based on unvisited URLs and maxVisitedUrls
 * 
 * 1/ pick a URL from unvisited list
 * 2/ visit the URL
 * 3/ save the collected data to the disk and update the frontier
 * 4/ go to step 1
 * 
 * Besides, if visitAPage fails, it will close the browser and re-launch a new one
 */
Visitor.prototype.visit = async function(){
	this.browser = await this.launch_puppeteer();
	const globalTimer = elapsed.start('global_crawling_timer');

	while(true){
		// pick a URL from unvisited list
		this.curURL = this.unvisited[0];
		this.curURLHash = utils.hashURL(this.curURL);

		this.collected.curURLHash = this.emptyCollectData();

		this.updateFileDirectory();
		this.updateLogger();

		// visit the URL
		await this.visitPage();

		// save the collected data to the disk
		await this.saveWebPageData();
		await this.saveCrawlerData();

		// Run the post visit callbacks
		for (let cb of this.postVisitCbs){
			await cb(this);
		}

		this.visited.push(this.curURL); // add the current URL to the visited list
		this.unvisited.shift(); // remove the current URL from the unvisited list

		// termination criteria
		if(this.visited.length >= this.maxURLNum){
			this.logger.debug('Max urls visited, exiting.');
			break;
		}

		if(this.unvisited.length === 0){
			this.logger.debug(' No unvisited URL, exiting.');
			break;
		}
	}

	try{
		await this.browser.close();
	}
	catch(e){
		this.logger.error(e);
	}

	const globalTime = globalTimer.get();
	// _ = globalTimer.end();

	// store elapsed time to disk
	fs.writeFileSync(pathModule.join(this.basedir, "time.crawling.out"), JSON.stringify({
		"crawling_time": globalTime,
	}));

	this.logger.debug('Done visiting the website: ' + this.domain + ' in ' + globalTime);
}

Visitor.prototype.visitPage = async function(){
	let page = await this.browser.newPage();

	// this.disableCSP(page);
	await page.setViewport({ width: 4096, height: 2048});

	try{
		/*
		*  ----------------------------------------------
		*  [PreLoading] Install the Event Handlers 
		*  ----------------------------------------------
		*/
		this.curCDPsession = await this.setupCDP(page);
		if (this.config.collector.COLLECT_CONSOLE_LOGS){ this.collectConsoleLogs(page); }
		if (this.config.collector.COLLECT_BROWSER_STDOUT){ this.collectBrowserStdout(); }
		if (this.config.collector.COLLECT_BROWSER_STDERR){ this.collectBrowserStderr(); }

		// Run the before callbacks which can redefine event handlers above
		for(let cb of this.beforeLoadCbs){
			await cb(this, page);
		}

		this.logger.debug("Visiting URL: " + this.curURL);
        
		/*
		*  ----------------------------------------------
		*  [Navigation] Navigate to the URL 
		*  ----------------------------------------------
		*/
		await this.navigate(page);

		/*
		*  ----------------------------------------------
		*  [PageLoaded] Start performing any actions 
		*  ----------------------------------------------
		*/
		// If we arrive here, the navigation succeeded
		this.logger.debug("Successfully loading the website: " + this.curURL);
		await page.evaluate(() => console.log('[CRAWLER] Page loaded successfully!'));

		/**
		 * ----------------------------------------------
		 * [UserActions] Perform the User Actions
		 * ----------------------------------------------
		 */
		for (let cb of this.userActionCbs){
			await cb(this, page);
		}
		
		/*
		*  ----------------------------------------------
		*  [PostLoading] Collect the Cralwer Data 
		*  ----------------------------------------------
		*/

		if (this.config.collector.COLLECT_WEB_STORAGE){ this.collectWebStorageData(page); }
		if (this.config.collector.COLLECT_COOKIES){ this.collectCookie(page);}

		// Run the after callbacks to collect more data
		// E.g. collect the domc lookups
		for (let cb of this.afterLoadCbs){
			await cb(this);
		}

		/*
		*  ----------------------------------------------
		*  [Next] Collect the Alternative URLs
		*  ----------------------------------------------
		*/
		if  (this.config.collector.COLLECT_ALT_URLS){ await this.collectAltURLs(page); }
		
		page.waitForTimeout(this.config.collector.WAIT_BEFORE_NEXT_URL); // wait for 3 seconds before closing the page
		await page.close();

	}catch(e){
		if (e.message.includes('Navigation timeout of')){
			this.logger.error('TimeoutError: Navigation timeout exceeded for URL: ' + this.curURL);
		}else if (e.message.includes('net::ERR_CONNECTION_REFUSED')){
			this.logger.error('ConnectionRefusedError: ERR_CONNECTION_REFUSED for URL: ' + this.curURL);
		}else if (e.message.includes('net::ERR_NAME_NOT_RESOLVED')){
			this.logger.error('DomainNameError: ERR_NAME_NOT_RESOLVED for URL: ' + this.curURL);
		}else if (e.message.includes('ERR_HTTP2_PROTOCOL_ERROR')){
			this.logger.error('HTTP2ProtocolError: ERR_HTTP2_PROTOCOL_ERROR for URL: ' + this.curURL);
		}else if (e.message.includes('ERR_CONNECTION_CLOSED')){
			this.logger.warn('ERR_CONNECTION_CLOSED: for URL: ' + this.curURL);
		}else if (e.message.includes('ERR_TUNNEL_CONNECTION_FAILED')){
			this.logger.warn('TunnelConnectionError: ERR_TUNNEL_CONNECTION_FAILED for URL: ' + this.curURL);
		}
		else{
			this.logger.error(e);
		}
		// utils.logError(e, this.basedir);
		try{
			// close the previous browser
			await page.close();
			await browser.close()
		}catch{
			// PASS
		}
	}
}

/**
 * This function will navigate to the URL in a step-down manner
 * 
 * We want detect the unreachable page as reailable as possible to avoid the timeout error
 * For other pages, We want the page to be fully loaded as much as possible to catch all the resources 
 * 
 * The following steps is nolonger used:
 * domcontentloaded or load is hard to trigger for some pages
 * 
 * TODO: How to distinguish the unreachable page and the page that is still loading?
 * e.g. qq.com and 000webhostapp.com
 * 
 * It will first probe the page with ['load', 'domcontentloaded'] in 15 seconds
 * If it succeeds, we proceed to the page with ['load', 'domcontentloaded', 'networkidle2'] in 90 seconds which can catch more resources
 * If it raises Navigation timeout, we will log/ignore the error and continue the following steps 
 * 
 */
Visitor.prototype.navigate = async function(page){
	try {
		// Waits till there are no more than 2 network connections for at least `500`* ms.
		// We don't use 'networkidle0' because some pages never stop loading/interacting with the network
		this.refreshCollectData();
		if (this.config.navigator["NAVIGATION_WAIT_UNTIL"]){
			await page.goto(this.curURL, 
				{waitUntil: this.config.navigator["NAVIGATION_WAIT_UNTIL"], timeout: this.config.navigator["NAVIGATION_TIMEOUT"]});
		}else{
			await page.goto(this.curURL, {waitUntil: ['networkidle2'], timeout: this.config.navigator["NAVIGATION_TIMEOUT"]});
		}
	} catch (e) {
		if (e.message.includes('Navigation timeout')){
			this.logger.error('Navigation timeout exceeded for URL (Not Fatal): ' + this.curURL);
		}else{
			throw e;
		}
	}
}

Visitor.prototype.emptyCollectData = function() {
	return {
		'htmls': [],
		'scripts': [],
		'css': [],
		'cookies': [],
		'webStorageData': {},
		'httpRequests': [],
		'XHRRequests': [],
		'FetchRequests': [],
		'consoleLogs': [],
		'browserStdout': [],
		'browserStderr': [],
		'taintflows': [],
		'crawlerErrors': [],
	};
}

Visitor.prototype.refreshCollectData = function() {
	this.collected.curURLHash = this.emptyCollectData();
}

// Visitor.prototype.disableCSP = async function(page){
// 	await page.setBypassCSP(true);
// }

Visitor.prototype.setupCDP = async function(page){
	
	let CDPsession = await page.target().createCDPSession();

	try{
		await CDPsession.send('Debugger.enable');
		await CDPsession.send('Runtime.enable');
		await CDPsession.send('Page.enable');
		
		await CDPsession.send("Fetch.enable", {
			handleAuthRequests: true,
			patterns: [{ requestStage: "Response" }]
		});

		await CDPsession.on('Fetch.requestPaused', async ({requestId, request, _, resourceType, responseErrorReason, responseStatusCode, responseStatusText, responseHeaders}) => {
			// logger.debug(`Request will be sent for ${requestId} with url: ${request.url} with resource type: ${resourceType}`);

			if (responseErrorReason == 'Failed'){
				try{
					await CDPsession.send('Fetch.continueRequest', { requestId });
				}catch(e){
					if (e.message.includes('Session closed. ') || e.message.includes('Target closed.')){
						this.logger.debug('ProtocolError (Due to domain unreachable): CDP (Fetch.continueRequest) failed for URL: ' + this.curURL);
					}else if (e.message.includes('Invalid InterceptionId.')){
						this.logger.debug('ProtocolError failed (Invalid InterceptionId.): ' + this.curURL);
					}else{
						this.logger.error(e);
					}
				}
				// log the error;
				return;
			}

			// Handle the redirection
			if (responseStatusCode == '301' || responseStatusCode == '302' || responseStatusCode == '303' || responseStatusCode == '307' || responseStatusCode == '308'){
				try{
					await CDPsession.send('Fetch.continueRequest', { requestId });
				}catch(e){
					if (e.message.includes('Session closed. ') || e.message.includes('Target closed.')){
						this.logger.debug('ProtocolError (Due to domain unreachable): CDP (Fetch.continueRequest) failed for URL: ' + this.curURL);
					}else if (e.message.includes('Invalid InterceptionId.')){
						this.logger.debug('ProtocolError failed (Invalid InterceptionId.): ' + this.curURL);
					}else{
						this.logger.error(e);
					}
				}
				return;
			}

			try{
				if (resourceType === 'Document' || resourceType === 'Stylesheet' || resourceType === 'Other' || resourceType === 'Script'){
					const response = await CDPsession.send('Fetch.getResponseBody', { requestId });

					if (request.url.endsWith('.ico')){
						return;
					}

					// The main page sometimes will has resourceType as 'Other'
					if (this.config.collector.COLLECT_HTML && resourceType === 'Document' || resourceType === 'Other'){
						this.collected.curURLHash.htmls.push({url: request.url,
															 source: response.body});
					}else if (this.config.collector.COLLECT_CSS && resourceType === 'Stylesheet'){
						this.collected.curURLHash.css.push({url: request.url,
															source: response.body});
					}else if (this.config.collector.COLLECT_SCRIPTS && resourceType === 'Script'){
						this.collected.curURLHash.scripts.push({
							scriptId: request.scriptId,
							url: request.url,
							executionContextId: request.executionContextId,
							source: response.body
						});
					}

				}

				if (this.config.collector.COLLECT_XHR_REQUESTS && resourceType === 'XHR'){
					this.collected.curURLHash.XHRRequests.push({url: request.url, method: request.method, headers: request.headers});
				}

				if (this.config.collector.COLLECT_FETCH_REQUESTS && resourceType === 'Fetch'){
					this.collected.curURLHash.FetchRequests.push({url: request.url, method: request.method, headers: request.headers});
				}

				try{
					await CDPsession.send('Fetch.continueRequest', { requestId });
				}catch(e){
					if (e.message.includes('Session closed. ') || e.message.includes('Target closed.')){
						this.logger.debug('ProtocolError (Due to domain unreachable): CDP (Fetch.continueRequest) failed for URL: ' + this.curURL);
					}else if (e.message.includes('Invalid InterceptionId.')){
						this.logger.debug('ProtocolError failed (Invalid InterceptionId.): ' + this.curURL);
					}else{
						this.logger.error(e);
					}
				}

			}catch(e){
				this.logger.error(`Error fetching ${request.url} {request id: ${requestId}} with resource type: ${resourceType}, `, e.message);
				// this.logger.error(`responseErrorReason: ${responseErrorReason}, responseStatusCode: ${responseStatusCode}, responseStatusText: ${responseStatusText}`)
				try{
					await CDPsession.send('Fetch.continueRequest', { requestId });
				}catch(e){
					if (e.message.includes('Session closed. ') || e.message.includes('Target closed.')){
						this.logger.debug('ProtocolError (Due to domain unreachable): CDP (Fetch.continueRequest) failed for URL: ' + this.curURL);
					}else if (e.message.includes('Invalid InterceptionId.')){
						this.logger.debug('ProtocolError failed (Invalid InterceptionId.): ' + this.curURL);
					}else{
						this.logger.error(e);
					}
				}
			}
		});
	}catch(e){
		if (e.message.includes('Protocol error (Runtime.enable)')){
			this.logger.debug('ProtocolError (Due to domain unreachable): CDP (Runtime.enable) failed for URL: ' + this.curURL);
		}else{
			this.logger.error(e);
			this.logger.error('Setting up CDP failed for URL: ' + this.curURL);
		}
	}

	return CDPsession;
}

Visitor.prototype.collectConsoleLogs = async function(page){
	page.on('console', consoleObj => {
		this.collected.curURLHash.consoleLogs.push(consoleObj.text());
	})

}

Visitor.prototype.collectBrowserStdout = async function(){
	this.browser.process().stdout.on('data', (data) => {
		this.collected.curURLHash.browserStdout.push(data.toString());	
	});
}

Visitor.prototype.collectBrowserStderr = async function(){
	this.browser.process().stderr.on('data', (data) => {
		this.collected.curURLHash.browserStderr.push(data.toString());	
	})
}

Visitor.prototype.collectWebStorageData = async function(page){
	await page.evaluate( () => {
			
		function getWebStorageData() {
			let storage = {};
			let keys = Object.keys(window.localStorage);
			let i = keys.length;
			while ( i-- ) {
				storage[keys[i]] = window.localStorage.getItem(keys[i]);
			}
			return storage;
		}

		let webStorageData = getWebStorageData();
		this.collected.curURLHash.webStorageData = webStorageData;
	});
}

Visitor.prototype.collectCookie = async function(page){
	let colletedCookies = await page.cookies();
	this.collected.curURLHash.cookies = colletedCookies;
}

Visitor.prototype.collectAltURLs = async function(page){
	let hrefs = await page.$$eval('a', as => as.map(a => a.href));
	for(let href of hrefs){
		// check if href belong to the same eTLD+1 / domain
		// see: https://www.npmjs.com/package/psl
		if(href.includes(this.domain) && utils.isValid(href)){
			if(this.unvisited.indexOf(href) === -1){
				this.unvisited.push(href);
			}
		}
	}
}

Visitor.prototype.saveWebPageData = async function(){
	let fileMap = {}; // for storing the file path of the collected data
	if (this.config.collector.COLLECT_HTML){
		for (let html of this.collected.curURLHash.htmls){
			let savePath = pathModule.join(this.webpageSourceFolder, utils.resolveURLToPath(html.url, 'html', html.source).path);
			
			if (!utils.validFilePath(savePath)){
				this.logger.warn('File name too long: ' + savePath);
				savePath = pathModule.join(this.webpageSourceFolder, utils.hashURL(utils.resolveURLToPath(html.url, 'html', html.source).path)+'.html');
			}

			fs.mkdirSync(path.dirname(savePath), { recursive: true });
		
			const stream = fs.createWriteStream(savePath);
			await stream.write(Buffer.from(html.source, 'base64').toString('utf-8'));
			stream.end();

			fileMap[html.url] = savePath;
		}
	}

	if (this.config.collector.COLLECT_CSS){
		for (let css of this.collected.curURLHash.css){
			let savePath = pathModule.join(this.webpageSourceFolder, utils.resolveURLToPath(css.url, 'css', css.source).path);
			
			if (!utils.validFilePath(savePath)){
				this.logger.warn('File name too long: ' + savePath);
				savePath = pathModule.join(this.webpageSourceFolder, utils.hashURL(utils.resolveURLToPath(css.url, 'css', css.source).path)+'.css');
			}

			fs.mkdirSync(path.dirname(savePath), { recursive: true });

			const stream = fs.createWriteStream(savePath);
			await stream.write(Buffer.from(css.source, 'base64').toString('utf-8'));
			stream.end();

			fileMap[css.url] = savePath;
		}
	}

	if (this.config.collector.COLLECT_SCRIPTS){
		for (let script of this.collected.curURLHash.scripts){
			let savePath = pathModule.join(this.webpageSourceFolder, utils.resolveURLToPath(script.url, 'js', script.source).path);
			
			if (!utils.validFilePath(savePath)){
				this.logger.warn('File name too long: ' + savePath);
				savePath = pathModule.join(this.webpageSourceFolder, utils.hashURL(utils.resolveURLToPath(script.url, 'js', script.source).path)+'.js');
			}
			
			fs.mkdirSync(path.dirname(savePath), { recursive: true });

			const stream = fs.createWriteStream(savePath);
			await stream.write(Buffer.from(script.source, 'base64').toString('utf-8'));
			stream.end();

			fileMap[script.url] = savePath;
		}
	}

	// store the file map
	this.collected.curURLHash.fileMap = fileMap;
	fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, 'fileMap.json'), JSON.stringify(fileMap, null, 4));
}

Visitor.prototype.saveCrawlerData = async function(){
	// append url in urls.out in the website-specific directory
	fs.appendFileSync(pathModule.join(this.webpageCrawlerFolder, "urls.out"), JSON.stringify([this.curURL, this.curURLHash], null, 4));

	// collect the webpage data
	if(this.config.collector.COLLECT_AND_CREATE_PAGE){

		// store url in url.out in the webpage-specific directory
		fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "url.out"), this.curURL);

		// store cookies, webstorage, and requests
		if (this.config.collector.COLLECT_COOKIES){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "cookies.json"), JSON.stringify(this.collected.curURLHash.cookies, null, 4));
		}

		if (this.config.collector.COLLECT_WEB_STORAGE){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "webstorage.json"), JSON.stringify(this.collected.curURLHash.webStorageData, null, 4));
		}

		if (this.config.collector.COLLECT_REQUESTS){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "requests.json"), JSON.stringify(this.collected.curURLHash.httpRequests, null, 4));
		}

		if (this.config.collector.COLLECT_XHR_REQUESTS){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "xhr-requests.json"), JSON.stringify(this.collected.curURLHash.XHRRequests, null, 4));
		}

		if (this.config.collector.COLLECT_FETCH_REQUESTS){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "fetch-requests.json"), JSON.stringify(this.collected.curURLHash.FetchRequests, null, 4));
		}

		if (this.config.collector.COLLECT_BROWSER_STDERR){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "browser-stderr.json"), JSON.stringify(this.collected.curURLHash.browserStderr, null, 4));
		}

		if (this.config.collector.COLLECT_BROWSER_STDOUT){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "browser-stdout.json"), JSON.stringify(this.collected.curURLHash.browserStdout, null, 4));
		}

		if (this.config.collector.COLLECT_CONSOLE_LOGS){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "console-logs.json"), JSON.stringify(this.collected.curURLHash.consoleLogs, null, 4));
		}

		if (this.config.collector.EXTRACT_DOM_LOOKUPS && this.collected.curURLHash.DOMCLookups){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "domc-lookups.json"), JSON.stringify(this.collected.curURLHash.DOMCLookups, null, 4));
		}

		if (this.config.collector.EXTRACT_UNDEF_LOOKUPS && this.collected.curURLHash.undefinedLookups){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "undefined-lookups.json"), JSON.stringify(this.collected.curURLHash.undefinedLookups, null, 4));
		}

		if (this.config.collector.COLLECT_TAINTING_FLOWS && this.collected.curURLHash.taintflows){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "taintflows.json"), JSON.stringify(this.collected.curURLHash.taintflows, null, 4));
		}

		if (this.config.collector.COLLECT_ERRORS){
			fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "crawler-errors.json"), JSON.stringify(this.collected.curURLHash.crawlerErrors, null, 4));
		}
	}
}


Visitor.prototype.updateFileDirectory = function(){
	let webpageFolderName = utils.hashURL(this.curURL);
	let webpageFolder = pathModule.join(this.basedir, webpageFolderName);

	this.webpageFolder = webpageFolder;

	this.webpageSourceFolder = pathModule.join(webpageFolder, 'source');
	this.webpageCrawlerFolder = pathModule.join(webpageFolder, 'crawler');

	// make sure the output directory exists
	if (!fs.existsSync(this.webpageCrawlerFolder) || !fs.existsSync(this.webpageSourceFolder)){
		fs.mkdirSync(this.webpageCrawlerFolder, { recursive: true });
		fs.mkdirSync(this.webpageSourceFolder, { recursive: true });
	}
}

Visitor.prototype.updateLogger = function(){
	this.logger = new Logger('debug', 'Visitor', pathModule.join(this.webpageCrawlerFolder, 'crawler.log'));
}

Visitor.prototype.launch_puppeteer = async function(){
	var browser = await puppeteer.launch({
		executablePath: this.browserExecutablePath,
		headless: this.browserHeadless,
		devtools: this.browserDevtools,
		args: this.browserFlags,
		'ignoreHTTPSErrors': true,
	});


	browser.on('disconnected', async () => {
		this.logger.warn('Browser disconnected.');
	})

	return browser;	
}

module.exports = Visitor;


