/**
 * Third-party libraries
 */
// const puppeteer = require('puppeteer');
const { chromium, firefox } = require('playwright');
const fs = require('fs');
const pathModule = require('path');
const elapsed = require("elapsed-time-logger");
const utils = require('./utils.js');
const Logger = require('./logger');
const path = require('path');
const { warn, log, timeStamp } = require('console');

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
		this.browserType = chromium;
		this.browserExecutablePath = config.chrome.CHROME_EXECUTABLE_PATH;
		this.browserFlags = config.chrome.CHROME_FLAGS;
		this.browserHeadless = config.chrome.HEADLESS;
		this.browserDevtools = config.chrome.DEVTOOLS;
	} else if (config.navigator.BROWSER === "foxhound") {
		this.browserType = firefox;
		this.browserExecutablePath = config.foxhound.FOXHOUND_EXECUTABLE_PATH;
		this.browserFlags = config.foxhound.FOXHOUND_FLAGS;
		this.browserHeadless = config.foxhound.HEADLESS;
		this.browserDevtools = config.foxhound.DEVTOOLS;
	} else {
		throw "Configuration Error: Not chrome or foxhound. BROWSER is not supported!"
	}

	this.logger = undefined;
	this.browser = undefined;
	this.context = undefined; // in playwright, the context is isolated browser environment
	this.startURL = url;
	this.domain = domain;
	this.basedir = basedir;
	this.maxURLNum = maxurls;

	// Remember to update the following data structures when visiting a new page
	this.unvisited = [url];
	this.visited = [];
	this.curURL = url;
	this.curURLHash = utils.hashURL(url);
	// this.curCDPsession = undefined;

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
	this.browser = await this.launch_browser();
	const globalTimer = elapsed.start('global_crawling_timer');

	while(true){
		// pick a URL from unvisited list
		this.curURL = this.unvisited[0];
		this.curURLHash = utils.hashURL(this.curURL);
		this.visited.push(this.curURL); // add the current URL to the visited list

		this.collected.curURLHash = this.emptyCollectData();

		this.updateFileDirectory();
		this.updateLogger();

		// visit the URL
		await this.visitPage();

		// save the collected data to the disk
		await this.saveWebPageData();
		await this.saveCrawlerData();

		this.unvisited.shift(); // remove the current URL from the unvisited list

		// termination criteria
		if(this.visited.length >= this.maxURLNum){
			this.logger.debug('Max urls visited, exiting.');
			break;
		}

		if(this.unvisited.length === 0){
			this.logger.debug('No unvisited URL, exiting.');
			break;
		}
	}

	// Run the post visit callbacks
	for (let cb of this.postVisitCbs){
		await cb(this);
	}

	try{
		await this.context.close();
		await this.browser.close();
	}
	catch(e){
		// PASS
	}

	const globalTime = globalTimer.get();

	// store elapsed time to disk
	fs.writeFileSync(pathModule.join(this.basedir, "time.crawling.out"), JSON.stringify({
		"crawling_time": globalTime,
	}));

	this.logger.debug('Done visiting the website: ' + this.domain + ' in ' + globalTime);
}

Visitor.prototype.visitPage = async function(){
	this.context = await this.browser.newContext({ bypassCSP: true });
	let page = await this.context.newPage();

	await page.setViewportSize({ width: 4096, height: 2048});

	try{
		/*
		*  ----------------------------------------------
		*  [PreLoading] Install the Event Handlers 
		*  ----------------------------------------------
		*/
		await this.setupInterception(page);
		if (this.config.collector.COLLECT_CONSOLE_LOGS){ this.collectConsoleLogs(page); }
		// if (this.config.collector.COLLECT_BROWSER_STDOUT){ this.collectBrowserStdout(); }
		// if (this.config.collector.COLLECT_BROWSER_STDERR){ this.collectBrowserStderr(); }

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
		if  (this.config.collector.COLLECT_ALT_URLS || this.maxURLNum){ await this.collectAltURLs(page); }
		
		// If the page is still alive:
		try{
			await page.waitForTimeout(this.config.navigator.WAIT_BEFORE_NEXT_URL);
			await page.close();
		}catch(e){
			if (e.message.includes('Target page, context or browser has been closed')){
				this.logger.warn('PageClosedError: Target page, context or browser has been closed (page.waitForTimeout)');
			}else{
				throw e;
			} 
		}

	}catch(e){
		if (e.message.includes('Navigation timeout of')){
			this.logger.error('TimeoutError: Navigation timeout exceeded for URL: ' + this.curURL);
		}else if (e.message.includes('NS_ERROR_CONNECTION_REFUSED') ||
							e.message.includes('net::ERR_CONNECTION_REFUSED')){
			this.logger.error('ConnectionRefusedError: NS_ERROR_CONNECTION_REFUSED for URL: ' + this.curURL);
		}else if (e.message.includes('NS_ERROR_UNKNOWN_HOST') || 
							e.message.includes('net::ERR_NAME_NOT_RESOLVED')){
			this.logger.error('DomainNameError: NS_ERROR_UNKNOWN_HOST for URL: ' + this.curURL);
		}else if (e.message.includes('ERR_HTTP2_PROTOCOL_ERROR')){
			this.logger.error('HTTP2ProtocolError: ERR_HTTP2_PROTOCOL_ERROR for URL: ' + this.curURL);
		}else if (e.message.includes('ERR_CONNECTION_CLOSED')){
			this.logger.warn('ERR_CONNECTION_CLOSED: for URL: ' + this.curURL);
		}else if (e.message.includes('ERR_TUNNEL_CONNECTION_FAILED')){
			this.logger.warn('TunnelConnectionError: ERR_TUNNEL_CONNECTION_FAILED for URL: ' + this.curURL);
		}else if (e.message.includes('Target page, context or browser has been closed')){
			this.logger.warn('PageClosedError: Target page, context or browser has been closed.');
		}
		else{
			this.logger.error(e);
		}
		try{
			// close the previous browser
			await page.close();
			await context.close();
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
			await page.goto(this.curURL, {waitUntil: 'networkidle', timeout: this.config.navigator["NAVIGATION_TIMEOUT"]});
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


/**
 * Here we setup the interception for the page on the network level
 * So that we can collect all the resources have been loaded on the page
 */
Visitor.prototype.setupInterception = function(page) {
  page.route('**/*', async (route) => {
    const request = route.request();
    const url = request.url();
    const resourceType = request.resourceType();
    const method = request.method();
    const headers = request.headers();

		// this.logger.debug(`Intercepted: ${url} (${resourceType})`);
		// this.logger.debug(request.isNavigationRequest());

    try {
      if (request.redirectedFrom()) {
        // Handle redirects
        this.logger.debug(`Handling redirect for: ${url}`);
        await route.continue();
      } else {
        await route.continue();
      }

      try {
        const response = await page.waitForResponse(response => response.url() === url && response.request().resourceType() === resourceType);
        const responseStatus = response.status();

        if (responseStatus >= 300 && responseStatus < 400) {
          this.collected.curURLHash.redirects = this.collected.curURLHash.redirects || [];
          this.collected.curURLHash.redirects.push({ url: url, status: responseStatus });
        } else if (resourceType === 'document' || resourceType === 'stylesheet' || resourceType === 'script' || resourceType === 'Other') {
          if (request.url().endsWith('.ico')){ return; }
					
					const body = await response.text();

          // The main page sometimes will has resourceType as 'Other'
          if (this.config.collector.COLLECT_HTML &&
              (resourceType === 'document' || resourceType === 'Other')) {	
            this.collected.curURLHash.htmls.push({ url: url, source: body });
          } else if (this.config.collector.COLLECT_CSS &&
                     resourceType === 'stylesheet') {
            this.collected.curURLHash.css.push({ url: url, source: body });
          } else if (this.config.collector.COLLECT_SCRIPTS &&
                     resourceType === 'script') {
            this.collected.curURLHash.scripts.push({ url: url, source: body });
          }
        }

        if (this.config.collector.COLLECT_XHR_REQUESTS &&
            resourceType === 'xhr') {
          this.collected.curURLHash.XHRRequests.push({ url: url, method: method, headers: headers });
        }

        if (this.config.collector.COLLECT_FETCH_REQUESTS &&
            resourceType === 'fetch') {
          this.collected.curURLHash.FetchRequests.push({ url: url, method: method, headers: headers });
        }

      } catch (responseError) {
        if (responseError.message.includes('Target page, context or browser has been closed')) {
          this.logger.warn(`Response handling skipped for ${url} as the target page, context, or browser has been closed`);
        } else {
          throw responseError;
        }
      }
    } catch (e) {
      this.logger.error(`Error handling response for ${url}: ${e.message}`);
			// throw e;
      try {
        await route.abort();
      } catch (abortError) {
        if (!abortError.message.includes('Route is already handled')) {
          this.logger.error(`Failed to abort route for ${url}: ${abortError.message}`);
        }
      }
    }
  });
};



Visitor.prototype.collectConsoleLogs = async function(page){
	page.on('console', consoleObj => {
		this.collected.curURLHash.consoleLogs.push(consoleObj.text());
	})

	page.on("pageerror", (err) => {
		this.collected.curURLHash.consoleLogs.push("[!] ERROR: " + err.message);
  })
}

Visitor.prototype.collectBrowserErrors = function(page) {
	page.on('pageerror', error => {
			this.collected.curURLHash.browserStderr.push(error.message);
	});
};

// Visitor.prototype.collectBrowserStdout = async function(){
// 	this.browser.process().stdout.on('data', (data) => {
// 		this.collected.curURLHash.browserStdout.push(data.toString());	
// 	});
// }

// Visitor.prototype.collectBrowserStderr = async function(){
// 	this.browser.process().stderr.on('data', (data) => {
// 		this.collected.curURLHash.browserStderr.push(data.toString());	
// 	})
// }

Visitor.prototype.collectWebStorageData = async function(page){
	const webStorageData = await page.evaluate(() => {
			const storage = {};
			const keys = Object.keys(localStorage);
			for (let key of keys) {
					storage[key] = localStorage.getItem(key);
			}
			return storage;
	});
	this.collected.curURLHash.webStorageData = webStorageData;
}

Visitor.prototype.collectCookie = async function(page){
	let collectedCookies = await page.context().cookies();
	this.collected.curURLHash.cookies = collectedCookies;
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
		
			// Write the raw response text directly
			fs.writeFileSync(savePath, html.source, 'utf-8');

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

			// Write the raw response text directly
			fs.writeFileSync(savePath, css.source, 'utf-8');

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

			// Write the raw response text directly
			fs.writeFileSync(savePath, script.source, 'utf-8');

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
			// fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "browser-stderr.json"), JSON.stringify(this.collected.curURLHash.browserStderr, null, 4));
		}

		if (this.config.collector.COLLECT_BROWSER_STDOUT){
			// fs.writeFileSync(pathModule.join(this.webpageCrawlerFolder, "browser-stdout.json"), JSON.stringify(this.collected.curURLHash.browserStdout, null, 4));
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


Visitor.prototype.launch_browser = async function(){
	let browserLanuchFlags = {
		executablePath: this.browserExecutablePath,
		headless: this.browserHeadless,
		devtools: this.browserDevtools,
		args: this.browserFlags,
		ignoreHTTPSErrors: true,
	};

	if (this.config.proxy && this.config.proxy.PROXY_SERVER){
		browserLanuchFlags['proxy'] = {
			server: `${this.config.proxy.PROXY_SERVER}:${this.config.proxy.PROXY_PORT}`
		}
	}

	var browser = await this.browserType.launch(browserLanuchFlags);

	browser.on('disconnected', async () => {
			this.logger.warn('Browser disconnected.');
	})

	return browser;    
}

module.exports = Visitor;


