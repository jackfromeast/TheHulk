/**
 * This file contains utility functions used by the crawler.
 */
const puppeteer = require('puppeteer');
const fs = require('fs');
const pathModule = require('path');
const crypto = require('crypto')
const argv = require("process.argv");
const path = require('path');
const fastcsv = require('fast-csv');
const js_beautify = require('js-beautify').js;
const elapsed = require("elapsed-time-logger");
var psl = require('psl');
const { URL } = require('url');


/**
 * @function extractDOMCLookups
 * @description Extract the DOMC lookups from the raw stdout from the browser process.
 * 
 * E.g.
 * 
 * From the following stdout:
 * [+] SafeLookup: Found a legitimate use of window/document object to load DOM element.
 * [+] SafeLookup: ORIGIN @http://127.0.0.1:8080
 * [+] SafeLookup: SOURCEURL/FILENAME @ __puppeteer_evaluation_script__
 * [+] SafeLookup: Lookup Site @5:25
        if (document.documentElement)
 * 
 * We extract the following:
 * {
 *    id: 1,
 *    origin: "http://127.0.0.1:8080",
 *    sourceURL: "__puppeteer_evaluation_script__",
 *    lookupSite: "5:25",
 *    text: "if (document.documentElement)"
 * }
*/
function extractDOMCLookups(raw_stdout){
    // Split the stdout into separate lookup entries
    let delimiter = ""
    for (let i = 0; i < 86; i++) {
      delimiter += "="
    }
    
    const entries = raw_stdout.split(delimiter);
  
    // delete empty entries
    for (let i = 0; i < entries.length; i++) {
      if (entries[i] === '') {
        entries.splice(i, 1);
      }
    }
  
    const lookups = [];
    let count = 0;
    entries.forEach((entry, index) => {
      entry = entry.trim();
      // Regular expressions to match each line's relevant part
      const originRegex = /\[\+\] SafeLookup: ORIGIN @(.+)/;
      const sourceURLRegex = /\[\+\] SafeLookup: SOURCEURL\/FILENAME @ (.+)/;
      const lookupSiteRegex = /\[\+\] SafeLookup: Lookup Site @(.+)/;
  
      // Extracting the information using the regular expressions
      const originMatch = entry.match(originRegex);
      const sourceURLMatch = entry.match(sourceURLRegex);
      const lookupSiteMatch = entry.match(lookupSiteRegex);
      const textMatch = entry.split('\n').slice(-1)[0];
  
      // Building the object if all parts are found
      if (originMatch && sourceURLMatch && lookupSiteMatch && textMatch) {
        const lookup = {
          id: count++,
          origin: originMatch[1].trim(),
          sourceURL: sourceURLMatch[1].trim(),
          lookupSite: lookupSiteMatch[1].trim(),
          text: textMatch.trim()
        };
        lookups.push(lookup);
      }
    });
  
    return lookups;
  }


/** 
 * @function readFile 
 * @param file_path_name: absolute path of a file.
 * @return the text content of the given file if it exists, otherwise -1.
**/
function readFile(file_path_name){
	try {
		const data = fs.readFileSync(file_path_name, 'utf8')
		return data;
	} catch (err) {
		// console.error(err)
		return -1;
	}
}


const stringIsAValidUrl = (s, protocols) => {
    try {
        url = new URL(s);
        return protocols
            ? url.protocol
                ? protocols.map(x => `${x.toLowerCase()}:`).includes(url.protocol)
                : false
            : true;
    } catch (err) {
        return false;
    }
};


function checkIfEmailInString(text) { 
    var re = /(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))/;
    return re.test(text);
}

function isValid(link){
	if(link.startsWith('mailto:')){
		return false
	}
	// if(checkIfEmailInString(link)){
	// 	return false
	// }

	return stringIsAValidUrl(link);
}


/** 
 * @function getNameFromURL 
 * @param url: eTLD+1 domain name
 * @return converts the url to its domain name and replaces all the ':' and '/' with '-'.
**/
function getNameFromURL(url) {
    // Parse the domain from the URL
    const hostname = new URL(url).hostname;
    const parsed = psl.parse(hostname);
    
    // Check for parsing errors and get the domain, or return an empty string if not possible
    if (!parsed.error && parsed.domain) {
        return parsed.domain.replace(/:/g, '-').replace(/\//g, '-');
    }else{
        // Manually get the domain part if psl parsing fails
        const domainParts = hostname.split('.').slice(-2).join('.');
        return domainParts.replace(/:/g, '-').replace(/\//g, '-');
    }
}



/** 
 * @function hashURL 
 * @param url: string
 * @return returns the SHA256 hash of the given input in hexa-decimal format
**/
function hashURL(url){
	const hash = crypto.createHash('sha256').update(url, 'utf8').digest('hex');
	return hash.slice(0, 10);
}


/** 
 * @function getOrCreateDataDirectoryForWebsite 
 * @param url: string
 * @return creates a directory to store the data of the input url and returns the directory name.
**/
function getOrCreateDataDirectoryForWebsite(url, dataStorageDirectory){
	const folderName = getNameFromURL(url);
	const folderPath = pathModule.join(dataStorageDirectory, folderName);
	if(!fs.existsSync(folderPath)){
		fs.mkdirSync(folderPath);
	}
	return folderPath;
}


function directoryExists(url, dataStorageDirectory){

	const folderName = getNameFromURL(url);
	const folderPath = pathModule.join(dataStorageDirectory, folderName);
	if(fs.existsSync(folderPath)){
		return true;
	}
	else{
		return false;
	}

}

function logError(error, dataDirectory){
    fs.writeFileSync(pathModule.join(dataDirectory, "error.out"), error.toString())
}

function saveBrowserStdout(browserProcessStdout, dataDirectory){  
    fs.writeFileSync(pathModule.join(dataDirectory, "browser.stdout.out"), browserProcessStdout);
}

function saveDOMCLookups(browserProcessStdout, dataDirectory){
    let lookups = extractDOMCLookups(browserProcessStdout);
	fs.writeFileSync(pathModule.join(dataDirectory, "domc.lookups.out"), JSON.stringify(lookups, null, 4));
}

/** 
 * @function getSourceFromScriptId 
 * @param session: chrome dev tools protocol (CDP) session.
 * @param scriptId: script id given by the CDP.
 * @return returns the script content of a given script id in a CDP session.
**/
async function getSourceFromScriptId(session, scriptId) {

	try{
		let res =  await session.send('Debugger.getScriptSource', {scriptId: scriptId});
		let script_content = res.scriptSource;
		let beautified_script_content = js_beautify(script_content, { indent_size: 2, space_in_empty_paren: true });
		return beautified_script_content;
	}catch{
		// Protocol error (Debugger.getScriptSource): No script for id: <ID>
		return ""
	}
}

/**
 * Try to resolve the URL to the relative file path
 * Ideally, we should store the files in the same directory structure as shown in source panel in devtools
 * 
 * However, we only collect html, css, and script files
 * 
 * Refer to crawler/extensions/save_all_resource/2.0.6_0/legacy/0.1.9/devtool.app.js
 * @param {*} cUrl 
 * @param {*} cType 
 * @param {*} cContent 
 * @returns 
 */
function resolveURLToPath(cUrl, cType, cContent) {
	var filepath, filename, isDataURI;
	var foundIndex = cUrl.search(/\:\/\//);
	// Check the url whether it is a link or a string of text data
	if (foundIndex === -1 || foundIndex >= 10) {
	  isDataURI = true;
	  // console.log('Data URI Detected!!!!!');
  
	  if (cUrl.indexOf('data:') === 0) {
		var dataURIInfo = cUrl
		  .split(';')[0]
		  .split(',')[0]
		  .substring(0, 30)
		  .replace(/[^A-Za-z0-9]/g, '.');
		// console.log('=====> ',dataURIInfo);
		filename = dataURIInfo + '.' + Math.random().toString(16).substring(2) + '.txt';
	  } else {
		filename = 'data.' + Math.random().toString(16).substring(2) + '.txt';
	  }
  
	  filepath = '_DataURI/' + filename;
	} else {
	  isDataURI = false;
	  if (cUrl.split('://')[0].includes('http')) {
		// For http:// https://
		filepath = cUrl.split('://')[1].split('?')[0];
	  } else {
		// For webpack:// ng:// ftp://
		filepath = cUrl.replace('://', '---').split('?')[0];
	  }
	  if (filepath.charAt(filepath.length - 1) === '/') {
		filepath = filepath + 'index.html';
	  }
	  filename = filepath.substring(filepath.lastIndexOf('/') + 1);
	}
  
	// Get Rid of QueryString after ;
	filename = filename.split(';')[0];
	filepath = filepath.substring(0, filepath.lastIndexOf('/') + 1) + filename;
  
	// Add default extension to non extension filename
	if (filename.search(/\./) === -1) {
	  var haveExtension = null;
	  if (cType && cContent) {
		// Special Case for Images with Base64
		if (cType.indexOf('image') !== -1) {
		  if (cContent.charAt(0) == '/') {
			filepath = filepath + '.jpg';
			haveExtension = 'jpg';
		  }
		  if (cContent.charAt(0) == 'R') {
			filepath = filepath + '.gif';
			haveExtension = 'gif';
		  }
		  if (cContent.charAt(0) == 'i') {
			filepath = filepath + '.png';
			haveExtension = 'png';
		  }
		}
		// Stylesheet | CSS
		if (cType.indexOf('stylesheet') !== -1 || cType.indexOf('css') !== -1) {
		  filepath = filepath + '.css';
		  haveExtension = 'css';
		}
		// JSON
		if (cType.indexOf('json') !== -1) {
		  filepath = filepath + '.json';
		  haveExtension = 'json';
		}
		// Javascript
		if (cType.indexOf('javascript') !== -1) {
		  filepath = filepath + '.js';
		  haveExtension = 'js';
		}
		// HTML
		if (cType.indexOf('html') !== -1) {
		  filepath = filepath + '.html';
		  haveExtension = 'html';
		}
  
		if (!haveExtension) {
		  filepath = filepath + '.html';
		  haveExtension = 'html';
		}
	  } else {
		// Add default html for text document
		filepath = filepath + '.html';
		haveExtension = 'html';
	  }
	  filename = filename + '.' + haveExtension;
	  // console.log('File without extension: ', filename, filepath);
	}
  
	// Remove path violation case
	filepath = filepath
	  .replace(/\:|\\|\=|\*|\.$|\"|\'|\?|\~|\||\<|\>/g, '')
	  .replace(/\/\//g, '/')
	  .replace(/(\s|\.)\//g, '/')
	  .replace(/\/(\s|\.)/g, '/');
  
	filename = filename.replace(/\:|\\|\=|\*|\.$|\"|\'|\?|\~|\||\<|\>/g, '');
  
	// Decode URI
	if (filepath.indexOf('%') !== -1) {
	  try {
		filepath = decodeURIComponent(filepath);
		filename = decodeURIComponent(filename);
	  } catch (err) {
		console.log(err);
	  }
	}
  
	// Strip double slashes
	while (filepath.includes('//')) {
	  filepath = filepath.replace('//', '/');
	}
  
	// Strip the first slash '/src/...' -> 'src/...'
	if (filepath.charAt(0) === '/') {
	  filepath = filepath.slice(1);
	}
  
	//  console.log('Save to: ', filepath);
	//  console.log('File name: ',filename);
  
	return {
	  path: filepath,
	  name: filename,
	  dataURI: isDataURI && cUrl,
	};
  }

  function validFilePath(savePath) {
    // Split the path by '/' to get individual parts.
    const parts = savePath.split('/');

    // Iterate over each part to check its length.
    for (const part of parts) {
        // Check if any part is longer than 254 characters.
        if (part.length > 254) {
            // If so, return false as it's invalid.
            return false;
        }
    }

    // If all parts are valid, return true.
    return true;
}

function getTimeStamp() {
    const now = new Date();

    // Extract year, month, day, hour, and minute
    const month = now.getMonth() + 1; // Note: Months are 0-indexed, so +1 to get the correct month
    const day = now.getDate();
    const hour = now.getHours();
    const minute = now.getMinutes();

    // Format the date and time string
    return `${month.toString().padStart(2, '0')}-${day.toString().padStart(2, '0')}-${hour.toString().padStart(2, '0')}-${minute.toString().padStart(2, '0')}`;
}

// Function to read CSV file and return a promise that resolves to an array of URLs
function readCSVFile(filePath) {
    const urls = [];
    return new Promise((resolve, reject) => {
      fs.createReadStream(path.resolve(filePath))
        .pipe(fastcsv.parse({ headers: false }))
        .on('error', error => reject(error))
        .on('data', row => urls.push(row[1])) // Assuming the URL is in the second column
        .on('end', rowCount => resolve(urls));
    });
  }

  

module.exports = {
    extractDOMCLookups,
    readFile,
    isValid,
    getNameFromURL,
    hashURL,
    getOrCreateDataDirectoryForWebsite,
    // savePageData,
    saveBrowserStdout,
    saveDOMCLookups,
    getSourceFromScriptId,
    directoryExists,
    checkIfEmailInString,
    logError,
    resolveURLToPath,
	validFilePath,
	getTimeStamp,
	readCSVFile
}