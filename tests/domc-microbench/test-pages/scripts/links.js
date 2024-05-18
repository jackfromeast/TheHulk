/**
 * @Name: links.js
 * @SourceType: DOC-TYPE-2
 * @SourceCode: document.links[0].href
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */

// Create the necessary HTML element
let linkElement = document.createElement('a');
linkElement.href = 'https://example.com/script.js';
linkElement.style.display = 'none';
document.body.appendChild(linkElement);

// JavaScript to create and append the script element
let scriptEle = document.createElement('script');
let src = document.links[0].href;
scriptEle.src = src;
document.body.appendChild(scriptEle);