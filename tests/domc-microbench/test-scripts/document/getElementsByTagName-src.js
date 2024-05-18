/**
 * @Name: getElementByTagName-src.js
 * @SourceType: API-TYPE-1
 * @SourceCode: document.getElementsByTagName('iframe')[0].src
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */

// Create the necessary HTML element
let iframeSource = document.createElement('iframe');
iframeSource.src = 'https://example.com';
iframeSource.style.display = 'none';
document.body.appendChild(iframeSource);

// JavaScript to create and append the source element
let source = document.createElement('source');
let src = document.getElementsByTagName('iframe')[0].src;
source.src = src;
document.body.appendChild(source);