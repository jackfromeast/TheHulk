/**
 * @Name: getElementByTagName-value.js
 * @SourceType: API-TYPE-1
 * @SourceCode: document.getElementsByName('source')[0].value
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */

// Create the necessary HTML element
let inputSource = document.createElement('input');
inputSource.type = 'hidden';
inputSource.name = 'source';
inputSource.value = 'https://example.com/script.js';
document.body.appendChild(inputSource);

// JavaScript to create and append the script element
let scriptEle = document.createElement('script');
let src = document.getElementsByName('source')[0].value;
scriptEle.src = src;
document.body.appendChild(scriptEle);