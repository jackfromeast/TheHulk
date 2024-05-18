/**
 * @Name: scripts.js
 * @SourceType: DOC-TYPE-2
 * @SourceCode: document.scripts[0].src
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */

// JavaScript to create and append the video element
let scriptEle = document.createElement('script');
let src = document.scripts[0].src;
scriptEle.src = src;
document.body.appendChild(scriptEle);