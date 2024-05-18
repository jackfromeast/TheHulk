/**
 * @Name: currentScript.js
 * @SourceType: DOC-TYPE-2
 * @SourceCode: document.currentScript.src
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */

let scriptEle = document.createElement('script');
let baseURL = document.currentScript.src;
scriptEle.src = baseURL;
document.body.appendChild(scriptEle);