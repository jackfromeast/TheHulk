/**
 * @Name: getElementById.js
 * @SourceType: API-TYPE-1
 * @SourceCode: document.getElementById('source').src
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */


// Create the necessary HTML element
let imgSource = document.createElement('img');
imgSource.id = 'source';
imgSource.src = 'https://example.com/image.jpg';
imgSource.style.display = 'none';
document.body.appendChild(imgSource);

// JavaScript to create and append the img element
let scriptEle = document.createElement('script');
let baseURL = document.getElementById('source').src;
scriptEle.src = baseURL;
document.body.appendChild(scriptEle);