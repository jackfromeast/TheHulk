/**
 * @Name: images.js
 * @SourceType: DOC-TYPE-2
 * @SourceCode: document.images[0].src
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */

// Create the necessary HTML element
let imgSource = document.createElement('img');
imgSource.src = 'https://example.com/audio.jpg';
imgSource.style.display = 'none';
document.body.appendChild(imgSource);

// JavaScript to create and append the audio element
let scriptEle = document.createElement('script');
let src = document.images[0].src;
scriptEle.src = src;
document.body.appendChild(scriptEle);