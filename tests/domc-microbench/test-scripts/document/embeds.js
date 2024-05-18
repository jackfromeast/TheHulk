/**
 * @Name: embeds.js
 * @SourceType: DOC-TYPE-2
 * @SourceCode: document.embeds[0].src
 * @SinkType: XSS
 * @SinkCode: document.createElement('object').data
 */


// Create the necessary HTML element
let embed = document.createElement('embed');
embed.src = 'https://example.com/embed.swf';
embed.style.display = 'none';
document.body.appendChild(embed);

// JavaScript to create and append the script element
let scriptEle = document.createElement('object');
let data = document.embeds[0].src;
scriptEle.src = data;
document.body.appendChild(scriptEle);