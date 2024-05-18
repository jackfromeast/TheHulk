/**
 * @Name: forms.js
 * @SourceType: DOC-TYPE-2
 * @SourceCode: document.forms[0].action
 * @SinkType: XSS
 * @SinkCode: document.createElement('iframe').src
 */

// Create the necessary HTML element
let form = document.createElement('form');
form.action = 'https://example.com';
document.body.appendChild(form);

// JavaScript to create and append the iframe element
let iframe = document.createElement('iframe');
let src = document.forms[0].action;
iframe.src = src + '/script.js';
document.body.appendChild(iframe);