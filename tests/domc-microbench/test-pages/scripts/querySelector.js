/**
 * @Name: querySelector.js
 * @SourceType: API-TYPE-1
 * @SourceCode: document.querySelector('meta[name="source"]').content
 * @SinkType: XSS
 * @SinkCode: document.createElement('script').src
 */


// Create the necessary HTML element
let metaSource = document.createElement('meta');
metaSource.name = 'source';
metaSource.content = 'https://example.com/style.css';
document.head.appendChild(metaSource);

// JavaScript to create and append the link element
let link = document.createElement('link');
let href = document.querySelector('meta[name="source"]').content;
link.href = href;
link.rel = 'script';
document.head.appendChild(link);