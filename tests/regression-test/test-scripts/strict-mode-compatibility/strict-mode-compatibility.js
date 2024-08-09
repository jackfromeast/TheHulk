/**
 * @Name: strict-mode-compatibility-1
 * @File: strict-mode-compatibility.js
 * @Import: Yes
 * @Refer: 
 *  - Domain: https://www.ebay.com/
 *  - URL: https://devicebind.ebay.com/signin/sub/tt.html?st=1722884633457&f=53000&e=0&pageid=4375194&rec=0&sc=0&sm=4&sig=Y8f7oa49%2BPjpipHd0vKtZTfDviZWNUOhOBUb9IjEblfRb4Bf1MEmn%2FJpgxCjioj41bOVNSRp4Xrh8ga%2FjjNDBQ%3D%3D
 *  - Function: anonymous
 */
(function () {
  // This will not throw an error in non-strict mode'
  // But after instrumentation, the putField operation will be carried out in rule-builder.js which is under the strict mode (as it has class keyword)
  window.indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB;
})();