const fs = require("fs");
const pathModule = require('path');

// This file is an example of a user-defined callback module.
module.exports = {
  extractDOMRelatedTaintFlowsCb
};

/**
 * The callback function will intakes the visitor and page objects as the argument
 * 
 * @param {*} visitor 
 * @param {*} page 
 */
async function extractDOMRelatedTaintFlowsCb(visitor, page){
    let taintFlows = visitor.collected.curURLHash.taintflows;
    let domRelatedTaintFlows = [];

    // Define the list of entry sources to filter out
    const entrySources = [
        "location.hash",
        "location.host",
        "location.hostname",
        "location.href",
        "location.origin",
        "location.pathname",
        "location.search",
        "location.protocol",
        "script.innerHTML",
        "window.name",
        "XMLHttpRequest.response",
        "WebSocket.MessageEvent.data",
        "window.postMessage",
        "MessageEvent",
        "localStorage.getItem",
        "PushSubscription.endpoint",
        "sessionStorage.getItem",
        "PushMessageData"
    ];

    // Filter the taint flows
    taintFlows.forEach(flow => {
      let sources = flow.sources;
      let isDomRelated = sources.some(source => !entrySources.includes(source));
      
      if (isDomRelated) {
          domRelatedTaintFlows.push(flow);
      }
    });

    fs.writeFileSync(pathModule.join(visitor.webpageCrawlerFolder, "dom-taintflows.json"), 
                     JSON.stringify(domRelatedTaintFlows, null, 2));
}