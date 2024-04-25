chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    chrome.action.getBadgeText({}, (text) => {
      sendResponse(text);
    });
    return true;
  }
);
