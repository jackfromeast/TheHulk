chrome.runtime.onMessage.addListener(
  function(request, sender, sendResponse) {
    chrome.action.getBadgeText({}, (text) => {
      sendResponse(text);
    });
    return true;
  }
);


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'CHECK_CONTENTEDITABLE') {
      if (message.editableCount > 0) {
          chrome.action.setIcon({ path: '/assets/on-fire-32.png', tabId: sender.tab.id });
      } else {
          chrome.action.setIcon({ path: '/assets/hulk-logo-32.png', tabId: sender.tab.id });
      }
  }
});