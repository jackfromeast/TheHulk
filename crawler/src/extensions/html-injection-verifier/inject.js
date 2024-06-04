var script_tag = document.createElement('div');

chrome.runtime.sendMessage({}).then((response) => {
	script_tag.innerHTML = response
	document.lastChild.appendChild(script_tag);
});


chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
	if (message.type === 'CHECK_CONTENTEDITABLE') {
			chrome.scripting.executeScript({
					target: { tabId: sender.tab.id },
					files: ['count-counteditable.js']
			}, (results) => {
					const editableCount = results[0].result;
					sendResponse({ editableCount });
			});
			return true; // Indicates we want to send a response asynchronously
	}
});