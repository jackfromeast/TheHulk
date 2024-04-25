const source = document.getElementById('source');

chrome.action.getBadgeText({}, (text) => source.value = text);

const inputHandler = function(e) {
  chrome.action.setBadgeText({
	  text: source.value,
  });
}

source.addEventListener('input', inputHandler);
