var script_tag = document.createElement('div');

chrome.runtime.sendMessage({}).then((response) => {
	script_tag.innerHTML = response
	document.lastChild.appendChild(script_tag);
});
