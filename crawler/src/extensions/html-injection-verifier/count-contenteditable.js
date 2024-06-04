function countContentEditablesInDocument(doc) {
  let editableElementsAllRaw = doc.querySelectorAll('[contenteditable]');

  if (editableElementsAllRaw.length === 0) {
      return 0;
  }

  let editableElementsAll = Array.from(editableElementsAllRaw).map(el => ({
      tag: el.tagName,
      attributes: Array.from(el.attributes).reduce((attrs, attr) => {
          attrs[attr.name] = attr.value;
          return attrs;
      }, {})
  }));

  let contentEditablesAll = editableElementsAll.filter(
      (el) => el.attributes.contenteditable !== "false" &&
              el.attributes.contenteditable !== "plaintext-only" &&
              el.tag !== "INPUT" &&
              el.tag !== "TEXTAREA"
  );

  return contentEditablesAll.length;
}

function countContentEditables() {
  let totalEditableCount = countContentEditablesInDocument(document);

  let iframes = document.querySelectorAll('iframe');
  iframes.forEach((iframe) => {
      try {
          totalEditableCount += countContentEditablesInDocument(iframe.contentDocument);
      } catch (e) {
          // console.warn('Could not access iframe contents:', e);
      }
  });

  if (totalEditableCount > 0) {
      chrome.runtime.sendMessage({
          type: 'CHECK_CONTENTEDITABLE',
          editableCount: totalEditableCount
      });
  }
}

document.addEventListener("DOMContentLoaded", function () {
  countContentEditables();
  setInterval(countContentEditables, 1000);
});