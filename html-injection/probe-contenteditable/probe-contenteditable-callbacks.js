const fs = require('fs');
const path = require('path');

module.exports = {
  probeContentEditableCb,
};

/**
* The callback function is used to check whether the webpage contains any the 
* contenteditable elements on the page. If it does, it will save the url and the
* contenteditable element to the file.
* 
* @param {*} visitor 
* @param {*} page 
*/
async function probeContentEditableCb(visitor, page){
  let contentEditablesAll = [];
  
  // Main page contenteditables
  contentEditablesAll = await getContentEditables(page);

  // Handle the editor within iframe 
  const frames = await page.frames();
  for (let frame of frames) {
    const frameContentEditables = await getContentEditables(frame);
    contentEditablesAll = contentEditablesAll.concat(frameContentEditables);
  }
  
  // Filter out the contenteditable attributes that are not "true"
  contentEditablesAll = contentEditablesAll.filter(
      (el) => el.attributes.contenteditable !== "false");
  
  // TODO: Also filter out the elements whose tagName is input or textarea

  // If there are contenteditable elements
  if (contentEditablesAll.length > 0) {
    visitor.logger.info(`Found contenteditable elements on the url: ${visitor.curURL}`);

    // Save the contenteditable elements to the file
    fs.writeFileSync(path.join(visitor.webpageCrawlerFolder, "contentEditableElements.json"), 
        JSON.stringify(contentEditablesAll, null, 4));
    
    // update the overall map of contenteditable elements
    updateContentEditableMap(visitor, contentEditablesAll.length);
  }
}


/**
 * Helper function to get all contenteditable elements on the page (iframe)
 * This should capture the element has contenteditable attr and or contenteditable="true"
 * However, it will also captrue the element with contenteditable="false"
 * 
 * @param {*} context 
 * @param {*} startId 
 * @returns 
 */
const getContentEditables = async (context) => {
  return await context.$$eval("[contenteditable]", elements => {
      return elements.map(el => ({
          tag: el.tagName,
          attributes: Array.from(el.attributes).reduce((attrs, attr) => {
              attrs[attr.name] = attr.value;
              return attrs;
          }, {})
      }));
  });
};


/**
 * Helper function to update the overall map of contenteditable elements for sites.
 * 
 * @param {*} visitor The visitor object containing information about the current site.
 * @param {number} contentEditableNum The number of contenteditable elements found on the page.
 */
const updateContentEditableMap = (visitor, contentEditableNum) => {
  const filePath = path.join(visitor.basedir, "..", "contentEditableEleSiteMap.json");

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
    contentEditableNum: contentEditableNum
  });

  // Write the updated data back to the file
  fs.writeFileSync(filePath, JSON.stringify(data, null, 4));
};