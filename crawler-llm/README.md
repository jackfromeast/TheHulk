# LLM-Crawler

This folder contains the crawler that automated by AI (LLM and CV). That said, the crawling workflow (e.g. which and how to interact with elements) is determined by AI models at runtime using the underlying wrapped browser driver interfaces, by given the overall task goal. 

The LLM-Crawler aims to address challenges that are difficult for traditional crawlers, including:

1/ Auto-login

Traditional crawlers struggle with logging into portals that protect critical assets, which are often susceptible to stored HTML injection vulnerabilities. The LLM-Crawler is designed to handle complex interactions required for accessing, especially for unseen webpages.

2/ Dynamic generated HTML elements

Identifying contenteditable HTML elements can be challenging when they are dynamically generated and require user interactions, such as those in chat boxes. The LLM-Crawler can interact with these elements in real time.

3/ Find all the stored html injection

The LLM-Crawler can navigate through websites to determine if HTML injections persist across pages, such as checking if injected HTML in emails remains visible in the 'sent' folder of an email client.

4/ Gadget discovery

Gadgets finding requires comprehensive page interaction to trigger the javascript code as much as possible.


## HTML Injection

### Contenteditable Elements

+ Step1. Find all the contenteditable elements in the page.
+ Step2. Perform the Copy&Paste action on the found contenteditable elements.
+ Step3. Perform submittion (render) or navigation action to check whether the html injection can be stored.

### HTML Injection in general

+ Step1. Find all the user interactable elements in the page.
+ Step2. Input the different payloads and check whether it will be rendered as html.
  + Step2-1: test raw html (e.g. <h1>html</h1>) & log;
  + Step2-2: test markups (e.g. markup language for different template engines) & log;
+ Step3. Check whether the content will be escaped, removed or rendered.
+ Step4. Perform submittion, render or navigation action to check whether the html injection can be stored.


## TODO: Pipeline for finding html injection using llm-crawler 
@Ishmeals

## Limitaions

### 1/ Popups 

Sometimes, it fails to reconginze the html elements as a close button for the popup, especially these elements like `<span>` which has been decorated with `onclick` event. In the current version, the skyvern will remove the `class` attributes of `<span>` element so the llm cannot tell the corrent element to interact with.

In zoho's case:

```
<span class="zb-close-btn zd-popup-sprite"></span>
```

But, when it passed to the llm:

```
<span id=237></span>
```

### 2/ New window tab

It cannot handle the a link which shown on another window tab. This is usually because of the target=_blank  or the onclick event has been set to use window.open. We can write a script to modify all the link in the page first, for example,

```
const puppeteer = require('puppeteer');

(async () => {
    // Launch the browser
    const browser = await puppeteer.launch({ headless: false });
    const page = await browser.newPage();

    // Navigate to the desired page
    await page.goto('https://www.example.com');

    // Modify the link's target attribute and click on it
    await page.evaluate(() => {
        // Find the link element (you can use a more specific selector if needed)
        const link = document.querySelector('a[target="_blank"]');
        if (link) {
            // Change the target attribute to _self to stay on the same page
            link.setAttribute('target', '_self');
            // Click the link
            link.click();
        }
    });

    // Additional actions can be performed here

    // Close the browser
    // await browser.close();
})();
```

### 3/ Too many interactable elements

Too many interactable elements and exceed the maximum tokens, can we deploy any heuristic strategy to filter out some of them first?

### 4/ Too slow.

We can start more docker to run it. This is fine as long as they can find the html injection vulnerability.


## Improvements

### Breadth-first Search

1/ How to determine a new page?

A url for most of pages. But how about the signle-page elements? We also want to find the elements within the dynamic generated DOM contents, that said, whenever a new content added, we need to perform Step1. again.

2/ Webpage snapshot?

We may want to perform certain actions to test whether the input will be rendered or the html injection will be stored. After the actions, we want to back the state that starts that current test and test another elements.
