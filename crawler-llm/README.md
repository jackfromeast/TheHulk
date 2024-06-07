# LLM-Crawler

This folder contains the crawler that automated by AI (LLM and CV). That said, the crawling workflow (e.g. which and how to interact with elements) is determined by AI models at runtime using the underlying wrapped browser driver interfaces, by given the overall task goal. 

The LLM-Crawler aims to address challenges that are difficult for traditional crawlers, including:

1/ Auto-login

Traditional crawlers struggle with logging into portals that protect critical assets, which are often susceptible to stored HTML injection vulnerabilities. The LLM-Crawler is designed to handle complex interactions required for accessing, especially for unseen webpages.

2/ Dynamic generated HTML elements

Identifying contenteditable HTML elements can be challenging when they are dynamically generated and require user interactions, such as those in chat boxes. The LLM-Crawler can interact with these elements in real time.

3/ Locating all stored html injections

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
  + Step2-1: test raw html (e.g. `<h1>html</h1>`) & log;
  
  + Step2-2: test markups (e.g. markup language for different template engines) & log;
+ Step3. Check whether the content will be escaped, removed or rendered.
+ Step4. Perform submittion, render or navigation action to check whether the html injection can be stored.


## Pipeline for finding html injection using llm-crawler 

1. Modular attack specification
    - List of websites
    - Description of vulnerable location
    - Payload
    - Payload success verification

2. Skyvern (3 pass)
    - Registers accounts on sites
    - Finds vulnerable locations
    - Tests vulnerable locations


## Limitaions

### 1/ Limited view of interactable elements 

The entire html file is not sent to the llm. Instead it sends snippets of interactable elements and also strips all attributes, only keeping the text within the element.

Sometimes, it fails to reconginze the html elements as a close button for the popup, especially these elements like `<span>` which has been decorated with `onclick` event. In the current version, the skyvern will remove the `class` attributes of `<span>` element so the llm cannot tell the corrent element to interact with.

In zoho's case:

```
<span class="zb-close-btn zd-popup-sprite"></span>
```

But, when it passed to the llm:

```
<span id=237></span>
```

### 3/ Too many interactable elements

Too many interactable elements and exceed the maximum tokens, can we deploy any heuristic strategy to filter out some of them first?

### 4/ Too slow.

We can start more docker to run it. This is fine as long as they can find the html injection vulnerability.

### 5/ Captcha

The crawler gets detected as a bot and is unable to solve Captchas.

## Improvements

### Breadth-first Search

1/ How to determine a new page?

A url for most of pages. But how about the signle-page elements? We also want to find the elements within the dynamic generated DOM contents, that said, whenever a new content added, we need to perform Step1. again.

2/ Webpage snapshot?

We may want to perform certain actions to test whether the input will be rendered or the html injection will be stored. After the actions, we want to back the state that starts that current test and test another elements.
