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