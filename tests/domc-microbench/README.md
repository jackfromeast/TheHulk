# Microbenchmark for DOM Clobbering Gadgets

The folder contains a list of test pages that consist of different clobberable sources and sinks. The detection tool should be able to pass all these test pages.

The test pages are compiled (generated) from the test-scripts folder. Each JavaScript file in the folder contains a test case and would generate a test pages in the test-pages combined with the html and css templates in templates.

The server can be setup by running: `./setup.sh`.

The setuped server should be able to visited at `http://127.0.0.1:8000/domc-win-xss-1.html`. Ideally, there are urls that help link different pages one by one. Therefore, we just to let the crawler/analyzer starts at the first page.


TODO::

I am considering can we use one file for holding all the test scripts and let it generate the html test pages?