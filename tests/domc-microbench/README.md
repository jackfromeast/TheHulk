# Microbenchmark for DOM Clobbering Gadgets

The folder contains a list of test pages that consist of different clobberable sources and sinks. The detection tool should be able to pass all these test pages.

The server can be setup by running: `./setup.sh`.

The setuped server should be able to visited at `http://127.0.0.1:8000/domc-win-xss-1.html`. Ideally, there are urls that help link different pages one by one. Therefore, we just to let the crawler/analyzer starts at the first page.