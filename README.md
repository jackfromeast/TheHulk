# TheHulk

[![Node](https://img.shields.io/badge/node%40latest-%3E%3D%2018.18.2-brightgreen.svg)](https://img.shields.io/badge/node%40latest-%3E%3D%2018.18.2-brightgreen.svg) [![Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Naereen/StrapDown.js/graphs/commit-activity) [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Find%20DOM%20Clobbering%20Gadgets%20with%20TheHulk&url=https://github.com/jackfromeast/TheHulk)

TheHulk is a dynamic analysis tool designed to detect and exploit DOM Clobbering vulnerabilities. 

## Overview

TheHulk operates in three key phases:

1. **Gadget Detection with Dynamic Taint Analysis**:
TheHulk performs dynamic taint analysis in the browser to track dangerous dataflows at runtime for a given input URL.

2. **Exploit Generation with Symbolic DOM**:
Using the recorded taint traces from the first phase, TheHulk collects and solves constraints along the trace to generate DOM Clobberable HTML markups as exploits.

3. **Exploit Verification**:
TheHulk injects the generated HTML payload into the target webpage and hooks the dangerous sinks to verify exploitability.

<img src="https://github.com/jackfromeast/TheHulk/wiki/assets/thehulk-arch.jpg">

## Installation

To install TheHulk, follow these steps:

1. Clone the repository with submodules (customized [Jalangi2](https://github.com/jackfromeast/jalangi2) and [mitmproxy](https://github.com/mitmproxy/mitmproxy)):

```
git clone --recursive https://github.com/jackfromeast/TheHulk.git
```

2. Run the installation script:

```
cd TheHulk && ./install.sh
```

## Running

TheHulk can be run in two modes: as a standalone module or as a pipeline task.

**Running TheHulk with Tasks**

[Tasks](./tasks/) helps you define the input, output, and configurations of an analysis task for better pipeline orchestration. A typical task directory includes the following components:

+ `input` folder: Holds the list of URLs for analysis.
+ `output` folder: Stores the analysis results for each site or page.
+ `callbacks` folder: Contains JavaScript-defined callback functions that the crawler invokes during execution.
+ `config.browser.yml` file: Configuration file for the taint analysis engine.
+ `config.scheduler.yml` file: Configuration file for the crawler.
+ `run.sh` file: Entrypoint script to start the task.

For example, to detect and exploit the gadgets in the DOM Clobbering collection, you could simply:

1. Configure the browser with network proxy: `http://127.0.0.1:8899`
  + https://help.ubuntu.com/stable/ubuntu-help/net-proxy.html.en

2. Update the two configuration files located at `tasks/run-taint-tracking-dom-clobbering-collection`.
  + 2-1. Update the `WORKSPACE` path to specify where the output folders will be placed.
  + 2-2. Config the inputs, browser configs and callbacks if necessary (can be skiped).

3. Start the task:
```
./tasks/run-taint-tracking-dom-clobbering-collection/run.sh
```

**Running Dynamic Taint Engine Only**

Even Hulk is designed to detect DOM Clobbering gadgets, its dynamic taint engine can be generilzed to detect other client-side vulnerabilities. The source code of the taint engine is located at: `gadget-detection/runtime-analysis/src`.

1. Configure the browser with network proxy: `http://127.0.0.1:8899`
  + https://help.ubuntu.com/stable/ubuntu-help/net-proxy.html.en

2. Update the configuration file located at `gadget-detection/browser/config.browser.yml`.
  + 2-1. Update the `WORKSPACE` path to specify where the output folders will be placed.
  + 2-2. Config the inputs, browser configs and callbacks if necessary (can be skiped).

3. Start the taint-aware browser:

```
./gadget-detection/run.sh
```

Note: You can adjust the '--force-device-scale-factor=1.75' argument in the configuration file to change the browser's resolution. This setting provides optimal resolution for checking the source code, but it might be too large for viewing web pages. Adjust as necessary for your display.

**Running Exploit Generation Module Only**

To generate DOM Clobberable HTML markups from a taint trace using the following command:

```
node exploit-gen/src/exploit.js --trace exploit-gen/src/tests/motivating-example.json
```

## Example

Below is a screenshot of an analysis result for detecting a DOM Clobbering gadget in the Google Client API Library.

<img src="https://github.com/jackfromeast/TheHulk/wiki/assets/moti-example.jpg">

The exploit generation output:

```
$ node exploit-gen/src/exploit.js --trace exploit-gen/src/tests/motivating-example.json
====================
<embed name="scripts">
<form name="scripts" id="0">alert("Hulk!")</form>
====================
<form name="scripts"></form>
<form name="scripts" id="0">alert("Hulk!")</form>
...
```

## DOM Clobbering Collection

DOM Clobbering Collection is list of wildly-used client-side libraries with DOM clobbering gadgets that found by Thehulk.

The dataset is available at https://github.com/jackfromeast/dom-clobbering-collection.

