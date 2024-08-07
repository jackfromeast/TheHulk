![TheHulk](https://github.com/jackfromeast/TheHulk/wiki/assets/icon.jpg)

For more info, please check out [wiki](https://github.com/jackfromeast/TheHulk/wiki)!

### Install & Run

To install TheHulk, follow these steps:

1. Clone the repository with submodules:

```
git clone --recursive https://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@github.com/jackfromeast/TheHulk.git
```

2. Run the installation script:

```
cd TheHulk && ./install.sh
```

#### Running the Taint-Aware Browser

To run the taint-aware browser, follow these instructions:

1. Configure the Browser:
  + 1-1. Open the configuration file located at `concolic-engine/browser/config.browser.yml`.
  + 1-2. Update the `WORKSPACE` path to specify where the output folders will be placed.
  + 1-3. Update the callback scripts path, using either an absolute path or a relative path to the crawler/src directory.

2. Start the Browser and Open the Console:

```
./concolic-engine/run.sh
```

Note: You can adjust the '--force-device-scale-factor=1.75' argument in the configuration file to change the browser's resolution. This setting provides optimal resolution for checking the source code, but it might be too large for viewing web pages. Adjust as necessary for your display.