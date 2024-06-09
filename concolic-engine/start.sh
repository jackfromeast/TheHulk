#!/bin/bash
## @description
## --------------------------------
## This bash script helps to prepare the running enviroment of concolic engine
## Includes:
## 1/ Setting up the local server for hosting the analysis scripts
## 2/ Setting up the proxy server for instrumenting the JS&HTML files on the fly
## 3/ Setting up the test server for hosting the test pages
## 4/ Run the concolic anlysis on the browser
## 
## @usage
## --------------------------------
## ./start.sh [test] [proxy] [analysis]


check_and_kill_port() {
  local PORT=$1
  local PID=$(lsof -ti:$PORT)
  if [ -n "$PID" ]; then
    echo "[!] Port $PORT is in use by process $PID. Killing the process..."
    kill -9 $PID > /dev/null 2>&1
  fi
}

# Ensure the script is run under the concolic-engine path
CONCOLIC_PATH=$(pwd)
if [ "$(basename $(pwd))" != "concolic-engine" ]; then
  echo "[!] Please run this script from the concolic-engine directory."
  exit 1
fi

RUN_TEST=false
RUN_PROXY=false
RUN_ANALYSIS=false

# Parse arguments
for arg in "$@"; do
  case $arg in
    test)
      RUN_TEST=true
      shift
      ;;
    proxy)
      RUN_PROXY=true
      shift
      ;;
    analysis)
      RUN_ANALYSIS=true
      shift
      ;;
    *)
      echo "[!] Unknown argument: $arg"
      exit 1
      ;;
  esac
done


# Step 1: Start the Test Server for hosting the test pages
# We currently don't use this 
if [ "$RUN_TEST" = true ]; then
  check_and_kill_port 8001
  echo "[+] Starting the local test server for hosting the test pages..."
  cd $CONCOLIC_PATH/../tests/domc-microbench && http-server test-pages -p 8001 -d false > /dev/null 2>&1 &
  TEST_SERVER_PID=$!
  sleep 2
  echo "[+] Test Server started with PID $TEST_SERVER_PID, at http://localhost:8001"
fi

## Step 2: Start the Proxy Server for instrumenting the JS & HTML on-the-fly
if [ "$RUN_PROXY" = true ]; then
  check_and_kill_port 8899
  echo "[+] Starting the Proxy Server for instrumenting the JS & HTML on-the-fly..."

  ### Setup the python env first
  source $(conda info --base)/etc/profile.d/conda.sh
  conda activate TheThing

  cd $CONCOLIC_PATH/../proxy-server && ./setup.sh > /dev/null 2>&1 &
  PROXY_SERVER_PID=$!
  sleep 2
  echo "[+] Proxy Server started with PID $PROXY_SERVER_PID"
fi

# Step 3: Start the Local Server for hosting the analysis bundle
if [ "$RUN_ANALYSIS" = true ]; then
  # check_and_kill_port 8002
  echo "[+] Starting the local analysis server for hosting the analysis bundle..."
  cd $CONCOLIC_PATH/runtime-analysis && npm run deploy > /dev/null 2>&1
  # cd $CONCOLIC_PATH/http-server && http-server --port 8002 -o . > /dev/null 2>&1 &
  # ANALYSIS_SERVER_PID=$!
  sleep 2
  # echo "[+] Local Analysis Server started with PID $ANALYSIS_SERVER_PID, at http://localhost:8002"
fi


## Step 4: Get back and run the browser
echo "[+] Running the browser..."
cd $CONCOLIC_PATH/browser/ && node ./browser.js --conf=./config.browser.yml &
BROWSER_PID=$!
echo "[+] Browser started with PID $BROWSER_PID"

wait $TEST_SERVER_PID $PROXY_SERVER_PID $BROWSER_PID