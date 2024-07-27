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

RUN_TEST=true
RUN_PROXY=true
RUN_ANALYSIS=true

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
  pushd $CONCOLIC_PATH/../tests/taint-tracking-builtins > /dev/null 2>&1
  http-server test-pages -p 8001 -d false -c-1 > /dev/null 2>&1 &
  curl -s http://localhost:8001
  TEST_SERVER_PID=$!
  sleep 1
  echo "[+] Test Server started with PID $TEST_SERVER_PID, at http://localhost:8001"
  popd > /dev/null 2>&1
fi

## Step 2: Start the Proxy Server for instrumenting the JS & HTML on-the-fly
if [ "$RUN_PROXY" = true ]; then
  check_and_kill_port 8899
  echo "[+] Starting the Proxy Server for instrumenting the JS & HTML on-the-fly..."

  ### Setup the python env firstcd 
  pushd $CONCOLIC_PATH/../proxy-server > /dev/null 2>&1
  ./setup.sh > /dev/null 2>&1 &
  PROXY_SERVER_PID=$!
  sleep 2
  echo "[+] Proxy Server started with PID $PROXY_SERVER_PID"
  popd > /dev/null 2>&1
fi

# Step 3: Start the Local Server for hosting the analysis bundle
if [ "$RUN_ANALYSIS" = true ]; then
  pushd $CONCOLIC_PATH/runtime-analysis > /dev/null 2>&1
  # check_and_kill_port 8002
  echo "[+] Starting the local analysis server for hosting the analysis bundle..."
  npm run deploy > /dev/null 2>&1
  sleep 1
  popd > /dev/null 2>&1
fi


## Step 4: Get back and run the browser
echo "[+] Running the browser..."
pushd $CONCOLIC_PATH/browser > /dev/null 2>&1
node ./browser.js --conf=./config.browser.yml &
popd > /dev/null 2>&1
BROWSER_PID=$!
echo "[+] Browser started with PID $BROWSER_PID"

echo "========================== Start Browser =========================="

cleanup() {
  echo "[+] Cleaning up..."
  if [ -n "$TEST_SERVER_PID" ]; then
    kill $TEST_SERVER_PID
    echo "[+] Killed TEST_SERVER_PID $TEST_SERVER_PID"
  fi
  if [ -n "$PROXY_SERVER_PID" ]; then
    kill $PROXY_SERVER_PID
    echo "[+] Killed PROXY_SERVER_PID $PROXY_SERVER_PID"
  fi
}

wait $BROWSER_PID
echo "[+] Browser process $BROWSER_PID has finished"
cleanup
echo "========================== End Browser =========================="
