## The regression test for taint tracking analysis
## The task is to run the crawler with & without taint tracking analysis on the real-world websites
## It helps us to make sure the instrumention and analysis is side-effect free

## 1/ Run the normal crawler given the config.scheduler.normal.yml and config.browser.normal.yml
## 2/ Run the crawler with taint tracking analysis given the config.scheduler.analysis.yml and config.browser.analysis.yml
## 3/ Diff the console logs on the two runs generate the report

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
  if [ -n "$BROWSER_PID" ]; then
    kill $BROWSER_PID
    echo "[+] Killed BROWSER_PID $BROWSER_PID"
  fi
}

trap cleanup EXIT

check_and_kill_port() {
  local PORT=$1
  local PID=$(lsof -ti:$PORT)
  if [ -n "$PID" ]; then
    echo "[!] Port $PORT is in use by process $PID. Killing the process..."
    kill -9 $PID > /dev/null 2>&1
  fi
}

# Ensure the script is run under the concolic-engine path
SCRIPT_PATH=$(realpath "$0")
TASK_PATH=$(dirname "$SCRIPT_PATH")
CONCOLIC_PATH=$(realpath $TASK_PATH/../../)
THEHULK_PATH=$(realpath $CONCOLIC_PATH/../)
if [ "$(basename $CONCOLIC_PATH)" != "concolic-engine" ]; then
  echo "[!] Please run this script from the concolic-engine directory."
  exit 1
fi

## 0/ Clear the previous outputs
rm -rf $TASK_PATH/output/*


## 1/ Run the normal crawler
pushd $THEHULK_PATH/crawler/src/ > /dev/null 2>&1
node ./scheduler.js --scheduler-config $TASK_PATH/config.scheduler.normal.yml --crawler-config $TASK_PATH/config.browser.normal.yml
popd > /dev/null 2>&1
echo "[+] Normal Crawler finished."


## 2/ Run the crawler with taint tracking analysis
## 2-1/: Start the Proxy Server for instrumenting the JS & HTML on-the-fly
RUN_PROXY=true
RUN_ANALYSIS=true
if [ "$RUN_PROXY" = true ]; then
  check_and_kill_port 8899
  echo "[+] Starting the Proxy Server for instrumenting the JS & HTML on-the-fly..."

  ### Setup the python env first
  pushd $THEHULK_PATH/proxy-server > /dev/null 2>&1
  ./setup.sh > /dev/null 2>&1 &
  PROXY_SERVER_PID=$!
  sleep 1
  echo "[+] Proxy Server started with PID $PROXY_SERVER_PID"
  popd > /dev/null 2>&1
fi

## 2-2/: Refresh the latest analysis bundle
if [ "$RUN_ANALYSIS" = true ]; then
  pushd $CONCOLIC_PATH/runtime-analysis > /dev/null 2>&1
  echo "[+] Compile the lastest analysis bundle..."
  npm run deploy > /dev/null 2>&1
  sleep 1
  popd > /dev/null 2>&1
fi

## 2-3/: run the task
pushd $THEHULK_PATH/crawler/src/ > /dev/null 2>&1
node ./scheduler.js --scheduler-config $TASK_PATH/config.scheduler.analysis.yml --crawler-config $TASK_PATH/config.browser.analysis.yml
popd > /dev/null 2>&1
echo "[+] Crawler with analysis finished."


## 3/ Diff the console logs on the two runs generate the report
pushd $TASK_PATH/ > /dev/null 2>&1
node ./post-process.js
popd > /dev/null 2>&1
echo "[+] Post-process finished."