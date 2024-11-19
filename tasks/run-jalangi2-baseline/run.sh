## 1/ Start the test pages
## 2/ Start the proxy server
## 3/ Start the task.js

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

RUN_TEST=true
RUN_PROXY=true
RUN_ANALYSIS=false

# Step 1: Start the Test Server for hosting the test pages
# We currently don't use this 
if [ "$RUN_TEST" = true ]; then
  check_and_kill_port 8001
  pushd $THEHULK_PATH/tests/jalangi2-test > /dev/null 2>&1
  http-server test-pages -p 8001 -d false -c-1 > /dev/null 2>&1 &
  curl -s http://localhost:8001
  TEST_SERVER_PID=$!
  sleep 1
  echo "[+] Test Server started with PID $TEST_SERVER_PID, at http://localhost:8001"
  popd > /dev/null 2>&1
fi

## Step 2: Start the Proxy Server for instrumenting the JS & HTML on-the-fly
if [ "$RUN_PROXY" = true ]; then
  check_and_kill_port 8877
  echo "[+] Starting the Proxy Server for instrumenting the JS & HTML on-the-fly..."

  ### Setup the python env first
  pushd $THEHULK_PATH/proxy-server > /dev/null 2>&1
  ./setup.sh > /dev/null 2>&1 &
  PROXY_SERVER_PID=$!
  sleep 1
  echo "[+] Proxy Server started with PID $PROXY_SERVER_PID"
  popd > /dev/null 2>&1
fi

# Step 3: Refresh the latest analysis bundle
if [ "$RUN_ANALYSIS" = true ]; then
  pushd $CONCOLIC_PATH/runtime-analysis > /dev/null 2>&1
  echo "[+] Compile the lastest analysis bundle..."
  npm run deploy > /dev/null 2>&1
  sleep 1
  popd > /dev/null 2>&1
fi

## Step 4: Get back and run the task
pushd $THEHULK_PATH/crawler/src/ > /dev/null 2>&1
node ./scheduler.js --scheduler-config $TASK_PATH/config.scheduler.yml --crawler-config $TASK_PATH/config.browser.yml &
popd > /dev/null 2>&1
BROWSER_PID=$!
echo "[+] Browser started with PID $BROWSER_PID"

echo "========================== Start task running =========================="

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

wait $BROWSER_PID
echo "[+] Browser process $BROWSER_PID has finished"

echo "========================== Task End Running =========================="
