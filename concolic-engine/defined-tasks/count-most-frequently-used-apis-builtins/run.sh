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

RUN_TEST=false
RUN_PROXY=true
RUN_ANALYSIS=true

# Step 1: Start the Test Server for hosting the test pages
# We currently don't use this 
if [ "$RUN_TEST" = true ]; then
  check_and_kill_port 8001
  pushd $THEHULK_PATH/tests/taint-tracking-builtins > /dev/null 2>&1
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

  pushd $THEHULK_PATH/proxy-server > /dev/null 2>&1
  ./setup.sh > /dev/null 2>&1 &
  PROXY_SERVER_PID=$!
  sleep 1
  echo "[+] Proxy Server started with PID $PROXY_SERVER_PID"

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

echo "========================== Task Start Running =========================="

wait $TEST_SERVER_PID $PROXY_SERVER_PID $BROWSER_PID

echo "========================== Task End Running =========================="

# Step 5: Clean up the results
# pushd $TASK_PATH > /dev/null 2>&1
# echo "[+] Post processing the results..."
# node $TASK_PATH/post-process.js
# popd > /dev/null 2>&1