check_and_kill_port() {
  local PORT=$1
  local PID=$(lsof -ti:$PORT)
  if [ -n "$PID" ]; then
    echo "[!] Port $PORT is in use by process $PID. Killing the process..."
    kill -9 $PID > /dev/null 2>&1
  fi
}

# Ensure the script is run under the gadget-detection path
SCRIPT_PATH=$(realpath "$0")
TASK_PATH=$(dirname "$SCRIPT_PATH")
ROOT_PATH=$(realpath $TASK_PATH/../../)


pushd $ROOT_PATH/crawler/src/ > /dev/null 2>&1
node ./scheduler.js --scheduler-config $TASK_PATH/config.scheduler.yml --crawler-config $TASK_PATH/config.browser.yml &
popd > /dev/null 2>&1
BROWSER_PID=$!
echo "[+] Browser started with PID $BROWSER_PID"

echo "========================== Start task running =========================="

wait $BROWSER_PID
echo "[+] Browser process $BROWSER_PID has finished"

echo "========================== Task End Running =========================="
