THEHULK_PATH=$(pwd)

### 1/ Install crawler
pushd $THEHULK_PATH/crawler
npm install
popd

### 2/ Install proxy-server
pushd $THEHULK_PATH/proxy-server
pip install -r requirements.txt
npm install
popd

### 3/ Install the dependencies: Jalangi2
pushd $THEHULK_PATH/libs/jalangi2
npm install
popd
