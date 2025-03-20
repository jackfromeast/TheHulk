#!/bin/bash

THEHULK_PATH=$(pwd)

# Define green color for echo
GREEN='\033[0;32m'
NC='\033[0m' # No Color

### Install nodejs, npm, http-server
echo -e "${GREEN}Installing nodejs, npm, and http-server...${NC}"
sudo apt update
sudo apt install -y nodejs npm
sudo npm install -g http-server

### Install crawler
echo -e "${GREEN}Installing crawler dependencies...${NC}"
pushd $THEHULK_PATH/crawler
npm install
popd

### Install proxy-server
if ! command -v conda &> /dev/null; then
    echo -e "${GREEN}Miniconda is not installed. Installing Miniconda...${NC}"
    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O miniconda.sh
    bash miniconda.sh -b -p $HOME/miniconda3
    rm miniconda.sh
    export PATH="$HOME/miniconda3/bin:$PATH"
    conda init bash
    source ~/.bashrc
fi

# Create the conda environment if it doesn't exist
if ! conda env list | grep -q "mitmproxy_env"; then
    echo -e "${GREEN}Creating conda environment 'mitmproxy_env'...${NC}"
    conda create -n mitmproxy_env python=3.8 -y
fi

# Activate the conda environment
source ~/miniconda3/etc/profile.d/conda.sh
conda activate mitmproxy_env

## TODO: Install the certificate of proxy server

# Install requirements in the conda environment
echo -e "${GREEN}Installing proxy-server dependencies...${NC}"
pushd $THEHULK_PATH/proxy-server
pip install -r requirements.txt
npm install
popd

### Install taint engine
echo -e "${GREEN}Installing taint engine dependencies...${NC}"
pushd $THEHULK_PATH/gadget-detection
npm install
popd

### Install exploit generation engine
echo -e "${GREEN}Installing exploit generation engine dependencies...${NC}"
pushd $THEHULK_PATH/exploit-gen
npm install
popd

### Install the dependencies: Jalangi2
echo -e "${GREEN}Installing Jalangi2 dependencies...${NC}"
pushd $THEHULK_PATH/libs/jalangi2
npm install
popd

### Install dom-clobbering-collection 
echo -e "${GREEN}Installing dom-clobbering-collection dependencies...${NC}"
pushd $THEHULK_PATH/dataset/dom-clobbering-collection/domc-gadgets-assets/attacker.com
npm install
popd

### Setup the network proxy for testing
echo -e "${GREEN}Setting up the network proxy for testing...${NC}"

# Set proxy environment variables
export http_proxy=http://127.0.0.1:8899
export https_proxy=http://127.0.0.1:8899

# Make the proxy settings persistent by adding them to ~/.bashrc
if ! grep -q "http_proxy=http://127.0.0.1:8899" ~/.bashrc; then
    echo "export http_proxy=http://127.0.0.1:8899" >> ~/.bashrc
    echo "export https_proxy=http://127.0.0.1:8899" >> ~/.bashrc
    echo -e "${GREEN}Proxy settings added to ~/.bashrc for persistence.${NC}"
fi

# Apply the proxy settings to the current session
source ~/.bashrc

echo -e "${GREEN}Network proxy set to http://127.0.0.1:8899${NC}"
echo -e "${GREEN}Installation and proxy setup completed successfully.${NC}"