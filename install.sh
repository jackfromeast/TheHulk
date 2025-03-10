#!/bin/bash

THEHULK_PATH=$(pwd)

### 1/ Install crawler
pushd $THEHULK_PATH/crawler
npm install
popd

### 2/ Install proxy-server
if ! command -v conda &> /dev/null; then
    echo "Miniconda is not installed. Installing Miniconda..."
    wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O miniconda.sh
    bash miniconda.sh -b -p $HOME/miniconda3
    rm miniconda.sh
    export PATH="$HOME/miniconda3/bin:$PATH"
    conda init bash
    source ~/.bashrc
fi

# Create the conda environment if it doesn't exist
if ! conda env list | grep -q "mitmproxy_env"; then
    echo "Creating conda environment 'mitmproxy_env'..."
    conda create -n mitmproxy_env python=3.8 -y
fi

# Activate the conda environment
source ~/miniconda3/etc/profile.d/conda.sh
conda activate mitmproxy_env

# Install requirements in the conda environment
pushd $THEHULK_PATH/proxy-server
pip install -r requirements.txt
npm install
popd

### 3/ Install concolic execution engin
pushd $THEHULK_PATH/gadget-detection
npm install
popd

### 3/ Install the dependencies: Jalangi2
pushd $THEHULK_PATH/libs/jalangi2
npm install
popd
