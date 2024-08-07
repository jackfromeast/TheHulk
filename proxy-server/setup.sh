#!/bin/bash

# Activate the conda environment
source ~/miniconda3/etc/profile.d/conda.sh
conda activate mitmproxy_env

ENV_PATH=$(conda info --base)/envs/mitmproxy_env
SCRIPT_PATH=$(realpath "$0")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

# Export PYTHONPATH with the absolute path
mitmdump --set stream_large_bodies=500m --anticache --quiet -p 8899 -s "$SCRIPT_DIR/proxy.py"