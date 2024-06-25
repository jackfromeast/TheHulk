#!/bin/bash

# Activate the conda environment
source ~/miniconda3/etc/profile.d/conda.sh
conda activate mitmproxy_env

mitmdump --set stream_large_bodies=500m --anticache --quiet -p 8899 -s "proxy.py"