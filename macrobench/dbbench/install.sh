#!/bin/bash

# build dependencies
sudo apt-get install -y libgflags-dev libsnappy-dev zlib1g-dev libbz2-dev liblz4-dev libzstd-dev

git clone https://github.com/facebook/rocksdb.git
cd rocksdb
make -j$(nproc) release

