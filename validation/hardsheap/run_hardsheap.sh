#!/bin/bash

sudo apt install -y build-essential libboost-system-dev libboost-thread-dev libboost-program-options-dev libboost-test-dev libboost-filesystem-dev

if [ ! -d "HardsHeap" ]; then
    git clone git@github.com:kaist-hacking/HardsHeap.git
fi

mkdir -p ./HardsHeap/artifact/secure-allocators/SwiftSweeper/
cp run.sh ./HardsHeap/artifact/secure-allocators/SwiftSweeper/

cd ./HardsHeap/
./build.sh
./setup.sh
cd artifact
rm -rf output
./run.py -r $(pwd)/../ -o output

