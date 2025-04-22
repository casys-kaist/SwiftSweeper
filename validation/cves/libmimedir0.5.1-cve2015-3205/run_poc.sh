#!/bin/bash
# DF Case
RED="\e[31m"
GREEN="\e[32m"
PURPLE="\e[35m"
ENDCOLOR="\e[0m"

BENCH_TARGET=$1
COMM=""

if [ ! -f "free.vcf" ]; then
  python poc.py
fi

source ../loader.sh
LIB=$(get_library $BENCH_TARGET)
COMMAND="LD_LIBRARY_PATH=/usr/local/lib/ ./poc"
COMM="${LIB} ${COMMAND}"

sudo gdb -batch -ex r -ex bt --args env ${COMM} > test_output.txt 2>&1
if grep SIGSEGV ./test_output.txt >/dev/null || grep "Segmentation fault" ./test_output.txt > /dev/null;  then 
    echo "DETECT"
else
  echo "VULNERABLE"
fi