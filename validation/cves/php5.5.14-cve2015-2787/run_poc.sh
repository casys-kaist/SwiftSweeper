#!/bin/bash
RED="\e[31m"
GREEN="\e[32m"
PURPLE="\e[35m"
ENDCOLOR="\e[0m"

BENCH_TARGET=$1
COMM=""
UAF_POINT="ext/standard/var_unserializer.c:1243"

source ../loader.sh
LIB=$(get_library $BENCH_TARGET)
COMMAND="./php-5.5.14/sapi/cli/php -f ./poc.php"
COMM="${LIB} ${COMMAND}"


sudo gdb -batch -ex r -ex bt --args env ${COMM} > test_output.txt 2>&1
if grep SIGSEGV ./test_output.txt >/dev/null || grep SIGABRT ./test_output.txt > /dev/null;  then 
  if grep "${UAF_POINT}" ./test_output.txt > /dev/null; then 
    echo "DETECT"
  else 
    echo "PREVENT"
  fi
else
  echo "VULNERABLE"
fi