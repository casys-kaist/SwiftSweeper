#!/bin/bash
RED="\e[31m"
GREEN="\e[32m"
PURPLE="\e[35m"
ENDCOLOR="\e[0m"

BENCH_TARGET=$1
COMM=""
UAF_POINT="var_unserializer.c:1254"

source ../loader.sh
LIB=$(get_library $BENCH_TARGET)
COMMAND="./php-5.4.44/sapi/cli/php -f ./poc.php"
COMM="${LIB} ${COMMAND}"


GLIBC_OUTPUT=$(sh -c "./php-5.4.44/sapi/cli/php -f ./poc.php")  2>/dev/null
COMM_OUTPUT=$(sudo sh -c "${COMM}")  2>/dev/null

sudo gdb -batch -ex r -ex bt --args env ${COMM} > test_output.txt 2>&1
if grep SIGSEGV ./test_output.txt >/dev/null || grep SIGABRT ./test_output.txt > /dev/null;  then 
  if grep "${UAF_POINT}" ./test_output.txt > /dev/null; then 
    echo "DETECT"
  else 
    echo "PREVENT"
  fi
else
  if [ "$GLIBC_OUTPUT" = "$COMM_OUTPUT" ]; then 
  echo "VULNERABLE"
  else 
  echo "PREVENT"
  fi
fi