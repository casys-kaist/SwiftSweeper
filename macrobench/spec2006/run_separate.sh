#!/bin/bash

TIMEOUT="1800"
BENCHES="400.perlbench 401.bzip2 403.gcc 429.mcf 433.milc 444.namd 445.gobmk 447.dealII 450.soplex 453.povray 456.hmmer 458.sjeng 462.libquantum 464.h264ref 470.lbm 471.omnetpp 473.astar 482.sphinx3 483.xalancbmk"

for BENCH in $BENCHES; do
    ./bench_spec2006.sh --LIBCS="SwiftSweeper" --BENCHES="$BENCH" &
    PID=$!

    (
        sleep $TIMEOUT
        if ps -p $PID > /dev/null; then
            echo "Process exceeded time limit of $TIMEOUT seconds. Killing it."
            kill -9 $PID
        fi
    ) &

    # Wait for the command to complete
    wait $PID
    EXIT_STATUS=$?

    # Check if the command finished naturally
    if [ $EXIT_STATUS -eq 0 ]; then
        echo "Process completed successfully within time limit."
    else
        echo "Process was terminated due to timeout or other issue."
    fi
done