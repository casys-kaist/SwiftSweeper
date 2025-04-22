#!/bin/bash

get_library() {
    case $1 in
    "SwiftSweeper")
            echo LD_PRELOAD=libkernel.so
        ;;
    "ffmalloc")
        echo LD_PRELOAD="${HOME}/ffmalloc/libffmallocnpmt.so"
        ;;
    "hushvac")
            echo LD_PRELOAD=${HOME}/hushvac-analyze/libhushvacnpmt.so
        ;;
    "markus")
        echo LD_PRELOAD="${HOME}/markus-allocator/lib/libgc.so:${HOME}/markus-allocator/lib/libgccpp.so"
        ;;
    "minesweeper")
        echo LD_PRELOAD="${HOME}/minesweeper-analyze/lib/libminesweeper.so:${HOME}/minesweeper-analyze/lib/libjemalloc.so"
        ;;
    *)
        echo ""
    ;;
    esac
}