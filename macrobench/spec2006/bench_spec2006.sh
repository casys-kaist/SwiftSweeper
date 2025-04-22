#!/bin/bash
if [[ "$EUID" -eq 0 ]]; then
    echo "This script must be run without sudo"
    exit 1
fi

SCRIPT_DIR="$(dirname "$(realpath "$0")")"

THREADS="1"

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help)
            echo "Usage: $0 [--LIBCS=value] [--TASKSET=value]"
            exit 0
            ;;
        --LIBCS=*)
            LIBCS="${1#*=}"
            shift
            ;;
        --TASKSET=*)
            TASKSET="${1#*=}"
            shift
            ;;
        --BENCHES=*)
            BENCH_SELECT="${1#*=}"
            shift
            ;;
        --PARALLEL)
            PARALLEL="1"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [ -z "$LIBCS" ]; then
    LIBCS="glibc SwiftSweeper hushvac markus minesweeper"
fi

if [ -z "$TASKSET" ]; then
    TASKSET="";
fi

if [[ $(uname -r) == "4.0.0-kml" ]] && [[ $LIBCS != "dangzero" ]]; then
    echo "You are trying to run SPECCPU_2006 on a dangzero kernel with a non-dangzero library(s): $LIBCS."
    read -p "This will generate incorrect results. Are you sure? [y/n] "
    if [[ ! $REPLY =~ ^[Yy]$ ]]
    then
        exit 1
    fi
fi

BENCH="400.perlbench 401.bzip2 403.gcc 429.mcf 433.milc 444.namd 445.gobmk 447.dealII 450.soplex 453.povray 456.hmmer 458.sjeng 462.libquantum 464.h264ref 470.lbm 471.omnetpp 473.astar 482.sphinx3 483.xalancbmk"

if [[ $LIBCS == *"dangzero"* ]]; then
    SPEC_FOLDER="/trusted/SPECCPU_2006"
else
    SPEC_FOLDER="/home/$(cut -d/ -f3 <<< "$(realpath $(dirname "$0"))")/SPECCPU_2006"
fi

if [ ! -d "${SPEC_FOLDER}" ]; then
    echo "SPECCPU_2006 not exist!"
    exit 1
fi

for LIBC in $LIBCS
do
    if [ -z "$BENCH_SELECT" ]; then
        if [ -z "$PARALLEL" ]; then
            sudo ${SCRIPT_DIR}/../common/bench_spec.sh --label="${LIBC}" --target="${LIBC}" --bench="SPECCPU_2006" --benchmarks="${BENCH}" --result_label="ALL" --taskset="${TASKSET}"
        else
            sudo ${SCRIPT_DIR}/../common/bench_spec_parallel.sh --label="${LIBC}" --target="${LIBC}" --bench="SPECCPU_2006" --benchmarks="${BENCH}" --result_label="ALL" --taskset="${TASKSET}"
        fi
    else
        if [ -z "$PARALLEL" ]; then
            sudo ${SCRIPT_DIR}/../common/bench_spec.sh --label="${LIBC}" --target="${LIBC}" --bench="SPECCPU_2006" --benchmarks="${BENCH_SELECT}" --result_label="SELECT" --taskset="${TASKSET}"
        else
            sudo ${SCRIPT_DIR}/../common/bench_spec_parallel.sh --label="${LIBC}" --target="${LIBC}" --bench="SPECCPU_2006" --benchmarks="${BENCH_SELECT}" --result_label="SELECT" --taskset="${TASKSET}"
        fi
    fi
    
    sudo mkdir -p ${SCRIPT_DIR}/../result/SPECCPU_2006/${LIBC}
    sudo mv ${SCRIPT_DIR}/../result/SPECCPU_2006/*.result ../result/SPECCPU_2006/${LIBC}
    sudo mv ${SCRIPT_DIR}/../result/SPECCPU_2006/*.time.out* ../result/SPECCPU_2006/${LIBC}
    sudo mv ${SCRIPT_DIR}/../result/SPECCPU_2006/result_${LIBC}_*.csv ../result/SPECCPU_2006/${LIBC}
done
