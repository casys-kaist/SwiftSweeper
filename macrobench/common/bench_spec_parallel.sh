#!/bin/bash

if [ "$#" -lt 5 ]; then
    echo "Usage: $0 [--label=value] [--target=value] [--threads=value] [--bench=value] [--benchmarks=value] [OPTIONS]"
    exit 1
fi

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -h|--help)
            echo "Usage: $0 [--label=value] [--target=value] [--threads=value] [--bench=value] [--benchmarks=value] [OPTIONS]"
            exit 0
            ;;
        --label=*)
            LABEL="${1#*=}"
            shift
            ;;
        --target=*)
            export BENCH_TARGET="${1#*=}"
            shift
            ;;
        --iter=*)
            ITER="${1#*=}"
            shift
            ;;
        --threads=*)
            THREADS="${1#*=}"
            shift
            ;;
        --bench=*)
            BENCHES="${1#*=}"
            shift
            ;;
        --benchmarks=*)
            BENCHMARKS="${1#*=}"
            shift
            ;;

        # OPTIONAL from here
        --out_folder=*)
            OUT_FOLDER="${1#*=}"
            shift
            ;;
        --result_label=*)
            RESULT_LABEL="${1#*=}"
            shift
            ;;
        --taskset=*)
            TASKSET="${1#*=}"
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

HOME=$(realpath $(dirname "$0"))

function main {
    if [ ! -d "${HOME}/../result/${BENCHES}" ]; then
        mkdir -p ${HOME}/../result/${BENCHES}
    fi

    if [ "$LABEL" == "dangzero" ]; then
        DIR_SPEC="/trusted/${BENCHES}" # for dangzero
    else
        DIR_SPEC="/home/$(cut -d/ -f3 <<< "$HOME")/${BENCHES}"
    fi
    
    DIR_CONFIG="$HOME"

    if [ -z $OUT_FOLDER ]; then
        export DIR_RESULT=${DIR_CONFIG}/../result/${BENCHES}
    else
        export DIR_RESULT=${OUT_FOLDER}
    fi

    mkdir -p /tmp/spec

    if [ "$BENCHES" == "SPECCPU_2006" ]; then
        cp ${DIR_CONFIG}/../common/eval.sh /tmp/spec/eval-2006.sh
    else
        cp ${DIR_CONFIG}/../common/eval.sh /tmp/spec/eval-2017.sh
    fi

    # Lauch spec
    cd $DIR_SPEC
    source $DIR_SPEC/shrc

    ## Required Setup for benchmark
    #Get current stack size limit
    current_limit=$(ulimit -s)

    # Check if the limit is unlimited or greater than or equal to 122880
    if [ "$current_limit" != "unlimited" ] && [ "$current_limit" -lt 122880 ]; then
        # Set the stack size limit to 122880
        ulimit -s 122880
        echo "Stack size limit updated to 122880"
    fi

    ### End of setup
    BENCHMARK_RUNNING_PATTERN="Running Benchmarks"
    SUCCESS=""
    FAIL=""
    UNKNOWN=""

    BENCH_LEFT=$(wc -w <<< "$BENCHMARKS")
    REQUIRED_CORES_PER_BENCH=3

    # Parse TASKSET range or use all cores if TASKSET is not set
    if [ ! -z "$TASKSET" ]; then
        IFS='-' read -r TASKSET_START TASKSET_END <<< "$TASKSET"
        AVAILABLE_CORES=$(seq $TASKSET_START $TASKSET_END)
    else
        TASKSET_START=0
        TASKSET_END=$(( $(nproc) - 1 ))
        AVAILABLE_CORES=$(seq $TASKSET_START $TASKSET_END)
    fi

    # Calculate the total cores in the TASKSET range
    TOTAL_CORES=$(echo "$AVAILABLE_CORES" | wc -w)
    TOTAL_REQUIRED_CORES=$((BENCH_LEFT * REQUIRED_CORES_PER_BENCH))

    # Check if there are enough cores
    if [ "$TOTAL_REQUIRED_CORES" -gt "$TOTAL_CORES" ]; then
        echo "Error: Not enough CPU cores available in the specified TASKSET range ($TASKSET). At least $TOTAL_REQUIRED_CORES cores are required."
        exit 1
    fi

    # Allocate cores for each benchmark
    declare -a CORE_RANGES
    index=0
    for BENCH in $BENCHMARKS; do
        start_core=$(echo "$AVAILABLE_CORES" | awk "NR==$((index * REQUIRED_CORES_PER_BENCH + 1))")
        end_core=$(echo "$AVAILABLE_CORES" | awk "NR==$(((index + 1) * REQUIRED_CORES_PER_BENCH))")
        CORE_RANGES+=("$start_core-$end_core")
        ((index++))
    done

    # Run benchmarks concurrently
    index=0
    for BENCH in $BENCHMARKS; do
        (
            cores="${CORE_RANGES[$index]}"

            result_path="$DIR_RESULT/$BENCH.result"
            PREFIX="taskset -c $cores"

            output_csv="$DIR_RESULT/result_${LABEL}_PARALLEL_${BENCH}.csv"
            echo "benchmark_name, max_rss, elapsed_time, speclog_path" > $output_csv

            if [ "$BENCHES" == "SPECCPU_2006" ]; then
                $PREFIX runspec --iterations 1 --size "ref" --action onlyrun --config  $DIR_CONFIG/../spec2006/spec_config.cfg --noreportable $BENCH | tee $result_path
            else 
                $PREFIX runcpu --action onlyrun --iterations 1 --size ref --threads $THREADS --config=$DIR_CONFIG/../spec2017/spec_config.cfg $BENCH | tee $result_path
            fi

            max_rss=0
            elapsed_time=0
            if grep -q "$BENCHMARK_RUNNING_PATTERN" "$result_path"; then
                if tail -n 15 "$result_path" | grep -q "Error"; then
                    FAIL+="$BENCH "
                    max_rss="failed"
                    elapsed_time="failed"
                elif grep -q "Run Complete" "$result_path"; then
                    SUCCESS+="$BENCH "

                    timeout_file_prefix="$DIR_RESULT/$BENCH.time.out"

                    # Iterate over files of time out and get the maximum RSS
                    for timeout_file in $timeout_file_prefix*; do
                        if [ -f "$timeout_file" ]; then
                            rss=$(grep "Maximum resident set size" $timeout_file | awk '{print $6}')
                            if (( rss > max_rss )); then
                                max_rss=$rss
                            fi
                        fi
                    done

                    # Extract elapsed time from the output
                    speclog_path=$(grep "The log for this run is in" $result_path | awk '{print $8}')
                    elapsed_time=$(tail -n 20 $speclog_path | grep "runtime=" | awk -F'=' '{print $3}' | cut -d ',' -f1)
                else
                    UNKNOWN+="$BENCH "
                    max_rss="unknown error"
                    elapsed_time="unknown error"
                fi
            fi

            # Format: benchmark_name, max_rss, elapsed_time
            echo "$BENCH, $max_rss, $elapsed_time, $speclog_path" >> "$output_csv"
        ) &
        ((index++))
    done

    # Wait for all background jobs to finish
    wait

    echo "Benchmark success: $SUCCESS"
    echo "Benchmark fail: $FAIL"
    echo "Benchmark unknown: $UNKNOWN"
}

source $HOME/../environment
main