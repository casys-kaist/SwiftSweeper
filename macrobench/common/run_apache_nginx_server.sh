#!/bin/bash


function library {
    USER_NAME=$(cut -d/ -f3 <<< "$(realpath $0)")
    HOME="/home/${USER_NAME}"

    case "$1" in
    "SwiftSweeper")
        echo LD_PRELOAD=libkernel.so
        ;;
    "ffmalloc")
        echo LD_PRELOAD="$HOME/ffmalloc/libffmallocnpmt.so"
        ;;
    "markus")
        echo LD_PRELOAD="$HOME/markus-allocator/lib/libgc.so:$HOME/markus-allocator/lib/libgccpp.so"
        ;;
    "minesweeper")
        echo LD_PRELOAD="$HOME/minesweeper-analyze/lib/libminesweeper.so:$HOME/minesweeper-analyze/lib/libjemalloc.so"
        ;;
    "hushvac")
        echo LD_PRELOAD="$HOME/hushvac/libhushvacnpmt.so"
        ;;
    "hushvac+")
        echo LD_PRELOAD="$HOME/hushvac-analyze/libhushvacnpmt.so"
        ;;
    * )
        ;;
esac
}

if [ "$#" -lt 2 ]; then
    echo "Usage : $0 <program: apache2/nginx> <library> <worker: default 16> <foreground/background>"
    exit 1
fi

if [ "$4" == "background" ]; then
    if [ ! -p "/tmp/wait" ]; then
        echo "You should run with "/tmp/wait" pipe enabled!"
        exit 1
    fi
fi

SCRIPT_DIR=$(realpath $(dirname "$0"))
FILE_SIZE=64
if [ "$1" == "apache2" ]; then
    FILE_PATH="$SCRIPT_DIR/../$1/${FILE_SIZE}bytes.txt"
    export UNSET_RTLD_DEEPBIND=1
elif [ "$1" == "nginx" ]; then
    FILE_PATH="/usr/local/nginx/html/${FILE_SIZE}bytes.txt"
else
    echo "Usage : $0 <program: apache2/nginx> <library> <worker: default 16> <foreground/background>"
    exit 1
fi

if [ -z "$3" ] || [ "$3" == "" ]; then
    WORKER=16
else
    WORKER=$3
fi

echo "Run $1 with $2 library"

PREFIX=$(library $2)
echo $PREFIX

TASKSET="taskset -c 0-31"

sudo dd if=/dev/urandom of="$FILE_PATH" bs=1 count="$FILE_SIZE"
${SCRIPT_DIR}/track_memory.sh $1 &
TRACK_PID="$!"

if [ "$4" == "background" ]; then
    if [ "$2" == "dangzero" ]; then
        sudo ${PREFIX} ${TASKSET} /trusted/nginx/nginx -c $SCRIPT_DIR/../$1/nginx.conf -g "worker_processes $WORKER;" & # for dangzero
    elif [ "$1" == "apache2" ]; then
        sudo ${PREFIX} ${TASKSET} $SCRIPT_DIR/../$1/httpd/bin/httpd -D FOREGROUND -f $SCRIPT_DIR/../$1/httpd.conf &
    else
        sudo ${PREFIX} ${TASKSET} $SCRIPT_DIR/../$1/nginx-1.24.0/objs/nginx -c $SCRIPT_DIR/../$1/nginx.conf -g "worker_processes $WORKER;" &
    fi
else
    if [ "$2" == "dangzero" ]; then
        sudo ${PREFIX} ${TASKSET} /trusted/nginx/nginx -c $SCRIPT_DIR/../$1/nginx.conf -g "worker_processes $WORKER;" # for dangzero
    elif [ "$1" == "apache2" ]; then
        sudo ${PREFIX} ${TASKSET} $SCRIPT_DIR/../$1/httpd/bin/httpd -D FOREGROUND -f $SCRIPT_DIR/../$1/httpd.conf
    else
        sudo ${PREFIX} ${TASKSET} $SCRIPT_DIR/../$1/nginx-1.24.0/objs/nginx -c $SCRIPT_DIR/../$1/nginx.conf -g "worker_processes $WORKER;"
    fi
fi

if [ "$4" == "background" ]; then
    PID="$!"
    echo "$1 start" > "/tmp/wait"

    # Wait until worker finished
    cat < "/tmp/wait" > /dev/null

    sudo kill -9 $PID $TRACK_PID
    sudo pkill -x nginx

    # Signal to bench
    echo "clean finished" > "/tmp/wait"
fi