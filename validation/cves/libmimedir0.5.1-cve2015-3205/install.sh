#!/bin/bash

tar -xf libmimedir-0.5.1.tar.gz
sudo chown -R $(whoami).$(whoami) libmimedir-0.5.1
cd libmimedir-0.5.1
./configure
make
# sudo make install
# cp /usr/local/lib/libmimedir.* /lib/
# sudo cp /usr/local/lib/libmimedir.* /lib/

curr_dir=$(dirname $0)
echo $curr_dir

cd ..
gcc -g poc.c -o poc -L$curr_dir/libmimedir-0.5.1/.libs -lmimedir