clean:

populate:
	./redis_populate.py -k 2000000 -d 1400000 -s 8192 perm
#	sleep 5s
#	./redis_populate.py -k 2000000 -s 8192 perm

benchmark:
	./redis-benchmark -t get -f key_list.txt -n 20000000 -r 20000000 -c 50 -q -P 1
