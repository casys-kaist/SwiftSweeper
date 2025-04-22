ALL_MOD = $(shell find . -maxdepth 1 -mindepth 1 -type d) 
ALL_MOD_CLEAN = $(addsuffix .clean, $(ALL_MOD))

.PHONY: $(ALL_MOD_CLEAN) $(ALL_MOD) clean

$(ALL_MOD_CLEAN): 
	@if [ -e $(basename $@)/Makefile ] ; then \
		if [ $(basename $@) != "redis" ] ; then \
        	$(MAKE) -C $(basename $@) clean ;\
		fi; \
	fi 
	rm -rf ./config*
	rm -rf mnt
	rm -rf result
	rm -rf bench
	rm -rf ./redis_bench/redis-benchmark

redis: 
	if [ ! -d "./redis" ]; then \
		git clone https://github.com/redis/redis.git; \
	fi
	cd redis && git checkout 663fbd345 && cd ..
	cp ./redis_bench/redis-benchmark.c ./redis/src/
	$(MAKE) -C ./redis/ MALLOC=libc -j 12
	cp ./redis/src/redis-benchmark ./redis_bench/

clean: $(ALL_MOD_CLEAN)
    $(E) "cleaning complete: " $(ALL_MOD)
