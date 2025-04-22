#!/usr/bin/env python3
import argparse
import sys
import numpy as np
import multiprocessing as mp
import redis
import os
from itertools import chain

redis_conn = redis.Redis(host='localhost', port=6379, db=0)

def gen_seq(args):
    return range(args.num_keys)

def gen_perm(args):
    return np.random.permutation(args.num_keys)

def gen_uni_task(args):
    np.random.seed(None)
    args, n_reqs = args
    return [(100 * np.random.randint(args.num_keys // 100)
             + np.random.randint(args.percent))
            for _ in range(n_reqs)]

def gen_uni(args):
    assert(args.num_keys % 100 == 0)
    assert(0 < args.percent <= 100)

    n_cpus = mp.cpu_count()
    n_reqs_list = [args.num_reqs // n_cpus + ((args.num_reqs % n_cpus) if i == 0 else 0) for i in range(n_cpus)]

    with mp.Pool(n_cpus) as pool:
        keys_list = pool.map(gen_uni_task, [(args, n_reqs) for n_reqs in n_reqs_list])

    return list(chain(*keys_list))

def gen_zipf_task(args):
    np.random.seed(None)
    dist_map, n_reqs = args

    u = np.random.random(n_reqs)
    return np.searchsorted(dist_map, u) - 1

def gen_zipf(args):
    class ZipfGenerator:
        # https://stackoverflow.com/questions/31027739/python-custom-zipf-number-generator-performing-poorly
        def __init__(self, n, alpha):
            tmp = np.power(np.arange(1, n+1) , -alpha)
            zeta = np.r_[0, np.cumsum(tmp)]
            self.dist_map = zeta / zeta[-1]

        def next(self, n=1):
            u = np.random.random(n)
            return np.searchsorted(self.dist_map, u) - 1

    zgen = ZipfGenerator(args.num_keys, args.skew)

    n_cpus = mp.cpu_count()
    n_reqs_list = [args.num_reqs // n_cpus + ((args.num_reqs % n_cpus) if i == 0 else 0) for i in range(n_cpus)]
    with mp.Pool(n_cpus) as pool:
        keys_list = pool.map(gen_zipf_task, [(zgen.dist_map, n_reqs) for n_reqs in n_reqs_list])

    return list(chain(*keys_list))

def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='key pattern')

    parser_seq = subparsers.add_parser('seq', help='sequential pattern')
    parser_seq.set_defaults(generate=gen_seq)

    parser_perm = subparsers.add_parser('perm', help='permutation pattern')
    parser_perm.set_defaults(generate=gen_perm)

    parser_uni = subparsers.add_parser('unif', help='uniform pattern')
    parser_uni.add_argument('-r', '--num-reqs', type=int, required=True)
    parser_uni.add_argument('-p', '--percent', type=int, required=True)
    parser_uni.set_defaults(generate=gen_uni)

    parser_zipf = subparsers.add_parser('zipf', help='zipfian pattern')
    parser_zipf.add_argument('-r', '--num-reqs', type=int, required=True)
    parser_zipf.add_argument('-s', '--skew', type=float, required=True)
    parser_zipf.set_defaults(generate=gen_zipf)

    parser.add_argument('-k', '--num-keys', type=int, help='insert keys', required=True)
    parser.add_argument('-d', '--num-delete-keys', type=int, help='number of delete keys', default=0)
    parser.add_argument('-n', '--requests', type=int, help='Total number of requests', default=100000)
    parser.add_argument('-s', '--size', type=int, help='Data size of SET/GET value in bytes', default=4096)

    return parser.parse_args()

def main():
    args = parse_args()

    # Write sequential keys to redis
    f = open("write_key_list.txt", "w")
    for key in range(args.num_keys):
        if key == 0:
            f.write(str(key))
        else:
            f.write(' ' + str(key))
    f.write('\n')
    f.close()

    os.system("./redis-benchmark -t set -f write_key_list.txt -q -d " + str(args.size) + " -n " + str(args.num_keys))
    os.remove("write_key_list.txt")

    # Delete random keys from redis
    keys = args.generate(args)
    f = open("delete_key_list.txt", "w")
    f2 = open("key_list.txt", "w")

    for i, key in enumerate(keys):
        if(i < args.num_delete_keys):
            if i == 0:
                f.write(str(key))
            else:
                f.write(' ' + str(key))
        else:
            if i == args.num_delete_keys:
                f2.write(str(key))
            else:
                f2.write(' ' + str(key))
    f.write('\n')
    f2.write('\n')
    f.close()
    f2.close()

    os.system("./redis-benchmark -t del -f delete_key_list.txt -q -n " + str(args.num_delete_keys))
    os.remove("delete_key_list.txt")

    # Sample benchmark
    # os.system("./redis-benchmark -t get -c 50 -P 1024 -f key_list.txt -n " + str(args.requests))
    # os.remove("key_list.txt")
    # Our redis benchmark also modify -r option to generate random index for key_list.txt
    # Thus to generate dupulicated random sequence from perm or uni, use -r option with required key size
    # os.system("./redis-benchmark -t get -c 50 -P 1024 -f key_list.txt -r 100000000 -n " + str(args.requests))
    # os.remove("key_list.txt")

if __name__ == '__main__':
    main()

