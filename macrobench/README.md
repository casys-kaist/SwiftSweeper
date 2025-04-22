## Macro benchmarks
> The goal of these experiments is to measure the macrobench of SwiftSweeper.
> We prepared 4 experiments: apache2, nginx, parsec, and SPEC2006.

## How to run
### Apache2
   ```
   cd macrobench/apache2
   ./install.sh
   ./bench_apache2.sh
   ```

### Nginx
   ```
   cd macrobench/nginx
   ./install.sh
   ./bench_nginx.sh
   ```

### SPEC2006
```
# Before run, you should install SPEC2006 in home directory

$ cd SPEC{version}
$ bench_spec{version}.sh
```

### parsec
```
$ install.sh
$ bench_parsec.sh
```