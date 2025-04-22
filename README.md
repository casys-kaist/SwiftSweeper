# IEEE S&P 2025 SwiftSweeper: Defeating Use-After-Free Bugs Using Memory Sweeper Without Stop-the-World
Junho Ahn<sup>1</sup>, Kanghyuk Lee<sup>1</sup>, Chanyoung Park<sup>2</sup>, Hyungon Moon<sup>2</sup> and Youngjin Kwon<sup>1</sup> 
1) School of Computing, KAIST
2) Computer Science and Engineering, UNIST

> The paper is available in [here](https://???).

## Abstraction
Use-after-free (UAF) vulnerabilities pose severe security risks in memory-unsafe languages like C and C++. To mitigate these issues, prior work has employed memory sweeping, inspired by conservative garbage collection. However, such approaches inherit key limitations, including stop-the-world pauses, poor scalability, and high CPU usage, rendering them unsuitable for modern, latency-sensitive applications.

This paper presents SwiftSweeper, a secure memory allocator designed to prevent UAF vulnerabilities in unmodified binaries. SwiftSweeper reimagines memory sweeping by eliminating stop-the-world pauses and enhancing scalability to support high-performance C and C++ workloads. It features an efficient and secure in-kernel data path, implemented using eBPF (XMP, eXpress Memory Path), and a co-designed user-level allocator and kernel. We implement SwiftSweeper on Linux and demonstrate that it delivers state-of-the-art performance, memory efficiency, and minimal latency overhead across both single-threaded and multi-threaded applications, including SPEC CPU and WebServer benchmarks.

For more details, please check the paper.

# SwiftSweeper Artifact Evaluation
## Artifact Appendix
### Abstract
This artifact evaluation introduces the source code, runtime setup, and instructions to reproduce the results of the SwiftSweeper evaluations. We evaluate SwiftSweeper in terms of security, performance, and memory. For security evaluation, we perform CVE analysis, NIST Juliet test suite and HardsHeap. For performance evaluation, we evaluate SwiftSweeper with SPEC CPU 2006, PASEC 3.0, Apache, and Nginx Webserver. This artifact demonstrates that SwiftSweeper can successfully prevent use-after-free (UAF) bugs with minimal impact on performance and memory usage.

### Description & Requirements
#### Hardware Dependencies
There are no hardware dependencies on this project.  
  
We tested SwiftSweeper with Intel(R) Xeon(R) Gold 5220R CPU at 2.2GHz with 24 cores, 172GB DRAM - 2666 MHZ, 512 GB SSD, and 10-Gigabit Network Connection. In all the experiments, we disable hyper-threading, CPU power-saving states, and frequency scaling to reduce the variance. We use Non-Uniform Memory Access (NUMA) in the PARSEC 3.0 benchmarks to fully utilize all 48 cores in the motherboard. 

#### Software Dependencies
SwiftSweeper requires to install clang-17 to support atomic operations in the bpf program. You can use `scripts/setup.sh` to install the clang-17.   

### Set-up
#### SwiftSweeper Installation
SwiftSweeper consists of two distinct components: the kernel and the user space. The SwiftSweeper kernel includes the necessary kernel patches for the eBPF helper functions and custom page fault handler. The SwiftSweeper user space contains both the user-level components and the eBPF custom page fault handler.

##### SwiftSweeper-Kernel installation
First, you need to install the SwiftSweeper Kernel.
1. Clone the SwiftSweeper Kernel repository:
   ```bash
   git clone https://github.com/casys-kaist/SwiftSweeper-Kernel
   ```
2. Get submodules and update. This will clone SwiftSweeper-Kernel repository.
   ```bash
   cd SwiftSweeper
   git submodule init
   git submodule update
   ```
3. Build and install the kernel:
   ```bash
   cd SwiftSweeper-Kernel
   make -j$(nproc)
   sudo make -j$(nproc) INSTALL_MOD_STRIP=1 modules_install
   sudo make install
   ```
4. Reboot your system.
    
After rebooting, install the libbpf library:
1. Navigate to the libbpf directory and build the library:
   ```bash
   cd SwiftSweeper-Kernel/tools/lib/bpf
   make -j$(nproc)
   sudo make install
   ```
2. Install the kernel header files:
   ```bash
   cd SwiftSweeper-Kernel
   sudo make headers_install INSTALL_HDR_PATH=/usr
   ```

Currently, the default path for libbpf is `/usr/local/lib64`. To enable linking, add this path to the linker configuration:
1. Open the linker configuration file:
   ```bash
   sudo vi /etc/ld.so.conf.d/99.conf
   ```
2. Add the following line to `99.conf`:
   ```bash
   /usr/local/lib64
   ```
3. Update the linker cache:
   ```bash
   sudo ldconfig
   ```

##### SwiftSweeper-User installation
After installing the kernel, you can build the SwiftSweeper user part.
1. Move to the SwiftSweeper repository:
   ```bash
   cd SwiftSweeper
   ```
2. Install the Clang-17 compiler:
	```bash
	./scripts/setup.sh
	```
3. Build and install the user components:
   ```bash
   make -j$(nproc)
   sudo make install
   ```
   Default build is **SwiftSweeper-p**(prevent) mode.  
   To build **SwiftSweeper-d(detect)** mode, follow below instruction.
   ```bash
   vim libkernel/include/kconfig.h
   # comment out #define CONFIG_BATCHED_FREE, #define CONFIG_ADOPTIVE_BATCHED_FREE
   make -j$(nproc)
   sudo make install
   ```
   
##### To run the unit tests:
1. Execute the unit tests:
   ```bash
   make unit_test
   ```

### Evaluation workflow
#### Experiments
All results will be stored in `macrobench/result/{test_name}`.

##### 0. Preliminary Step
Before running the script, we recommend extending the sudo authentication timeout:
   ```bash
   sudo visudo
   # Add the line "Defaults:<User_name> timestamp_timeout=600"
   sudo -k
   ```   

In each script, you can set options for your own sake. Available options are as follows: 
* `--LIBCS`: Set library(s) to run. Default value is "glibc SwiftSweeper ffmalloc markus".
* `--TASKSET`: Set thread number of taskset command. Default value is 19. which is required to bind the core and reduce fluctuation. This also limits the additional CPU resources consumed by MarkUs’s GC thread, unlike other test cases
* `--THREADS`: **[Only for PARSEC 3.0]** Set thread numbers to run. Default value is "1 2 4 8 16 32"
* `--CONNECTIONS`: **[Only for Apache2 and Nginx]** Set connection number of benchmark. Default value is "100 200 400 800"
* `--BENCH_SEC`: **[Only for Apache2 and Nginx]** Set the connection time for benchmark. Default value is 30

##### 1. SPEC2006
Before starting, you should obtain and install SPEC2006 in the /home/{USER} directory.
   ```bash
   tar -xvf cpu2006.tar.gz -C /home/{USER}
   mv /home/{USER}/cpu2006 /home/{USER}/SPECCPU_2006
   cd /home/{USER}/SPECCPU_2006
   ./install.sh
   ```

After installing the SPEC2006, you can execute `./bench_sepc2006.sh` to run SPEC CPU 2006 benchmarks. 
```bash
cd macrobench/spec2006
./bench_spec2006.sh [--LIBCS=value] [--TASKSET=value] # This will take a long time to complete.
```

> Note that in SPECCPU 2006 Povray, vmlinux parsing within libbpf increases the peak RSS from 8832 to 15360, with most of the increase attributed to parsing the BTF file. To mitigate this, the BPF arena and bpf_for can be disabled via kconfig.h. Please disable CONFIG_BPF_ARENA and CONFIG_GC_DELTA_MARKING to achive the optimal RSS in Povray. (Disabling these optimizations increases total execution time by approximately 3.4 seconds in Povray.)

###### Expected Result (Performance)
| Benchmark         | 400.perlbench | 401.bzip2  | 403.gcc   | 429.mcf   | 433.milc  | 444.namd  | 445.gobmk | 447.dealII | 450.soplex | 453.povray | 456.hmmer | 458.sjeng | 462.libquantum | 464.h264ref | 470.lbm   | 471.omnetpp | 473.astar  | 482.sphinx3 | 483.xalancbmk | Geomean   | Geomean Ratio | Geomean (Int) | Geomean (Float) |
|------------------|--------------|------------|-----------|-----------|-----------|-----------|-----------|------------|------------|------------|-----------|-----------|---------------|------------|-----------|------------|------------|------------|--------------|------------|---------------|---------------|----------------|
| **glibc**        | 292.595917   | 438.971466 | 228.963681 | 220.122984 | 427.373795 | 356.664520 | 449.639556 | 269.191228  | 186.428111  | 135.836607  | 356.791190 | 503.610604 | 217.442544    | 480.517998 | 289.655700 | 212.264485  | 377.418105  | 468.071953  | 189.681595   | 300.103171 | 1.000000      | 305.969964    | 281.731850      |
| **gBPF arena**   | 322.651080   | 443.611764 | 315.924457 | 226.259518 | 464.989684 | 358.377259 | 454.738792 | 279.586004  | 205.896030  | 138.381485  | 309.875313 | 505.118963 | 215.566097    | 479.796843 | 294.177811 | 245.170289  | 363.879719  | 473.557827  | 228.792231   | 314.461488 | 1.047845      | 334.946427    | 292.897348      |

###### Expected Result (Memory)
| Benchmark         | 400.perlbench | 401.bzip2  | 403.gcc   | 429.mcf   | 433.milc  | 444.namd  | 445.gobmk | 447.dealII | 450.soplex | 453.povray | 456.hmmer | 458.sjeng | 462.libquantum | 464.h264ref | 470.lbm   | 471.omnetpp | 473.astar  | 482.sphinx3 | 483.xalancbmk | Geomean   | Geomean Ratio | Geomean (Int) | Geomean (Float) | Max       |
|------------------|--------------|------------|-----------|-----------|-----------|-----------|-----------|------------|------------|------------|-----------|-----------|---------------|------------|-----------|------------|------------|------------|--------------|------------|---------------|---------------|----------------|-----------|
| **glibc**        | 679536       | 870996     | 907252    | 1717248   | 697364    | 49152     | 31104     | 817940     | 434044     | 7296       | 27264     | 180480    | 99892         | 66616      | 420096    | 175872     | 334992     | 45504      | 430456       | 197281.3003 | 1.000000      | 223959.2576   | 149856.9817    | 1717248   |
| **gBPF arena**   | 892516       | 870008     | 881196    | 1718836   | 692412    | 50524     | 32488     | 835480     | 606176     | 8832       | 36548     | 181684    | 101052        | 55368      | 421308    | 279028     | 538964     | 66108      | 1102828      | 233888.7822 | 1.185560      | 264147.3484   | 171469.5971    | 1718836   |

##### 2. Parsec
Installing PARSEC 3.0.
   ```bash
   cd macrobench/parsec
   sudo ./install.sh

   # If you encounter issues while running install.sh, repeat the following steps until successful:
   cd parsec-benchmark
   sudo rm -rf parsec-3.0*
   cd ../
   sudo ./install.sh
   ```
   
After installing PARSEC, you can execute `./bench_parsec_threads.sh` to run the PARSEC 3.0 benchmarks.
   ```bash
   sudo ./bench_parsec_threads.sh [--LIBCS=value] [--THREADS=value]
   ```

##### 3. Apache
   ```bash
   cd macrobench/apache2
   ./install.sh
   sudo ./bench_apache2.sh [--LIBCS=value] [--CONNECTIONS=value] [--THREADS=value (default 16)] [--BENCH_SEC=value (default 30)]

   # If scripts don’t run as intended, you can manually run host and client on each server.
   # Host
   cd macrobench/common
   sudo ./run_apache_nginx_server.sh <apache2/nginx> <library> <num_threads> "No"

   # Client
   cd macrobench/common
   sudo ./run_apache_nginx_client.sh <apache2/nginx> <Num_connections> <num_threads> <BENCH_SEC> <library>
   ```

##### 4. Nginx
   ```bash
   cd macrobench/nginx
   ./install.sh
   sudo ./bench_nginx.sh [--LIBCS=value] [--CONNECTIONS=value] [--THREADS=value (default 16)] [--BENCH_SEC=value (default 30)]
   ```

##### 5. CVES
   ```bash
   cd validation/cves
   sudo ./install.sh
   make
   # If make stops, Please use this command. This will build programs sequently
   make build_serial

   make run
   vim result.csv   # To check the result
   ```

##### 6. HardsHeap
   ```bash
   cd validation/hardsheap
   ./run_hardsheap.sh
   ```

## Contributors
If you need any further clarification or questions, feel free to contact the authors at the following email.
1. Junho Ahn (junhoahn@kaist.ac.kr)
2. KangHyuk Lee (babamba@kaist.ac.kr)
