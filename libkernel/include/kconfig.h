/* Debug Settings */
#define CONFIG_NDEBUG 1 /* Disable all debug options, including mimalloc and ota */
// #define CONFIG_DEBUG_ALLOC 1 /* Print each alloc/free operation */
// #define CONFIG_DEBUG_GC 1 /* Print garbage collection operations */
// #define CONFIG_DEBUG_LOCK 1 /* Print each lock/unlock operation */
// #define CONFIG_DEBUG_MIMALLOC 1 /* Debug mimalloc */
// #define CONFIG_MEMORY_DEBUG 1 /* Print memory usage statistics */
// #define CONFIG_FORCE_GC 1 /* Forecefully execute gc at SLEEP_TIME_INTERVAL_MIN */
// #define CONFIG_TIME_BREAKDOWN 1 /* Check mark & sweep time */

/* Page Fault Settings */
#define CONFIG_PF_PREFETCH_MAX 32 /* Maximum prefetch multiplier for page fault */

/* Garbage Collector Settings */
#define CONFIG_ENABLE_GC 1 /* Enable garbage collector */
#define CONFIG_ENABLE_CONCURRENT_GC 1 /* Disable stop-the-world. otherwise, use stop-the-world */
#define CONFIG_GC_DELTA_MARKING 1 /* Enable delta marking, which skips pointer marking from stack. */
#define CONFIG_GC_DELTA_FULL_PATH_THRESHOLD 0.2 /* Threshold for delta marking */
#define CONFIG_GC_THREAD 1 /* Execute garbage collector using thread */
#define CONFIG_ON_DEMAND_GC_BATCH_SIZE 32 /* Batch size for on-demand garbage collection */
#define CONFIG_GC_INTERVAL 256 /* Interval of each gc bytes. May increase performance, but decrease the latency */
// #define CONFIG_GC_ALLOW_CYCLIC 1 /* Allow cyclic pointer from large pool for the performance. (In the paper, we turn it off.) */

/* GC Sleep Interval Settings */
#define CONFIG_GC_SLEEP_TIME_INTERVAL_MIN 1000000000ULL
#define CONFIG_GC_SLEEP_TIME_INTERVAL_MAX 16000000000ULL
#define CONFIG_GC_SLEEP_MINIMUM_THRESHOLD (1024 * 48)
#define CONFIG_GC_SLEEP_FRAG_INTERVAL 0.2 /* Fragmentation rate for triggering garbage collection */
#define CONFIG_GC_SLEEP_FRAG_CHANGE_THRESHOLD 0.1 /* Significant change threshold for fragmentation rate */
#define CONFIG_GC_SLEEP_FORCE_THRESHOLD 0.8 /* Force garbage collection if fragmentation rate exceeds this threshold */

/* BPF Feature */
#define CONFIG_BPF_ARENA 1 /* (WARN! Increase the Peak RSS due to a vmlinux parsing) Enable bpf arena */

/* Extra security options */
// #define CONFIG_SECURITY_PKRU 1 /* Enable PKRU security for metadata protection. */
