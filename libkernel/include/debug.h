#ifndef __LIB_DEBUG_H
#define __LIB_DEBUG_H

#include <sys/resource.h>

/* GCC lets us add "attributes" to functions, function
 * parameters, etc. to indicate their properties.
 * See the GCC manual for details. */
#define UNUSED __attribute__((unused))
#define NO_RETURN __attribute__((noreturn))
#define NO_INLINE __attribute__((noinline))
#define PRINTF_FORMAT(FMT, FIRST) __attribute__((format(printf, FMT, FIRST)))
#define MAX_BACKTRACE_LEVEL 16

#ifndef __printf
#define __printf(fmt, args) __attribute__((format(printf, (fmt), (args))))
#endif

#ifdef CONFIG_DEBUG_ALLOC
#define debug_printk(fmt, args...) printk(fmt, ##args)
#else
#define debug_printk(fmt, args...) ((void)0)
#endif

#define print_rss()                                                                                                                                            \
	do {                                                                                                                                                   \
		struct rusage usage;                                                                                                                           \
		if (getrusage(RUSAGE_SELF, &usage) == 0) {                                                                                                     \
			printk("Current RSS: %ld KB\n", usage.ru_maxrss);                                                                                      \
		} else {                                                                                                                                       \
			printk("getrusage failed");                                                                                                                   \
		}                                                                                                                                              \
	} while (0)

/* Halts the OS, printing the source file name, line number, and
 * function name, plus a user-specific message. */
#define PANIC(...) debug_panic(__FILE__, __LINE__, __func__, __VA_ARGS__)
#define TODO(...) debug_panic(__FILE__, __LINE__, __func__, "todo!")

void debug_panic(const char *file, int line, const char *function, const char *message, ...) PRINTF_FORMAT(4, 5) NO_RETURN;
void debug_backtrace(void);

int printk(const char *fmt, ...) __printf(1, 2);

#endif // end of #ifndef __LIB_DEBUG_H

/* This is outside the header guard so that debug.h may be
 * included multiple times with different settings of NDEBUG. */
#undef ASSERT
#undef UNREACHABLE

#ifndef CONFIG_NDEBUG
#define ASSERT(CONDITION)                                                                                                                                      \
	if ((CONDITION)) {                                                                                                                                     \
	} else {                                                                                                                                               \
		PANIC("assertion %s failed.", #CONDITION);                                                                                                     \
	}
#define UNREACHABLE() PANIC("executed an unreachable statement");
#else
#define ASSERT(CONDITION) ((void)0);
#define UNREACHABLE() for (;;)
#endif /* lib/debug.h */
