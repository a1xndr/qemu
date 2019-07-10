#ifndef _QOS_FUZZ_H_
#define _QOS_FUZZ_H_

#include "tests/libqos/qgraph.h"

int qos_fuzz(const unsigned char *Data, size_t Size);
void qos_setup(void);

extern char **fuzz_path_vec;
extern int qos_argc;
extern char **qos_argv;
extern void* qos_obj;
extern QGuestAllocator *qos_alloc;

typedef struct fuzz_memory_region {
	bool io;
	uint64_t start;
	uint64_t length;
	struct fuzz_memory_region* next;
} fuzz_memory_region;

extern fuzz_memory_region *fuzz_memory_region_head;
extern fuzz_memory_region *fuzz_memory_region_tail;

extern uint64_t total_io_mem;
extern uint64_t total_ram_mem;

void fuzz_add_qos_target(const char* name,
		const char* description,
		const char* interface,
		QOSGraphTestOptions* opts,
		void(*init_pre_main)(void),
		void(*init_pre_save)(void),
		void(*save_state)(void),
		void(*reset)(void),
		void(*pre_fuzz)(void),
		void(*fuzz)(const unsigned char*, size_t),
		void(*post_fuzz)(void));

void qos_init_path(void);
#endif
