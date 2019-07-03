#ifndef _QOS_FUZZ_H_
#define _QOS_FUZZ_H_

int qos_fuzz(const unsigned char *Data, size_t Size);
void qos_setup(void);


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

#endif
