#ifndef FUZZER_H_
#define FUZZER_H_

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "exec/memory.h"
#include "tests/libqtest.h"
#include "migration/qemu-file.h"
#include "ramfile.h"

extern QTestState *s;
extern QEMUFile *writefile;
extern QEMUFile *ramfile;
extern ram_disk *rd;

typedef struct qtest_cmd {
	char name[32];
	uint8_t size;
} qtest_cmd;

typedef uint32_t addr_type;

static qtest_cmd commands[] = 
{
	{"clock_step", 0},
	{"clock_step", 0},
	{"clock_set", 1},
	{"outb", 2},
	{"outw", 2},
	{"outl", 2},
	{"inb", 1},
	{"inw", 1},
	{"inl", 1},
	{"writeb", 2},
	{"writew", 2},
	{"writel", 2},
	{"writeq", 2},
	{"readb", 1},
	{"readw", 1},
	{"readl", 1},
	{"readq", 1},
	{"read", 2},
	{"write", 3},
	{"b64read", 2},
	{"b64write", 10},
	{"memset", 3},
};
void reset(void);
void save_device_state(void);
void setup_qtest(void);
void fuzz_register_mr(const MemoryRegion *mr);
#endif

