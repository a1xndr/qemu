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

typedef struct FuzzTarget {
	GString* name;
	GString* description;
	void(*init_pre_main)(void);
	void(*init_pre_save)(void);
	void(*save_state)(void);
	void(*reset)(void);
	void(*pre_fuzz)(void);
	void(*fuzz)(const unsigned char*, size_t);
	void(*post_fuzz)(void);
	int* main_argc;
	char*** main_argv;
	QSLIST_ENTRY(FuzzTarget) target_list;

} FuzzTarget;



void save_device_state(void);
void save_vm_state(void);
void reboot(void);

void load_device_state(void);
void load_vm_state(void);


void save_device_state(void);
void setup_qtest(void);
void fuzz_register_mr(const MemoryRegion *mr);

FuzzTarget* fuzz_get_target(char* name);

extern FuzzTarget* fuzz_target;

void fuzz_add_target(const char* name,
	const char* description,
	void(*init_pre_main)(void),
	void(*init_pre_save)(void),
	void(*save_state)(void),
	void(*reset)(void),
	void(*pre_fuzz)(void),
	void(*fuzz)(const unsigned char*, size_t),
	void(*post_fuzz)(void),
	int* main_argc,
	char*** main_argv);

int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size);
int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp);

#endif

