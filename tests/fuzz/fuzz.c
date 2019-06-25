#include "ramfile.h"
#include "migration/qemu-file.h"
#include "migration/global_state.h"
#include "migration/savevm.h"
#include "tests/libqtest.h"
#include "exec/memory.h"
#include "migration/migration.h"
#include "fuzz.h"

QTestState *s;

QEMUFile *ramfile;
QEMUFile *writefile;
ram_disk *rd;



uint64_t total_mr_size = 0;
uint64_t mr_index = 0;

const MemoryRegion* mrs[1000];

void fuzz_register_mr(const MemoryRegion *mr)
{
	/* printf("Registering MR: %s 0x%lx 0x%lx \n", mr->name, (uint64_t)mr->addr, (uint64_t)mr->size); */
	/* mrs[mr_index++]= mr; */
	/* total_mr_size += mr->size; */
}

void reset(void){
	/* mtree_info(1,1,0); */
	/* for(int i = 0; i<mr_index; i++) */
	/* { */
	/* printf("Registering MR (ram = %d): %s 0x%lx \n", mrs[i]->ram, mrs[i]->name, (uint64_t)(mrs[i]->addr)); */
	/* } */
	qemu_freopen_ro_ram(ramfile);
	//int ret = qemu_loadvm_state(ramfile);
	int ret = qemu_load_device_state(ramfile);
	if (ret < 0)
		exit(-1);
}

void save_device_state(void) {
	writefile = qemu_fopen_ram(&rd);
	global_state_store();
	/* qemu_savevm_state(writefile, NULL); */
	qemu_save_device_state(writefile);
	qemu_fflush(writefile);
	ramfile = qemu_fopen_ro_ram(rd);

	// Skip the device-state header which causes a complaint during load
}

void setup_qtest(void) {
	s = qtest_init_fuzz(NULL, NULL);
}
