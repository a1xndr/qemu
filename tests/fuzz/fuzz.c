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
	/* printf("Resetting...\n"); */
	/* qemu_system_reset(SHUTDOWN_CAUSE_GUEST_RESET); */
	vm_stop(RUN_STATE_RESTORE_VM);
	qemu_system_reset(SHUTDOWN_CAUSE_NONE);
	migration_incoming_state_destroy();
	qemu_freopen_ro_ram(ramfile);
	/* int ret = qemu_load_device_state(ramfile); */
	int ret = qemu_loadvm_state(ramfile);
	if (ret < 0){
		printf("reset error\n");
		/* exit(-1); */
	}
}

void save_device_state(void) {
	writefile = qemu_fopen_ram(&rd);
	global_state_store();
	qemu_savevm_state(writefile, NULL);
	/* qemu_save_device_state(writefile); */
	qemu_fflush(writefile);
	ramfile = qemu_fopen_ro_ram(rd);

	// Skip the device-state header which causes a complaint during load
}

void setup_qtest(void) {
	s = qtest_init_fuzz(NULL, NULL);
	global_qtest = s;
}
