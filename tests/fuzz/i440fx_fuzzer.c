/*
 * =====================================================================================
 *
 *       Filename:  i440fx_fuzzer.c
 *
 *    Description:  Fuzz the i440fx PCI Bridge
 *
 *         Author:  Alexander Oleinik (), alxndr@bu.edu
 *
 * =====================================================================================
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"
#include "sysemu/cpus.h"
#include "qemu/main-loop.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "exec/ioport.h"

void usage(void);
int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size);
int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp);
void reset(void);
int fuzz_i440(const unsigned char *Data, size_t Size);
int fuzz_ports(const unsigned char *Data, size_t Size);

int fuzz_argc = 5;
const char *fuzz_argv[] = {"qemu-system-x86_64",
    "-machine",
    "accel=fuzz",
    "-display",
    "none"};

const char *fuzz_envp[] = {"qemu-system-x86_64", "-accel=fuzz"};

int (*fuzzer)(const unsigned char *Data, size_t Size);

typedef struct port_fuzz_unit {
	uint16_t addr;
	uint32_t data;
} port_fuzz_unit;

typedef struct i440_fuzz_unit {
	uint32_t data[3];
} i440_fuzz_unit;

void reset(void){
    pause_all_vcpus();
    qemu_system_reset(SHUTDOWN_CAUSE_GUEST_RESET);
    resume_all_vcpus();
	if (!runstate_check(RUN_STATE_RUNNING) &&
			!runstate_check(RUN_STATE_INMIGRATE))
		runstate_set(RUN_STATE_PRELAUNCH);
	main_loop_wait(false);
}

// Fuzz Reads and Writes to the i440 using ports 0x0CF8 and 0x0CFC
int fuzz_i440(const unsigned char *Data, size_t Size){
	int i = 0;
	uint32_t indata;
	i440_fuzz_unit *u = (i440_fuzz_unit*)Data;
	while( (i+1)*sizeof(i440_fuzz_unit) < Size)
	{
		// These addresses cause false-positives or stalls
		cpu_outl( 0x0CF8, u->data[0]);
		cpu_outl( 0x0CFC, u->data[1]);
		cpu_outl( 0x0CF8, u->data[2]);
		indata = cpu_inl( 0x0CFC);
		i++;
		Data++;
		main_loop_wait(false);
	}
	reset();
    return 0;
}

int fuzz_ports(const unsigned char *Data, size_t Size){
	int i = 0;
	port_fuzz_unit *u = (port_fuzz_unit*)Data;
	while( (i+1)*sizeof(port_fuzz_unit) < Size)
	{
		/* printf("0x%x\n", u->addr); */
		// These addresses cause false-positives or stalls
		if(u->addr == 0x518 ||
				(u->addr >= 0x5655 && u->addr <= 0x565a ) ||
				(u->addr >= 0xb000 && u->addr <= 0xb0ff ) ||
				u->addr ==  0xb100) 
			break;
		cpu_outl( u->addr, u->data);
		i++;
		Data++;
		main_loop_wait(false);
	}
	reset();
    return 0;
}

int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size)
{
	return fuzzer(Data, Size);
}

void usage(void) {
	printf("Usage: ./fuzz [--i440fx|--ports] [LIBFUZZER ARGUMENTS]\n");
	exit(0);
}
int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp)
{
	if(*argc <= 1)
		usage();
	char *target = (*argv)[1];

	if( strcmp(target, "--i440fx") == 0 )
		fuzzer = &fuzz_i440;
	else if( strcmp(target, "--ports") == 0 )
		fuzzer = &fuzz_ports;
	else
		usage();


	if(target[0] )
    // Call vl.c:main which will return just before main_loop()
    real_main(fuzz_argc, (char**)fuzz_argv, (char**)fuzz_envp);
    return 0;
}

