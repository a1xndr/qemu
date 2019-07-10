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
#include "tests/libqtest.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "exec/ioport.h"
#include "ramfile.h"
#include "migration/qemu-file.h"
#include "migration/global_state.h"
#include "migration/savevm.h"
#include "qos_helpers.h"

#include "tests/libqos/qgraph.h"
#include "tests/libqos/qgraph_internal.h"
#include "tests/libqos/virtio-net.h"
#include "hw/virtio/virtio-net.h"

#include "qtest_fuzz.h"
#include "qos_fuzz.h"
#include "fuzz.h"


void usage(void);
int LLVMFuzzerTestOneInput(const unsigned char *Data, size_t Size);
int LLVMFuzzerInitialize(int *argc, char ***argv, char ***envp);
int fuzz_i440(const unsigned char *Data, size_t Size);
int fuzz_ports(const unsigned char *Data, size_t Size);
int qtest_test(const unsigned char *Data, size_t Size);


int fuzz_argc = 5;
const char *fuzz_argv[] = {"qemu-system-i386",
    "-machine",
    "accel=fuzz",
	/* "-m", */
	/* "1M", */
    "-display",
    "none"};

const char *fuzz_envp[] = {"qemu-system-x86_64", "-accel=fuzz"};

int (*fuzzer)(const unsigned char *Data, size_t Size);

Error *err = NULL;
size_t len;

typedef struct port_fuzz_unit {
	uint8_t addr1;
	uint8_t addr2;
	uint8_t data;
} port_fuzz_unit;
typedef struct i440_fuzz_unit {
	uint32_t data[3];
} i440_fuzz_unit;
typedef struct qtest_unit {
	uint8_t action;
	uint32_t op1;
	uint32_t op2;
} qtest_unit;


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
		u++;
		main_loop_wait(false);
	}
	/* reset(); */
    return 0;
}

int fuzz_ports(const unsigned char *Data, size_t Size){

	for(int i=0; i<20442; i++){
		/* printf("HERE %d!\n", i); */
		if(i==20438){
				cpu_outb( 0x3f8, 0x1b);
				cpu_outb( 0x3f8, 0x5b);
				cpu_outb( 0x3f8, 0x31);
				cpu_outb( 0x3f8, 0x4b);
		}
		/* /1* main_loop_wait(false); *1/ */
		cpu_outb( 0x3f8, 0);
		/* printf("\n"); */
	}


	/* reset(); */
    return 0;
}

int qtest_test(const unsigned char *Data, size_t Size){
	/* int i = 0; */
	char *u = (char*)Data;
	char buffer[1000];
	/* int i =0; */
	char *g = u;
	int i =0;
	while(g != NULL)
	{
		char *h = (char*)memchr(g, '\n', Size-(g-u));
		if(h==NULL || h==g || g[0] == 0){
			break;
		}
		i+=h-g;
		sprintf(buffer, "%.*s\n",(int)(h-g),g);
		printf("Sending Command: %s", buffer);
		qtest_send_to_server(s,"%s", buffer);
		printf("Received back: '%s'\n", qtest_recv_line(s)->str);
		g = h+1;
		main_loop_wait(false);
	}
	/* reset(); */
	return 0;
}


