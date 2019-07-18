

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "sysemu/sysemu.h"
#include "qemu/main-loop.h"
#include <wordexp.h>
#include "qemu-common.h"


#include "fuzz.h"
#include "qtest_fuzz.h"
#include "tests/libqtest.h"
#include "fuzz/qos_fuzz.h"


static void enum_memory(void) {
	mtree_info(true, true, true);
	fuzz_memory_region *fmr = g_new0(fuzz_memory_region, 1);

	fmr->io = false;
	fmr->start = 0x100000;
	fmr->length = 0x10000;
	fmr->next = fuzz_memory_region_head;
	fuzz_memory_region_tail->next = fmr;
	fuzz_memory_region_tail = fmr;
	fmr = fuzz_memory_region_head;

	while(true){
		printf("%lx:%lx\n", fmr->start, fmr->length);
		fmr = fmr->next;
		if(fmr == fuzz_memory_region_head)
			break;
	}
	/* printf("Totals %ld %ld", total_io_mem, total_ram_mem); */
	/* exit(0); */
}

static uint16_t normalize_io_port(uint64_t addr) {
	if(!fuzz_memory_region_head)
		enum_memory();
	addr = addr%total_io_mem;
	fuzz_memory_region *fmr = fuzz_memory_region_head;
	while(addr!=0) {
		if(!fmr->io){
			fmr = fmr->next;
			continue;
		}
		if(addr <= fmr->length)
		{
			addr= fmr->start + addr;
			break;
		}
		addr -= fmr->length +1;
		fmr = fmr->next;
	}
	if(addr>=0x5655 && addr<=0x565b)
		return 0;
	if(addr>=0x510 && addr<=0x518)
		return 0;
	if(addr>=0xae00 && addr<=0xae13) // PCI Hotplug
		return 0;
	if(addr>=0xaf00 && addr<=0xaf1f) // CPU Hotplug
		return 0;
	return addr;
}

static uint16_t normalize_mem_addr(uint64_t addr) {
	if(!fuzz_memory_region_head)
		enum_memory();
	addr = addr%total_ram_mem;
	fuzz_memory_region *fmr = fuzz_memory_region_head;
	while(addr!=0) {
		if(fmr->io){
			fmr = fmr->next;
			continue;
		}
		if(addr <= fmr->length)
		{
			return fmr->start + addr;
		}
		addr -= fmr->length +1;
		fmr = fmr->next;
	}
	return addr;
}

static void qtest_fuzz(const unsigned char *Data, size_t Size){
	const unsigned char *pos = Data;
	const unsigned char *End = Data + Size;

	qtest_cmd *cmd;
	
	while(pos < Data+Size)
	{
		// What is the command?
		cmd = &commands[(*pos)%(sizeof(commands)/sizeof(qtest_cmd))];
		pos++;
		
		if(strcmp(cmd->name, "clock_step") == 0){
			/* qtest_clock_step_next(s); */
		} // TODO: Add second clock_step
		/* else if(strcmp(cmd->name, "clock_set")) { */
		/* 	if(pos + sizeof(int64_t) < End) { */
		/* 		qtest_clock_set(s, *(int64_t*)(pos)); */
		/* 		pos += sizeof(int64_t); */
		/* 	} */
		/* } */
		else if(strcmp(cmd->name, "outb") == 0) {
			if(pos + sizeof(uint16_t) + sizeof(uint8_t) < End) {
				uint16_t addr = *(int16_t*)(pos);
				pos += sizeof(uint16_t);
				uint8_t val = *(uint16_t*)(pos);
				pos += sizeof(uint8_t);
				addr = normalize_io_port(addr);
				qtest_outb(s, addr, val);
			}
		}
		else if(strcmp(cmd->name, "outw") == 0) {
			if(pos + sizeof(uint16_t) + sizeof(uint16_t) < End) {
				uint16_t addr = *(int16_t*)(pos);
				pos += sizeof(uint16_t);
				uint16_t val = *(uint16_t*)(pos);
				pos += sizeof(uint16_t);
				addr = normalize_io_port(addr);
				qtest_outw(s, addr, val);
			}
		}
		else if(strcmp(cmd->name, "outl") == 0) {
			if(pos + sizeof(uint16_t) + sizeof(uint32_t) < End) {
				uint16_t addr = *(int16_t*)(pos);
				pos += sizeof(uint16_t);
				uint32_t val = *(uint32_t*)(pos);
				pos += sizeof(uint32_t);
				addr = normalize_io_port(addr);
				qtest_outl(s, addr, val);
			}
		}
		else if(strcmp(cmd->name, "inb") == 0) {
			if(pos + sizeof(uint16_t) < End) {
				uint16_t addr = *(int16_t*)(pos);
				pos += sizeof(uint16_t);
				addr = normalize_io_port(addr);
				qtest_inb(s, addr);
			}
		}
		else if(strcmp(cmd->name, "inw") == 0) {
			if(pos + sizeof(uint16_t) < End) {
				uint16_t addr = *(int16_t*)(pos);
				pos += sizeof(uint16_t);
				addr = normalize_io_port(addr);
				qtest_inw(s, addr);
			}
		}
		else if(strcmp(cmd->name, "inl") == 0) {
			if(pos + sizeof(uint16_t) < End) {
				uint16_t addr = *(int16_t*)(pos);
				pos += sizeof(uint16_t);
				addr = normalize_io_port(addr);
				qtest_inl(s, addr);
			}
		}
		else if(strcmp(cmd->name, "writeb") == 0) {
			if(pos + sizeof(uint32_t) + sizeof(uint8_t) < End) {
				uint32_t addr = *(int32_t*)(pos);
				pos += sizeof(uint32_t);
				uint8_t val = *(uint8_t*)(pos);
				pos += sizeof(uint8_t);
				addr = normalize_mem_addr(addr);
				qtest_writeb(s, addr, val);
			}
		}
		else if(strcmp(cmd->name, "writew") == 0) {
			if(pos + sizeof(uint32_t) + sizeof(uint16_t) < End) {
				uint32_t addr = *(int32_t*)(pos);
				pos += sizeof(uint32_t);
				uint16_t val = *(uint16_t*)(pos);
				pos += sizeof(uint16_t);
				addr = normalize_mem_addr(addr);
				qtest_writew(s, addr, val);
			}
		}
		else if(strcmp(cmd->name, "writel") == 0) {
			if(pos + sizeof(uint32_t) + sizeof(uint32_t) < End) {
				uint32_t addr = *(int32_t*)(pos);
				pos += sizeof(uint32_t);
				uint32_t val = *(uint32_t*)(pos);
				pos += sizeof(uint32_t);
				addr = normalize_mem_addr(addr);
				qtest_writel(s, addr, val);
			}
		}
		else if(strcmp(cmd->name, "readb") == 0) {
			if(pos + sizeof(uint32_t) < End) {
				uint32_t addr = *(int32_t*)(pos);
				pos += sizeof(uint32_t);
				addr = normalize_mem_addr(addr);
				qtest_readb(s, addr);
			}
		}
		else if(strcmp(cmd->name, "readw") == 0) {
			if(pos + sizeof(uint32_t) < End) {
				uint32_t addr = *(int32_t*)(pos);
				pos += sizeof(uint32_t);
				addr = normalize_mem_addr(addr);
				qtest_readw(s, addr);
			}
		}
		else if(strcmp(cmd->name, "readl") == 0) {
			if(pos + sizeof(uint32_t) < End) {
				uint32_t addr = *(int32_t*)(pos);
				pos += sizeof(uint32_t);
				addr = normalize_mem_addr(addr);
				qtest_readl(s, addr);
			}
		}
		else if(strcmp(cmd->name, "write_dma") == 0) {
			if(pos + sizeof(uint32_t) + sizeof(uint16_t) < End) {
				uint32_t addr = *(int32_t*)(pos);
				pos += sizeof(uint32_t);
				uint32_t val = 0x100000;
				addr = normalize_mem_addr(addr);
				qtest_writel(s, addr, val);
			}
		}
		else if(strcmp(cmd->name, "out_dma") == 0) {
			if(pos + sizeof(uint16_t) + sizeof(uint16_t) < End) {
				uint16_t addr = *(int16_t*)(pos);
				pos += sizeof(uint16_t);
				uint32_t val = 0x100000;
				addr = normalize_io_port(addr);
				qtest_outl(s, addr, val);
			}
		}
		// Now get the system up and running
		g_string_free(qtest_recv_line(s), true);
		main_loop_wait(false);
	}
}

static void *net_test_setup_nosocket(GString *cmd_line, void *arg)
{
	g_string_append(cmd_line, " -netdev hubport,hubid=0,id=hs0 ");
	return arg;
}
int qtest_argc;
char **qtest_argv;
static void register_qtest_fuzz_targets(void)
{
	QOSGraphTestOptions opts = {
		.before = net_test_setup_nosocket,
	};
	fuzz_add_qos_target("qtest-dma-fuzz", "fuzz qtest dma",
			"e1000e", &opts, &qos_setup, &qos_init_path, &save_device_state, &load_device_state,
			NULL, &qtest_fuzz, NULL);
	GString *cmd_line = g_string_new("qemu-system-i386 -display none -machine accel=fuzz -m 3"); //TODO: correct this
	wordexp_t result;
	wordexp (cmd_line->str, &result, 0);
	qtest_argc = result.we_wordc;
	qtest_argv = result.we_wordv;
	g_string_free(cmd_line, true);
	
	/* fuzz_add_target("qtest-dma-fuzz", "fuzz qtest dma", */
	/* 		&qtest_setup, NULL, NULL, &reboot, */
	/* 		NULL, &qtest_fuzz, NULL, &qtest_argc, &qtest_argv); */
	
}

fuzz_target_init(register_qtest_fuzz_targets);

