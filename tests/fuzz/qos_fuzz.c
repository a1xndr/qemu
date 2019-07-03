

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "sysemu/sysemu.h"
#include "qemu/main-loop.h"

#include "libqos/malloc.h"
#include "libqos/qgraph.h"
#include "libqos/qgraph_internal.h"

#include "hw/virtio/virtio-net.h"
#include "hw/virtio/virtio.h"
#include "libqos/virtio-net.h"
#include "fuzz.h"
#include "qos_fuzz.h"
#include "qos_helpers.h"
#include "tests/libqtest.h"


#define PCI_SLOT_HP             0x06
#define PCI_SLOT                0x04
#define QVIRTIO_NET_TIMEOUT_US (30 * 1000)
#define VNET_HDR_SIZE sizeof(struct virtio_net_hdr_mrg_rxbuf)

fuzz_memory_region *fuzz_memory_region_head;
fuzz_memory_region *fuzz_memory_region_tail;

uint64_t total_io_mem = 0;
uint64_t total_ram_mem = 0;


typedef struct qos_arg {
	const unsigned char *data;
	size_t size;
} qos_arg;


// Do what is normally done in qos_test.c:main
void qos_setup(void){
	qos_graph_init();
     module_call_init(MODULE_INIT_QOM);
    module_call_init(MODULE_INIT_LIBQOS);
	qos_set_machines_devices_available();
	qos_print_graph();
    qos_graph_foreach_test_path(walk_path);
	run_one_test(fuzz_path_vec);
}

/* static void hotplug(void *obj, void *data, QGuestAllocator *t_alloc) */
/* { */
/*     QVirtioPCIDevice *dev = obj; */
/*     QTestState *qts = dev->pdev->bus->qts; */
/*     const char *arch = qtest_get_arch(); */

/*     qtest_qmp_device_add("virtio-net-pci", "net1", */
/*                          "{'addr': %s}", stringify(PCI_SLOT_HP)); */

/*     if (strcmp(arch, "i386") == 0 || strcmp(arch, "x86_64") == 0) { */
/*         qpci_unplug_acpi_device_test(qts, "net1", PCI_SLOT_HP); */
/*     } */
/* } */


/* static void qos_fuzz_func_mmio_io(void *obj, char *Data, size_t Size, QGuestAllocator *t_alloc) */


static void qos_fuzz_func(void *obj, char *Data, size_t Size, QGuestAllocator *t_alloc)
{
	uint64_t req_addr;
    uint32_t free_head;
	
    QVirtioNet *net_if = obj;
    QVirtioDevice *dev = net_if->vdev;
    /* QVirtQueue *rx = net_if->queues[0]; */
    QVirtQueue *q;
	for(int i=0; i<3; i++)
	{
		qvirtqueue_cleanup(dev->bus, net_if->queues[i], t_alloc);
		net_if->queues[i] = qvirtqueue_setup(dev, t_alloc, i);
	}
	uint8_t queue;
	uint8_t length;
	while(true) {
		if(Size < sizeof(queue) + sizeof(length))
		{
			return;
		}
		queue = ((uint8_t) Data[0]) %3; 
		length = Data[1];
		Data +=2*sizeof(queue);
		Size -= sizeof(queue) + sizeof(length);
		if( length>=Size ){
			length=Size;
		}
		q = net_if->queues[queue];
		req_addr = guest_alloc(t_alloc, length);
		memwrite(req_addr, Data, length);
		free_head = qvirtqueue_add(q, req_addr, length, false, false);
		qvirtqueue_kick(dev, q, free_head);
		qtest_clock_step_next(s);
		main_loop_wait(false);
		/* qvirtio_wait_used_elem(dev, q, free_head, NULL, QVIRTIO_NET_TIMEOUT_US); */

		guest_free(t_alloc, req_addr);
	}

}

int qos_fuzz(const unsigned char *Data, size_t Size){
	/* printf("NEW FUZZ RUN\n"); */
	if(Size<4)
		return 0;
	qos_fuzz_func(qos_obj, (char *)Data, Size, qos_alloc);
	reset();
	return 0;
}

static void *virtio_net_test_setup_nosocket(GString *cmd_line, void *arg)
{
    g_string_append(cmd_line, " -netdev hubport,hubid=0,id=hs0 ");
    return arg;
}

static void register_virtio_net_test(void)
{
	QOSGraphTestOptions opts = {
        .before = virtio_net_test_setup_nosocket,
	};
	qos_add_test("basic", "virtio-net", NULL, &opts);
}

libqos_init(register_virtio_net_test);
