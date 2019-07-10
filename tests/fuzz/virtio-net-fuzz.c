#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "exec/memory.h"
#include "sysemu/sysemu.h"
#include "qemu/main-loop.h"

#include "hw/virtio/virtio-net.h"
#include "hw/virtio/virtio.h"
#include "libqos/virtio-net.h"

#include "fuzz.h"
#include "qos_fuzz.h"

typedef struct vq_action {
	uint8_t queue;
	uint8_t length;
	uint8_t write;
	uint8_t next;
	bool kick;
} vq_action;

static void virtio_net_ctrl_fuzz(const unsigned char *Data, size_t Size)
{
	uint64_t req_addr[10];
	int reqi =0;
	uint32_t free_head;
	
	QGuestAllocator *t_alloc = qos_alloc;

	QVirtioNet *net_if = qos_obj;
	QVirtioDevice *dev = net_if->vdev;
	QVirtQueue *q;
	vq_action vqa;
	int iters=0;
	while(true) {
		if(Size < sizeof(vqa)) {
			break;
		}
		vqa = *((vq_action*)Data);
		Data += sizeof(vqa);
		Size -= sizeof(vqa);

		q = net_if->queues[2];

		vqa.length = vqa.length >= Size ? Size :  vqa.length;

		req_addr[reqi] = guest_alloc(t_alloc, vqa.length);
		memwrite(req_addr[reqi], Data, vqa.length);
		if(iters == 0)
			free_head = qvirtqueue_add(q, req_addr[reqi], vqa.length, vqa.write , vqa.next) ;
		else
			qvirtqueue_add(q, req_addr[reqi], vqa.length, vqa.write , vqa.next) ;
		iters++;
		reqi++;
		if(iters==10)
			break;
		Data += vqa.length;
		Size -= vqa.length;
	}
	if(iters){
		qvirtqueue_kick(dev, q, free_head);
		qtest_clock_step_next(s);
		main_loop_wait(false);
		/* qvirtio_wait_used_elem(dev, q, free_head, NULL, QVIRTIO_NET_TIMEOUT_US); */
		for(int i =0; i<reqi; i++)
		guest_free(t_alloc, req_addr[i]);
	}
}

static void virtio_net_ctrl_fuzz_multi(const unsigned char *Data, size_t Size)
{
	uint64_t req_addr[10];
	int reqi =0;
	uint32_t free_head;
	
	QGuestAllocator *t_alloc = qos_alloc;

	QVirtioNet *net_if = qos_obj;
	QVirtioDevice *dev = net_if->vdev;
	QVirtQueue *q;
	vq_action vqa;
	int iters=0;
	while(Size >= sizeof(vqa)) {
		vqa = *((vq_action*)Data);
		Data += sizeof(vqa);
		Size -= sizeof(vqa);
		if(vqa.kick && free_head)
		{
			qvirtqueue_kick(dev, q, free_head);
			qtest_clock_step_next(s);
			main_loop_wait(false);
			for(int i =0; i<reqi; i++)
				guest_free(t_alloc, req_addr[i]);
			reqi = 0;
		}
		else {
			q = net_if->queues[2];

			vqa.length = vqa.length >= Size ? Size :  vqa.length;

			req_addr[reqi] = guest_alloc(t_alloc, vqa.length);
			memwrite(req_addr[reqi], Data, vqa.length);
			if(iters == 0)
				free_head = qvirtqueue_add(q, req_addr[reqi], vqa.length, vqa.write , vqa.next) ;
			else
				qvirtqueue_add(q, req_addr[reqi], vqa.length, vqa.write , vqa.next) ;
			iters++;
			reqi++;
			if(iters==10)
				break;
			Data += vqa.length;
			Size -= vqa.length;
		}
	}
}

static void virtio_net_tx_fuzz(const unsigned char *Data, size_t Size)
{
	uint64_t req_addr[10];
	int reqi =0;
	uint32_t free_head;
	
	QGuestAllocator *t_alloc = qos_alloc;

	QVirtioNet *net_if = qos_obj;
	QVirtioDevice *dev = net_if->vdev;
	QVirtQueue *q;
	vq_action vqa;
	int iters=0;
	while(true) {
		if(Size < sizeof(vqa)) {
			break;
		}
		vqa = *((vq_action*)Data);
		Data += sizeof(vqa);
		Size -= sizeof(vqa);

		q = net_if->queues[1];

		vqa.length = vqa.length >= Size ? Size :  vqa.length;

		req_addr[reqi] = guest_alloc(t_alloc, vqa.length);
		memwrite(req_addr[reqi], Data, vqa.length);
		if(iters == 0)
			free_head = qvirtqueue_add(q, req_addr[reqi], vqa.length, vqa.write , vqa.next) ;
		else
			qvirtqueue_add(q, req_addr[reqi], vqa.length, vqa.write , vqa.next) ;
		iters++;
		reqi++;
		if(iters==10)
			break;
		Data += vqa.length;
		Size -= vqa.length;
	}
	if(iters){
		qvirtqueue_kick(dev, q, free_head);
		qtest_clock_step_next(s);
		main_loop_wait(false);
		/* qvirtio_wait_used_elem(dev, q, free_head, NULL, QVIRTIO_NET_TIMEOUT_US); */
		for(int i =0; i<reqi; i++)
		guest_free(t_alloc, req_addr[i]);
	}
}


static void *virtio_net_test_setup_nosocket(GString *cmd_line, void *arg)
{
	g_string_append(cmd_line, " -netdev hubport,hubid=0,id=hs0 ");
	return arg;
}

static void register_virtio_net_fuzz_targets(void)
{
	QOSGraphTestOptions opts = {
		.before = virtio_net_test_setup_nosocket,
	};
	fuzz_add_qos_target("virtio-net-ctrl", "virtio-net ctrl virtqueue",
			"virtio-net", &opts, &qos_setup, NULL, NULL, &reboot,
			&qos_init_path, &virtio_net_ctrl_fuzz, NULL);
	
	fuzz_add_qos_target("virtio-net-ctrl-multi", "virtio-net ctrl virtqueue with multiple kicks",
			"virtio-net", &opts, &qos_setup, NULL, NULL, &reboot,
			&qos_init_path, &virtio_net_ctrl_fuzz_multi, NULL);
	
	fuzz_add_qos_target("virtio-net-tx", "virtio-net tx virtqueue",
			"virtio-net", &opts, &qos_setup, NULL, NULL, &reboot,
			&qos_init_path, &virtio_net_tx_fuzz, NULL);
}

fuzz_target_init(register_virtio_net_fuzz_targets);
