#ifndef QOS_HELPERS_H
#define QOS_HELPERS_H

#include "qemu/osdep.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qbool.h"
#include "qapi/qmp/qstring.h"
#include "libqtest.h"
#include "qapi/qmp/qlist.h"
#include "libqos/qgraph_internal.h"

extern char **fuzz_path_vec;
extern int qos_argc;
extern char **qos_argv;

extern void* qos_obj;
extern QGuestAllocator *qos_alloc;

void qos_set_machines_devices_available(void);
void *allocate_objects(QTestState *qts, char **path, QGuestAllocator **p_alloc);
void walk_path(QOSGraphNode *orig_path, int len);
void run_one_test(char **path);
#endif
