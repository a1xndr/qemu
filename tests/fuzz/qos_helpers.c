#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qos_helpers.h"
#include "qapi/qmp/qlist.h"
#include "libqtest.h"
#include "sysemu/qtest.h"
#include "libqos/qgraph.h"
#include "libqos/qgraph_internal.h"
#include "./qapi/qapi-commands-misc.h"

static void apply_to_node(const char *name, bool is_machine, bool is_abstract)
{
    char *machine_name = NULL;
    if (is_machine) {
        const char *arch = qtest_get_arch();
        machine_name = g_strconcat(arch, "/", name, NULL);
        name = machine_name;
    }
    qos_graph_node_set_availability(name, true);
    if (is_abstract) {
        qos_delete_cmd_line(name);
    }
    g_free(machine_name);
}
static void apply_to_qlist(QList *list, bool is_machine)
{
    const QListEntry *p;
    const char *name;
    bool abstract;
    QDict *minfo;
    QObject *qobj;
    QString *qstr;
    QBool *qbool;

    for (p = qlist_first(list); p; p = qlist_next(p)) {
        minfo = qobject_to(QDict, qlist_entry_obj(p));
        qobj = qdict_get(minfo, "name");
        qstr = qobject_to(QString, qobj);
        name = qstring_get_str(qstr);

        qobj = qdict_get(minfo, "abstract");
        if (qobj) {
            qbool = qobject_to(QBool, qobj);
            abstract = qbool_get_bool(qbool);
        } else {
            abstract = false;
        }

        apply_to_node(name, is_machine, abstract);
        qobj = qdict_get(minfo, "alias");
        if (qobj) {
            qstr = qobject_to(QString, qobj);
            name = qstring_get_str(qstr);
            apply_to_node(name, is_machine, abstract);
        }
    }
}


void qos_set_machines_devices_available(void)
{
	QDict *req = qdict_new();
    QObject *response;
    QDict *args = qdict_new();
    QList *lst;
	Error *err =NULL;
	/* qmp_init_marshal(&qmp_commands); */

	/* qdict_put_str(req, "execute", "query-machines" ); */

	qmp_marshal_query_machines(NULL,&response, &err);
	assert(!err);
	lst = qobject_to(QList, response);
    apply_to_qlist(lst, true);

    qobject_unref(response);


	qdict_put_str(req, "execute", "qom-list-types" );
	qdict_put_str(args, "implements", "device" );
    qdict_put_bool(args, "abstract", true);
	qdict_put_obj(req, "arguments", (QObject*) args);
    
	qmp_marshal_qom_list_types(args, &response, &err);
	assert(!err);
	/* assert(response); */
    /* g_assert(qdict_haskey((QDict*)response, "return")); */
    /* list = qdict_get_qlist((QDict*)response, "return"); */
	lst = qobject_to(QList, response);
    apply_to_qlist(lst, false);

    qobject_unref(response);
}

static QGuestAllocator *get_machine_allocator(QOSGraphObject *obj)
{
    return obj->get_driver(obj, "memory");
}

void *allocate_objects(QTestState *qts, char **path, QGuestAllocator **p_alloc)
{
    int current = 0;
    QGuestAllocator *alloc;
    QOSGraphObject *parent = NULL;
    QOSGraphEdge *edge;
    QOSGraphNode *node;
    void *edge_arg;
    void *obj;

    node = qos_graph_get_node(path[current]);
    g_assert(node->type == QNODE_MACHINE);

    obj = qos_machine_new(node, qts);
    qos_object_queue_destroy(obj);

    alloc = get_machine_allocator(obj);
    if (p_alloc) {
        *p_alloc = alloc;
    }

    for (;;) {
        if (node->type != QNODE_INTERFACE) {
            qos_object_start_hw(obj);
            parent = obj;
        }

        /* follow edge and get object for next node constructor */
        current++;
        edge = qos_graph_get_edge(path[current - 1], path[current]);
        node = qos_graph_get_node(path[current]);

        if (node->type == QNODE_TEST) {
            g_assert(qos_graph_edge_get_type(edge) == QEDGE_CONSUMED_BY);
            return obj;
        }

        switch (qos_graph_edge_get_type(edge)) {
        case QEDGE_PRODUCES:
            obj = parent->get_driver(parent, path[current]);
            break;

        case QEDGE_CONSUMED_BY:
            edge_arg = qos_graph_edge_get_arg(edge);
            obj = qos_driver_new(node, obj, alloc, edge_arg);
            qos_object_queue_destroy(obj);
            break;

        case QEDGE_CONTAINS:
            obj = parent->get_device(parent, path[current]);
            break;
        }
    }
}

