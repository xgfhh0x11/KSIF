#include <stdio.h>
#include "semantic_graph.h"

static const sem_node_t eprocess_nodes[] = {
    {SEM_ROLE_ACTIVE_PROCESS_LINKS, "ActiveProcessLinks",
     "Scheduler visibility via EPROCESS doubly-linked list"},
    {SEM_ROLE_TOKEN, "Token",
     "Security context reference; ties to SeAccessCheck"},
    {SEM_ROLE_OBJECT_TABLE, "ObjectTable",
     "Handle table pointer; governs process object resolution"}
};

static const sem_edge_t eprocess_edges[] = {
    {&eprocess_nodes[0], &eprocess_nodes[1], SEM_EDGE_DEPENDS_ON,
     "Process enumeration expects token visibility"},
    {&eprocess_nodes[0], &eprocess_nodes[2], SEM_EDGE_EXPOSES,
     "Handle table enumeration requires an enumerated process"},
    {&eprocess_nodes[1], &eprocess_nodes[2], SEM_EDGE_SYNCHRONIZES_WITH,
     "Access checks cross-reference handles and token context"}
};

static const sem_node_t ethread_nodes[] = {
    {SEM_ROLE_CROSS_THREAD_FLAGS, "CrossThreadFlags",
     "Lifecycle indicators (termination, alertable, etc.)"},
    {SEM_ROLE_TCB_STATE, "Tcb.State",
     "Dispatcher-level scheduling state"},
    {SEM_ROLE_CLIENT_ID, "Cid",
     "Unique identifiers for thread/process pairing"}
};

static const sem_edge_t ethread_edges[] = {
    {&ethread_nodes[0], &ethread_nodes[1], SEM_EDGE_ENFORCES,
     "Lifecycle flags must align with dispatcher state"},
    {&ethread_nodes[2], &ethread_nodes[0], SEM_EDGE_EXPOSES,
     "CID reporting depends on thread being in a coherent state"}
};

static const sem_node_t object_header_nodes[] = {
    {SEM_ROLE_OBJECT_HEADER_TYPE_INDEX, "TypeIndex",
     "Identifies object type; drives dispatcher/object manager routes"},
    {SEM_ROLE_OBJECT_HEADER_POINTER_COUNT, "PointerCount",
     "Tracks references from the kernel"},
    {SEM_ROLE_OBJECT_HEADER_HANDLE_COUNT, "HandleCount",
     "Tracks handle table references"}
};

static const sem_edge_t object_header_edges[] = {
    {&object_header_nodes[0], &object_header_nodes[1], SEM_EDGE_ENFORCES,
     "Type determines pointer accounting strategy"},
    {&object_header_nodes[0], &object_header_nodes[2], SEM_EDGE_ENFORCES,
     "Type determines handle accounting requirements"},
    {&object_header_nodes[1], &object_header_nodes[2], SEM_EDGE_SYNCHRONIZES_WITH,
     "Pointer/handle counts must converge at destruction time"}
};

static const sem_node_t handle_entry_nodes[] = {
    {SEM_ROLE_HANDLE_OBJECT, "Object",
     "Pointer or encoded value referencing kernel object"},
    {SEM_ROLE_HANDLE_GRANTED_ACCESS, "GrantedAccess",
     "Effective access mask assigned to handle"},
    {SEM_ROLE_HANDLE_VALUE, "Value",
     "Handle table encoding tying process handle namespace to object"}
};

static const sem_edge_t handle_entry_edges[] = {
    {&handle_entry_nodes[0], &handle_entry_nodes[1], SEM_EDGE_EXPOSES,
     "Object type constrains valid access masks"},
    {&handle_entry_nodes[2], &handle_entry_nodes[0], SEM_EDGE_DEPENDS_ON,
     "Decoded value must map to the proper object pointer"},
    {&handle_entry_nodes[2], &handle_entry_nodes[1], SEM_EDGE_SYNCHRONIZES_WITH,
     "Handle duplication inherits compatible access"}
};

static const sem_node_t access_state_nodes[] = {
    {SEM_ROLE_ACCESS_STATE_OPERATION_ID, "OperationId",
     "Correlates access attempts for auditing"},
    {SEM_ROLE_ACCESS_STATE_SUBJECT_CONTEXT, "SubjectSecurityContext",
     "Snapshot of token/privilege state at evaluation"}
};

static const sem_edge_t access_state_edges[] = {
    {&access_state_nodes[0], &access_state_nodes[1], SEM_EDGE_DEPENDS_ON,
     "Auditing ties decision to subject context"},
    {&access_state_nodes[1], &access_state_nodes[0], SEM_EDGE_EXPOSES,
     "Context updates trigger new operation identifiers"}
};

static const sem_node_t secdesc_nodes[] = {
    {SEM_ROLE_SECURITY_DESCRIPTOR_DACL, "DACL",
     "Discretionary ACL; governs allow/deny decisions"},
    {SEM_ROLE_SECURITY_DESCRIPTOR_SACL, "SACL",
     "System ACL; governs auditing semantics"}
};

static const sem_edge_t secdesc_edges[] = {
    {&secdesc_nodes[0], &secdesc_nodes[1], SEM_EDGE_SYNCHRONIZES_WITH,
     "Auditing must reflect discretionary outcomes"},
    {&secdesc_nodes[1], &secdesc_nodes[0], SEM_EDGE_EXPOSES,
     "SACL policy references DACL evaluation results"}
};

static const sem_graph_t graphs[] = {
    {
        SEM_DOMAIN_EPROCESS,
        "EPROCESS",
        eprocess_nodes,
        sizeof(eprocess_nodes) / sizeof(eprocess_nodes[0]),
        eprocess_edges,
        sizeof(eprocess_edges) / sizeof(eprocess_edges[0])
    },
    {
        SEM_DOMAIN_ETHREAD,
        "ETHREAD",
        ethread_nodes,
        sizeof(ethread_nodes) / sizeof(ethread_nodes[0]),
        ethread_edges,
        sizeof(ethread_edges) / sizeof(ethread_edges[0])
    },
    {
        SEM_DOMAIN_OBJECT_HEADER,
        "OBJECT_HEADER",
        object_header_nodes,
        sizeof(object_header_nodes) / sizeof(object_header_nodes[0]),
        object_header_edges,
        sizeof(object_header_edges) / sizeof(object_header_edges[0])
    },
    {
        SEM_DOMAIN_HANDLE_TABLE_ENTRY,
        "HANDLE_TABLE_ENTRY",
        handle_entry_nodes,
        sizeof(handle_entry_nodes) / sizeof(handle_entry_nodes[0]),
        handle_entry_edges,
        sizeof(handle_entry_edges) / sizeof(handle_entry_edges[0])
    },
    {
        SEM_DOMAIN_ACCESS_STATE,
        "ACCESS_STATE",
        access_state_nodes,
        sizeof(access_state_nodes) / sizeof(access_state_nodes[0]),
        access_state_edges,
        sizeof(access_state_edges) / sizeof(access_state_edges[0])
    },
    {
        SEM_DOMAIN_SECURITY_DESCRIPTOR,
        "SECURITY_DESCRIPTOR",
        secdesc_nodes,
        sizeof(secdesc_nodes) / sizeof(secdesc_nodes[0]),
        secdesc_edges,
        sizeof(secdesc_edges) / sizeof(secdesc_edges[0])
    }
};

const sem_graph_t *sem_graph_get(sem_domain_t domain)
{
    size_t i;
    for (i = 0; i < sizeof(graphs) / sizeof(graphs[0]); ++i) {
        if (graphs[i].domain == domain) {
            return &graphs[i];
        }
    }
    return NULL;
}

void sem_graph_print(const sem_graph_t *graph)
{
    size_t i;
    if (!graph) {
        printf("Semantic graph not available.\n");
        return;
    }

    printf("Domain: %s\n", graph->domain_name);
    printf("Nodes:\n");
    for (i = 0; i < graph->node_count; ++i) {
        printf("  - %s: %s\n",
               graph->nodes[i].name,
               graph->nodes[i].description);
    }
    printf("Edges:\n");
    for (i = 0; i < graph->edge_count; ++i) {
        printf("  - %s -> %s [%d]: %s\n",
               graph->edges[i].from->name,
               graph->edges[i].to->name,
               (int)graph->edges[i].type,
               graph->edges[i].expected_behavior);
    }
}

