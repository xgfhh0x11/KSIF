#ifndef KSIF_SEMANTIC_GRAPH_H
#define KSIF_SEMANTIC_GRAPH_H

#include <stddef.h>

typedef enum {
    SEM_DOMAIN_EPROCESS,
    SEM_DOMAIN_ETHREAD,
    SEM_DOMAIN_OBJECT_HEADER,
    SEM_DOMAIN_HANDLE_TABLE_ENTRY,
    SEM_DOMAIN_ACCESS_STATE,
    SEM_DOMAIN_SECURITY_DESCRIPTOR,
    SEM_DOMAIN_UNKNOWN
} sem_domain_t;

typedef enum {
    SEM_ROLE_ACTIVE_PROCESS_LINKS,
    SEM_ROLE_TOKEN,
    SEM_ROLE_OBJECT_TABLE,
    SEM_ROLE_CROSS_THREAD_FLAGS,
    SEM_ROLE_TCB_STATE,
    SEM_ROLE_CLIENT_ID,
    SEM_ROLE_OBJECT_HEADER_TYPE_INDEX,
    SEM_ROLE_OBJECT_HEADER_POINTER_COUNT,
    SEM_ROLE_OBJECT_HEADER_HANDLE_COUNT,
    SEM_ROLE_HANDLE_OBJECT,
    SEM_ROLE_HANDLE_GRANTED_ACCESS,
    SEM_ROLE_HANDLE_VALUE,
    SEM_ROLE_ACCESS_STATE_OPERATION_ID,
    SEM_ROLE_ACCESS_STATE_SUBJECT_CONTEXT,
    SEM_ROLE_SECURITY_DESCRIPTOR_DACL,
    SEM_ROLE_SECURITY_DESCRIPTOR_SACL,
    SEM_ROLE_UNDEFINED
} sem_role_t;

typedef enum {
    SEM_EDGE_DEPENDS_ON,
    SEM_EDGE_ENFORCES,
    SEM_EDGE_EXPOSES,
    SEM_EDGE_SYNCHRONIZES_WITH
} sem_edge_type_t;

typedef struct {
    sem_role_t role;
    const char *name;
    const char *description;
} sem_node_t;

typedef struct {
    const sem_node_t *from;
    const sem_node_t *to;
    sem_edge_type_t type;
    const char *expected_behavior;
} sem_edge_t;

typedef struct {
    sem_domain_t domain;
    const char *domain_name;
    const sem_node_t *nodes;
    size_t node_count;
    const sem_edge_t *edges;
    size_t edge_count;
} sem_graph_t;

const sem_graph_t *sem_graph_get(sem_domain_t domain);
void sem_graph_print(const sem_graph_t *graph);

#endif /* KSIF_SEMANTIC_GRAPH_H */

