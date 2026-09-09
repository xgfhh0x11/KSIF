#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "semantic_graph.h"
#include "observation.h"
#include "framework.h"

static sem_domain_t parse_domain(const char *arg)
{
    if (strcmp(arg, "eprocess") == 0)           return SEM_DOMAIN_EPROCESS;
    if (strcmp(arg, "ethread") == 0)             return SEM_DOMAIN_ETHREAD;
    if (strcmp(arg, "object_header") == 0)       return SEM_DOMAIN_OBJECT_HEADER;
    if (strcmp(arg, "handle_table_entry") == 0)  return SEM_DOMAIN_HANDLE_TABLE_ENTRY;
    if (strcmp(arg, "access_state") == 0)        return SEM_DOMAIN_ACCESS_STATE;
    if (strcmp(arg, "security_descriptor") == 0) return SEM_DOMAIN_SECURITY_DESCRIPTOR;
    return SEM_DOMAIN_UNKNOWN;
}

static void print_usage(void)
{
    printf("Kernel Semantic Integrity Framework (KSIF)\n");
    printf("Usage:\n");
    printf("  ksif --describe  <domain>             Print semantic graph\n");
    printf("  ksif --metrics                        Print placeholder metrics\n");
    printf("  ksif --profile                        Print framework profile\n");
    printf("  ksif --observe   <domain> [flags]     Compute metrics from scenario\n");
    printf("  ksif --observe-json <domain> [flags]  JSON output\n");
    printf("\nDomains:\n");
    printf("  eprocess  ethread  object_header  handle_table_entry\n");
    printf("  access_state  security_descriptor\n");
    printf("\nBuilt-in scenario flags (--observe):\n");
    printf("  --unlink-process    EPROCESS.ActiveProcessLinks unlinked (DKOM hide)\n");
    printf("  --token-swap        EPROCESS.Token replaced with SYSTEM token\n");
    printf("  --handle-widen      HandleEntry.GrantedAccess widened beyond type mask\n");
    printf("  --thread-state-mismatch  Tcb.State / CrossThreadFlags inconsistent\n");
    printf("  --all-edges-violated All edges in the domain marked violated\n");
    printf("  --miss <n>          Set missed_detection_signals to n (default: 0)\n");
    printf("  --perturb <n>       Set perturbation_count to n (default: 0)\n");
}

/*
 * Apply named DKOM scenario flags to an observation_input_t.
 *
 * Each flag sets specific node_missing[] / edge_violated[] indices
 * corresponding to the structure documented in semantic_graph.c.
 */
static void apply_scenario_flag(observation_input_t *obs,
                                const sem_graph_t *graph,
                                const char *flag)
{
    if (!obs || !graph || !flag) return;

    if (strcmp(flag, "--unlink-process") == 0) {
        /* EPROCESS: node 0 (ActiveProcessLinks) missing from enumeration.
         * Edge 0 (ActiveProcessLinks -> Token: depends_on) violated because
         * unlinking also breaks the scheduler visibility invariant. */
        if (obs->node_count > 0) obs->node_missing[0] = 1;
        if (obs->edge_count > 0) obs->edge_violated[0] = 1;
        obs->perturbation_count++;

    } else if (strcmp(flag, "--token-swap") == 0) {
        /* EPROCESS: node 1 (Token) now points to a foreign SYSTEM token.
         * Edge 1 (ActiveProcessLinks -> ObjectTable: exposes) violated
         * because handle enumeration now operates under wrong identity.
         * Edge from Token -> ObjectTable (SYNCHRONIZES_WITH, index 2). */
        if (obs->node_count > 1) obs->node_missing[1] = 1;
        if (obs->edge_count > 1) obs->edge_violated[1] = 1;
        if (obs->edge_count > 2) obs->edge_violated[2] = 1;
        obs->missed_detection_signals += 2;
        obs->perturbation_count++;

    } else if (strcmp(flag, "--handle-widen") == 0) {
        /* HANDLE_TABLE_ENTRY: edge 0 (Object -> GrantedAccess: exposes)
         * violated because type no longer constrains the access mask.
         * Node 1 (GrantedAccess) semantically inconsistent. */
        if (obs->node_count > 1) obs->node_missing[1] = 1;
        if (obs->edge_count > 0) obs->edge_violated[0] = 1;
        obs->missed_detection_signals += 1;
        obs->perturbation_count++;

    } else if (strcmp(flag, "--thread-state-mismatch") == 0) {
        /* ETHREAD: edge 0 (CrossThreadFlags -> Tcb.State: enforces)
         * violated — lifecycle flags say terminated but dispatcher state
         * says running. */
        if (obs->edge_count > 0) obs->edge_violated[0] = 1;
        obs->missed_detection_signals += 1;
        obs->perturbation_count++;

    } else if (strcmp(flag, "--all-edges-violated") == 0) {
        size_t i;
        for (i = 0; i < obs->edge_count; ++i) {
            obs->edge_violated[i] = 1;
        }
        obs->missed_detection_signals = graph->edge_count;
        obs->perturbation_count += (unsigned)graph->edge_count;
    }
    /* --miss N and --perturb N are handled at the call site */
}

static int cmd_observe(int argc, char **argv, int json_mode)
{
    int i;
    const sem_graph_t *graph;
    sem_domain_t domain;
    observation_input_t obs;
    sem_metrics_t metrics;

    if (argc < 3) {
        printf("--observe requires a domain argument.\n");
        return 1;
    }

    domain = parse_domain(argv[2]);
    if (domain == SEM_DOMAIN_UNKNOWN) {
        printf("Unknown domain: %s\n", argv[2]);
        return 1;
    }

    graph = sem_graph_get(domain);
    if (!graph) {
        printf("Graph not available for domain: %s\n", argv[2]);
        return 1;
    }

    observation_input_init(&obs, graph);

    /* Parse remaining flags. */
    for (i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--miss") == 0 && i + 1 < argc) {
            obs.missed_detection_signals = (size_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--perturb") == 0 && i + 1 < argc) {
            obs.perturbation_count = (size_t)atoi(argv[++i]);
        } else {
            apply_scenario_flag(&obs, graph, argv[i]);
        }
    }

    metrics = observation_compute(graph, &obs);

    if (!json_mode) {
        size_t nv = 0, ev = 0, j;
        for (j = 0; j < obs.node_count; j++) if (obs.node_missing[j]) nv++;
        for (j = 0; j < obs.edge_count; j++) if (obs.edge_violated[j]) ev++;

        printf("Domain: %s\n\n", graph->domain_name);
        printf("Observation summary:\n");
        printf("  Nodes flagged missing  : %zu / %zu\n", nv, graph->node_count);
        printf("  Edges flagged violated : %zu / %zu\n", ev, graph->edge_count);
        printf("  Missed detection signals: %zu\n", obs.missed_detection_signals);
        printf("  Perturbation count     : %zu\n\n", obs.perturbation_count);

        metrics_print(&metrics);
    } else {
        metrics_print_json(&metrics, graph->domain_name);
    }

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage();
        return 1;
    }

    if (strcmp(argv[1], "--describe") == 0) {
        const sem_graph_t *graph;
        sem_domain_t domain;

        if (argc < 3) {
            printf("--describe requires a domain argument.\n");
            return 1;
        }

        domain = parse_domain(argv[2]);
        graph = sem_graph_get(domain);
        sem_graph_print(graph);
        return 0;
    }

    if (strcmp(argv[1], "--metrics") == 0) {
        const telemetry_channel_t channels[] = {
            {"scheduler",      "Dispatcher traces / ready list audits"},
            {"object_manager", "Handle/object cross-validation"},
            {"access_check",   "SeAccessCheck decision logs"},
            {"forensic_tools", "Volatility/Rekall semantic dumps"}
        };
        /* Shipped values are baseline placeholders. Use --observe for
         * computed values from a synthetic scenario. */
        const sem_metrics_t metrics = {
            .semantic_drift_score = 0.00,
            .detection_delta      = 0.00,
            .stability_envelope   = 1.00,
            .provenance           = SEM_METRIC_PROVENANCE_PLACEHOLDER
        };

        metrics_print(&metrics);
        printf("\n");
        telemetry_print(channels, sizeof(channels) / sizeof(channels[0]));
        printf("\nFor computed metrics, use: ksif --observe <domain> [flags]\n");
        return 0;
    }

    if (strcmp(argv[1], "--profile") == 0) {
        framework_print_profile(framework_get_profile());
        return 0;
    }

    if (strcmp(argv[1], "--observe") == 0) {
        return cmd_observe(argc, argv, 0);
    }

    if (strcmp(argv[1], "--observe-json") == 0) {
        return cmd_observe(argc, argv, 1);
    }

    print_usage();
    return 1;
}
