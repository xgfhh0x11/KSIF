#include <stdio.h>
#include <string.h>
#include "observation.h"
#include "semantic_graph.h"

/* Edge-type violation weights for SDS computation.
 *
 * ENFORCES violations are the most severe: they represent a broken
 * invariant that a memory-safety tool cannot observe (e.g. TypeIndex
 * no longer constraining PointerCount).
 *
 * DEPENDS_ON violations indicate an enumeration or lookup path that
 * will produce incorrect results (e.g. Token invisible to SeAccessCheck).
 *
 * EXPOSES / SYNCHRONIZES_WITH violations are lower severity but still
 * signal semantic drift.
 */
static double edge_weight(sem_edge_type_t type)
{
    switch (type) {
        case SEM_EDGE_ENFORCES:           return 1.0;
        case SEM_EDGE_DEPENDS_ON:         return 0.8;
        case SEM_EDGE_EXPOSES:            return 0.5;
        case SEM_EDGE_SYNCHRONIZES_WITH:  return 0.4;
        default:                          return 0.3;
    }
}

/* Node violation weight: every missing node disrupts all edges incident
 * to it, so a missing node counts as 0.9 (slightly less than the heaviest
 * edge, since a missing node can be its own evidence). */
#define NODE_VIOLATION_WEIGHT 0.9

void observation_input_init(observation_input_t *obs,
                            const sem_graph_t *graph)
{
    if (!obs) return;
    memset(obs, 0, sizeof(*obs));
    if (graph) {
        obs->node_count = graph->node_count < KSIF_OBS_MAX_NODES
                          ? graph->node_count : KSIF_OBS_MAX_NODES;
        obs->edge_count = graph->edge_count < KSIF_OBS_MAX_EDGES
                          ? graph->edge_count : KSIF_OBS_MAX_EDGES;
    }
}

sem_metrics_t observation_compute(const sem_graph_t *graph,
                                  const observation_input_t *obs)
{
    sem_metrics_t result = {
        .semantic_drift_score = 0.0,
        .detection_delta      = 0.0,
        .stability_envelope   = 1.0,
        .provenance           = SEM_METRIC_PROVENANCE_PLACEHOLDER
    };

    if (!graph || !obs) {
        return result;
    }

    /* ------------------------------------------------------------------ *
     * Semantic Drift Score (SDS)                                          *
     *                                                                     *
     * Numerator:   sum of weights for each violated edge + each missing   *
     *              node.                                                   *
     * Denominator: sum of weights if every edge and node were violated —  *
     *              the theoretical maximum drift for this graph.           *
     *                                                                     *
     * Result:  0.0 = no drift; 1.0 = every relationship broken.          *
     * ------------------------------------------------------------------ */
    double observed_violation = 0.0;
    double max_possible       = 0.0;
    double enforcement_sum    = 0.0;  /* tracks ENFORCES violations for SE */

    /* Node contribution. */
    {
        size_t i;
        size_t n = obs->node_count < graph->node_count
                   ? obs->node_count : graph->node_count;
        for (i = 0; i < n; ++i) {
            max_possible += NODE_VIOLATION_WEIGHT;
            if (obs->node_missing[i]) {
                observed_violation += NODE_VIOLATION_WEIGHT;
            }
        }
    }

    /* Edge contribution. */
    {
        size_t i;
        size_t e = obs->edge_count < graph->edge_count
                   ? obs->edge_count : graph->edge_count;
        for (i = 0; i < e; ++i) {
            double w = edge_weight(graph->edges[i].type);
            max_possible += w;
            if (obs->edge_violated[i]) {
                observed_violation += w;
                if (graph->edges[i].type == SEM_EDGE_ENFORCES) {
                    enforcement_sum += w;
                }
            }
        }
    }

    if (max_possible > 0.0) {
        result.semantic_drift_score = observed_violation / max_possible;
    }

    /* ------------------------------------------------------------------ *
     * Detection Delta (DD)                                                *
     *                                                                     *
     * Fraction of expected detection signals that failed to fire.        *
     * Total signals == total edges (one detection path per semantic       *
     * relationship, per the threat model).                                *
     * ------------------------------------------------------------------ */
    if (graph->edge_count > 0) {
        result.detection_delta =
            (double)obs->missed_detection_signals / (double)graph->edge_count;
        if (result.detection_delta > 1.0) result.detection_delta = 1.0;
    }

    /* ------------------------------------------------------------------ *
     * Stability Envelope (SE)                                             *
     *                                                                     *
     * SE = 1.0 − (SDS × enforcement_pressure)                            *
     *                                                                     *
     * enforcement_pressure escalates as:                                  *
     *   - ENFORCES violations dominate (enforcement_sum / max_possible),  *
     *   - perturbation_count exceeds the steady-state threshold of 2.     *
     *                                                                     *
     * Range: [0.0, 1.0].  1.0 = fully within guardrails.                 *
     * ------------------------------------------------------------------ */
    {
        double enforcement_ratio = (max_possible > 0.0)
                                   ? (enforcement_sum / max_possible)
                                   : 0.0;

        double perturbation_factor = 1.0;
        if (obs->perturbation_count > 2) {
            /* Each additional perturbation beyond 2 reduces SE by 0.1,
             * floored at 0.1 to avoid a hard zero (partial observability). */
            double extra = (double)(obs->perturbation_count - 2) * 0.1;
            if (extra > 0.9) extra = 0.9;
            perturbation_factor = 1.0 - extra;
        }

        double enforcement_pressure = 0.5 + 0.5 * enforcement_ratio;
        result.stability_envelope =
            1.0 - result.semantic_drift_score * enforcement_pressure;
        result.stability_envelope *= perturbation_factor;

        if (result.stability_envelope < 0.0) result.stability_envelope = 0.0;
        if (result.stability_envelope > 1.0) result.stability_envelope = 1.0;
    }

    result.provenance = SEM_METRIC_PROVENANCE_COMPUTED;
    return result;
}

void metrics_print(const sem_metrics_t *metrics)
{
    if (!metrics) {
        printf("No metrics provided.\n");
        return;
    }

    if (metrics->provenance == SEM_METRIC_PROVENANCE_PLACEHOLDER) {
        printf("\n");
        printf("============================================================\n");
        printf("  [PLACEHOLDER] The values below are baseline constants.\n");
        printf("  Real metric computation requires kernel-telemetry binding\n");
        printf("  (see README §Roadmap / observation_engine_v1).\n");
        printf("  Use --observe to compute from a synthetic observation.\n");
        printf("============================================================\n");
    }

    printf("Semantic Drift Score (SDS) : %.4f%s\n",
           metrics->semantic_drift_score,
           metrics->provenance == SEM_METRIC_PROVENANCE_PLACEHOLDER ? "  (placeholder)" : "");
    printf("Detection Delta       (DD) : %.4f%s\n",
           metrics->detection_delta,
           metrics->provenance == SEM_METRIC_PROVENANCE_PLACEHOLDER ? "  (placeholder)" : "");
    printf("Stability Envelope    (SE) : %.4f%s\n",
           metrics->stability_envelope,
           metrics->provenance == SEM_METRIC_PROVENANCE_PLACEHOLDER ? "  (placeholder)" : "");

    if (metrics->provenance == SEM_METRIC_PROVENANCE_COMPUTED) {
        printf("\nInterpretation:\n");
        if (metrics->semantic_drift_score < 0.05) {
            printf("  SDS: baseline-equivalent — no significant relational anomaly.\n");
        } else if (metrics->semantic_drift_score < 0.3) {
            printf("  SDS: low drift — minor relational anomaly detected.\n");
        } else if (metrics->semantic_drift_score < 0.7) {
            printf("  SDS: moderate drift — DKOM-class manipulation plausible.\n");
        } else {
            printf("  SDS: severe drift — active semantic attack likely.\n");
        }

        if (metrics->stability_envelope >= 0.8) {
            printf("  SE:  system within guardrails.\n");
        } else if (metrics->stability_envelope >= 0.5) {
            printf("  SE:  guardrail pressure elevated; recovery path available.\n");
        } else {
            printf("  SE:  outside stability envelope — sustained attack signature.\n");
        }
    }
}

void metrics_print_json(const sem_metrics_t *metrics, const char *domain_name)
{
    if (!metrics) return;
    printf("{\n");
    printf("  \"domain\": \"%s\",\n", domain_name ? domain_name : "unknown");
    printf("  \"provenance\": \"%s\",\n",
           metrics->provenance == SEM_METRIC_PROVENANCE_COMPUTED
           ? "computed" : "placeholder");
    printf("  \"semantic_drift_score\": %.6f,\n", metrics->semantic_drift_score);
    printf("  \"detection_delta\":       %.6f,\n", metrics->detection_delta);
    printf("  \"stability_envelope\":    %.6f\n",  metrics->stability_envelope);
    printf("}\n");
}

void telemetry_print(const telemetry_channel_t *channels, size_t count)
{
    size_t i;
    if (!channels || count == 0) {
        printf("No telemetry channels.\n");
        return;
    }

    printf("Telemetry Channels:\n");
    for (i = 0; i < count; ++i) {
        printf("  - %s: %s\n", channels[i].channel, channels[i].description);
    }
}
