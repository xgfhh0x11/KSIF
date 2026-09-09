#ifndef KSIF_OBSERVATION_H
#define KSIF_OBSERVATION_H

#include <stddef.h>
#include "semantic_graph.h"

/* Provenance of a sem_metrics_t value. */
typedef enum {
    SEM_METRIC_PROVENANCE_PLACEHOLDER = 0, /* baseline constants */
    SEM_METRIC_PROVENANCE_COMPUTED    = 1  /* derived from synthetic observation */
} sem_metric_provenance_t;

typedef struct {
    double semantic_drift_score;        /* 0.0 = baseline parity */
    double detection_delta;             /* 0.0 = signals fully aligned */
    double stability_envelope;          /* 1.0 = within guardrails */
    sem_metric_provenance_t provenance;
} sem_metrics_t;

/*
 * Synthetic observation input.
 *
 * Because this build runs in user-space without live kernel telemetry,
 * callers describe the observed state via two parallel bit vectors:
 *
 *   node_missing[i]    — node i (by index in the graph's nodes array)
 *                        is absent from the observed snapshot
 *                        (e.g. process unlinked from ActiveProcessLinks)
 *
 *   edge_violated[i]   — edge i (by index in the graph's edges array)
 *                        is violated in the observed snapshot
 *                        (e.g. Token–ObjectTable synchronization broken)
 *
 * These correspond to synthetic DKOM scenarios (see README §Roadmap for
 * the live telemetry binding that would populate these automatically).
 */
#define KSIF_OBS_MAX_NODES 32
#define KSIF_OBS_MAX_EDGES 32

typedef struct {
    /* Which nodes are missing / anomalous in the observed snapshot. */
    int node_missing[KSIF_OBS_MAX_NODES];   /* 1 = missing, 0 = present */
    size_t node_count;

    /* Which edges are violated in the observed snapshot. */
    int edge_violated[KSIF_OBS_MAX_EDGES];  /* 1 = violated, 0 = intact */
    size_t edge_count;

    /* Number of distinct detection paths that failed to fire.
     * Used for Detection Delta computation.
     * 0 = all expected detection signals were observed. */
    size_t missed_detection_signals;

    /* Number of perturbations seen in the observation window.
     * Used for Stability Envelope computation. */
    size_t perturbation_count;
} observation_input_t;

typedef struct {
    const char *channel;
    const char *description;
} telemetry_channel_t;

/*
 * Compute sem_metrics_t from a semantic graph plus a synthetic observation.
 *
 *   SDS   — normalised graph-edit-distance: sum of weighted node/edge
 *             anomalies divided by the maximum possible violation weight.
 *             Edge weights depend on type: ENFORCES > DEPENDS_ON > others.
 *
 *   DD    — Detection Delta: missed_detection_signals / total_edges,
 *             indicating how much of the expected telemetry is absent.
 *
 *   SE    — Stability Envelope: 1.0 − (SDS × enforcement_pressure),
 *             where enforcement_pressure increases with perturbation_count.
 *
 * Returns baseline placeholders when graph or obs is NULL.
 */
sem_metrics_t observation_compute(const sem_graph_t *graph,
                                  const observation_input_t *obs);

void observation_input_init(observation_input_t *obs,
                            const sem_graph_t *graph);

void metrics_print(const sem_metrics_t *metrics);
void telemetry_print(const telemetry_channel_t *channels, size_t count);
void metrics_print_json(const sem_metrics_t *metrics, const char *domain_name);

#endif /* KSIF_OBSERVATION_H */
