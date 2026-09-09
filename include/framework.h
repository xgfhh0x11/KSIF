#ifndef KSIF_FRAMEWORK_H
#define KSIF_FRAMEWORK_H

#include <stddef.h>

typedef struct {
    const char *name;
    const char *status;
    const char *notes;
} ksif_module_t;

typedef struct {
    const char *lab_environment;
    const char *telemetry_stack;
    const char *metrics_pipeline;
    const ksif_module_t *modules;
    size_t module_count;
} ksif_profile_t;

const ksif_profile_t *framework_get_profile(void);
void framework_print_profile(const ksif_profile_t *profile);

#endif /* KSIF_FRAMEWORK_H */

