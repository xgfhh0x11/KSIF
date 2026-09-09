#include <stdio.h>
#include "framework.h"

static const ksif_module_t default_modules[] = {
    {"Semantic Mapping", "active",
     "Six-domain graph (EPROCESS/ETHREAD/OBJECT_HEADER/HANDLE_TABLE_ENTRY/ACCESS_STATE/SECURITY_DESCRIPTOR)"},
    {"Fragility Harness", "planned",
     "Live kernel telemetry binding; ETW + Volatility adapters pending"},
    {"Telemetry & Metrics", "active",
     "SDS/DD/SE computed from synthetic observations via --observe; real telemetry binding is the roadmap item"}
};

static const ksif_profile_t default_profile = {
    "Win10 x64 debug VM (snapshot friendly)",
    "ETW + WinDbg scripts + offline forensic diff",
    "Semantic Drift Score / Detection Delta / Stability Envelope",
    default_modules,
    sizeof(default_modules) / sizeof(default_modules[0])
};

const ksif_profile_t *framework_get_profile(void)
{
    return &default_profile;
}

void framework_print_profile(const ksif_profile_t *profile)
{
    size_t i;
    if (!profile) {
        printf("Framework profile unavailable.\n");
        return;
    }

    printf("Lab Environment : %s\n", profile->lab_environment);
    printf("Telemetry Stack : %s\n", profile->telemetry_stack);
    printf("Metrics Pipeline: %s\n", profile->metrics_pipeline);
    printf("Modules:\n");
    for (i = 0; i < profile->module_count; ++i) {
        printf("  - %s [%s]: %s\n",
               profile->modules[i].name,
               profile->modules[i].status,
               profile->modules[i].notes);
    }
}

