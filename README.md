# KSIF — Kernel Semantic Integrity Framework

A defense-oriented framework for modeling **semantic relationships** between
Windows kernel data structures, and for measuring deviation from those
relationships using observational telemetry. The aim is to express, in code,
the invariants that DKOM-class attacks violate — and to give defenders a
quantitative substrate against which to test detection rules.

---

## Motivation

Many kernel rootkit primitives are not memory-safety violations: they are
**semantic violations**. Direct Kernel Object Manipulation (DKOM) attacks
operate by writing legal values to legal fields, while breaking the *relational
contract* those fields participate in.

Examples:

- A process is hidden by unlinking its `EPROCESS` from `ActiveProcessLinks`
  while still being scheduled — the dispatcher views it, but enumeration
  paths do not.
- A privilege escalation primitive swaps `EPROCESS.Token` for a SYSTEM token —
  the field still type-checks; the *binding* between identity and process is
  broken.
- A `HandleTableEntry.GrantedAccess` value is widened without the type's
  permitted access mask agreeing — handle resolution still succeeds; access
  checks now leak.

Memory-safety tooling (KASLR, CFG, HVCI) does not address these. Patch-level
defenses (PatchGuard) cover a curated set of structures but cannot generalize.
KSIF treats the problem the other way around: enumerate the *semantic graph*
of relationships, define a metric for deviation, and let detection rules be
derived against it.

## Current Scope

The repository currently provides:

- A C-based static semantic graph over six kernel structures: `EPROCESS`,
  `ETHREAD`, `OBJECT_HEADER`, `HANDLE_TABLE_ENTRY`, `ACCESS_STATE`,
  `SECURITY_DESCRIPTOR`. For each, the nodes (semantic roles) and edges
  (`depends_on`, `enforces`, `exposes`, `synchronizes_with`) are declared in
  `src/semantic_graph.c`.
- A metric scaffold (`include/observation.h`) for three quantities:
  - **Semantic Drift Score (SDS)** — distance between observed and expected
    relational state.
  - **Detection Delta** — divergence between defender telemetry and a ground
    truth view.
  - **Stability Envelope** — recoverability indicator after disturbance.
- A descriptor for the lab profile and the telemetry channels expected to
  feed those metrics (`src/framework.c`).
- A CLI (`ksif`) that prints the graph, the metric placeholders, and the
  profile descriptor.

The current build is intentionally **observational and read-only**. No kernel
memory is written; no exploit-enabling functionality is implemented or
planned.

## Building

MSVC or clang-cl:

```powershell
mkdir build
cl /I include src\*.c /Fe:ksif.exe
```

```powershell
clang-cl /I include src\*.c /Fe:ksif.exe
```

## Usage

```powershell
.\ksif.exe --describe eprocess
.\ksif.exe --metrics
.\ksif.exe --profile
```

The binary currently emits the static graph and dummy metrics. Real metric
values will be populated when telemetry adapters are added (see Roadmap).

## Threat Model and Scope

KSIF is a **specification and measurement substrate**. It is not:

- A kernel agent. It does not load drivers, hook syscalls, or read kernel
  memory.
- A live detector. It does not decide, alert, or respond.
- A response system. Findings are intended for analyst review, not automated
  action.

It is:

- A formal description of what kernel relational state is expected to look
  like.
- A scaffold for computing distance metrics between observed and expected
  state, given an external telemetry feed.
- A documentation artefact that detection-engineering teams can consume,
  extend, or reject.

The intended deployment is offline analysis of dumps and structured ETW
captures, not online enforcement.

## Repository Layout

```
include/
    semantic_graph.h    - node and edge type definitions
    observation.h       - metric and telemetry types
    framework.h         - lab profile and module descriptors

src/
    semantic_graph.c    - static graphs for all six domains
    observation.c       - metric and telemetry print helpers
    framework.c         - lab profile descriptor
    main.c              - CLI entry point

docs/
    KSIF_Technical_Framework.md  - extended technical write-up
```

## Roadmap

The current source is a deliberate stub. Concrete next steps, in order:

1. **Volatility/Rekall ingestion adapter.** Read a process dump, walk
   `EPROCESS`/`ETHREAD`/`OBJECT_HEADER`, project the observed graph, and
   compare against the expected one — emitting an SDS value backed by data.
2. **ETW telemetry binding.** Map `Microsoft-Windows-Kernel-Process` and
   `Microsoft-Windows-Kernel-Object` providers to the relevant graph edges
   and compute a Detection Delta against the dump-derived ground truth.
3. **Formal SDS definition.** The current SDS is described qualitatively;
   replace this with a documented metric (graph edit distance over the
   observed-vs-expected projection) with explicit assumptions and bounds.
4. **Coverage expansion.** Add `TOKEN`, `PRIVILEGE_SET`, and the file/section
   object families. Document the trade-offs of each addition.
5. **Structured output.** Emit JSON/CSV reports suitable for downstream IR
   pipelines.

## Status

Research / non-production. The framework is intended as a specification and
analysis substrate for detection engineering and academic study of kernel
semantic integrity.

## References

- Butler, J. & Hoglund, G. — *Rootkits: Subverting the Windows Kernel*.
  Addison-Wesley, 2005. (Original DKOM exposition.)
- Walters, A. & Petroni, N. — "Volatools: Integrating Volatile Memory
  Forensics into the Digital Investigation Process." *Black Hat DC*, 2007.
- Schuster, A. — "Searching for processes and threads in Microsoft Windows
  memory dumps." *DFRWS*, 2006.
- Microsoft Driver Development Kit — `EPROCESS`, `ETHREAD`, `OBJECT_HEADER`
  structure references (public symbol PDBs).
