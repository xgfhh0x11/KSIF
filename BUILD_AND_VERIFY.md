# KSIF (Kernel Semantic Integrity Framework) — Build & Verification

> *Quality gate for the HBO NL portfolio. This file answers:
> "Is this project buildable, runnable, and behaving as documented?"*

> *Last updated: 2026-05-14 — post P0–P3 fix pass.*

## 1. Build

### 1.1 Primary build path
- **Platform**: Windows 10/11 x64.
- **Toolchain**: MSVC `cl.exe` (Visual Studio 2019+ Build Tools, x64 Native Tools prompt).
- **Command**:
  ```powershell
  cl /W3 /I include src\*.c /Fe:ksif.exe
  ```
  This mirrors the Windows job in `.github/workflows/c-build.yml` (line 40) and the README "Building" section. Run it from the repository root inside a Developer Command Prompt for VS or after `vcvarsall.bat x64`.
- **Output**: `ksif.exe` in the repository root (alongside transient `*.obj` files that `.gitignore` excludes).

### 1.2 Alternative build paths
- **clang-cl on Windows** (README, line 70):
  ```powershell
  clang-cl /I include src\*.c /Fe:ksif.exe
  ```
- **GCC on Linux** (CI matrix, c-build.yml line 21):
  ```bash
  gcc -Wall -Wextra -std=c11 -I include src/*.c -o ksif
  ```
- **Clang on Linux** (CI matrix):
  ```bash
  clang -Wall -Wextra -std=c11 -I include src/*.c -o ksif
  ```
- No `Makefile`, `CMakeLists.txt`, `.sln`, `.vcxproj`, `build.bat`, or `setup.py` is present. The "build system" is a single shell invocation; this is acceptable for a four-source-file C project and is exercised end-to-end by CI.

### 1.3 Dependencies
- **Required**:
  - A C11-capable C compiler (`cl`, `clang-cl`, `gcc`, or `clang`).
  - C standard library headers only: `<stdio.h>`, `<string.h>`, `<stddef.h>`. No third-party libraries, no Windows-SDK-specific headers in the current sources — the code compiles cross-platform despite modelling Windows kernel structures conceptually.
- **Optional**:
  - PowerShell 5.1+ to run the documented CLI invocations as written; any shell works in practice because the binary takes plain `--flag` arguments.
  - Git, to clone the repository.
  - GitHub Actions runners (`ubuntu-latest`, `windows-latest`) for the CI workflow; no self-hosted dependency.

## 2. Expected behavior

### 2.1 What this project does
KSIF is a read-only C CLI that prints (a) static semantic graphs over six Windows kernel data-structure domains (EPROCESS, ETHREAD, OBJECT_HEADER, HANDLE_TABLE_ENTRY, ACCESS_STATE, SECURITY_DESCRIPTOR), (b) placeholder values for three semantic-integrity metrics (Semantic Drift Score, Detection Delta, Stability Envelope) plus a list of telemetry channels expected to feed them, and (c) a lab-profile descriptor naming the intended environment, telemetry stack, and module status. It does not touch kernel memory, load drivers, or perform live detection — by design (README §"Threat Model and Scope").

### 2.2 Acceptance criteria
- [ ] `cl /W3 /I include src\*.c /Fe:ksif.exe` exits 0 with no warnings escalated to errors on Windows.
- [ ] `gcc -Wall -Wextra -std=c11 -I include src/*.c -o ksif` exits 0 on Linux (CI gate).
- [ ] `ksif.exe --describe eprocess` prints `Domain: EPROCESS`, three nodes (`ActiveProcessLinks`, `Token`, `ObjectTable`), and three edges.
- [ ] `ksif.exe --describe ethread|object_header|handle_table_entry|access_state|security_descriptor` each prints a non-empty domain block.
- [ ] `ksif.exe --metrics` prints three numeric metric lines and four telemetry channels.
- [ ] `ksif.exe --profile` prints `Lab Environment`, `Telemetry Stack`, `Metrics Pipeline`, and three modules with status tags.
- [ ] `ksif.exe` with no arguments prints usage and exits non-zero (returns 1, per `main.c:42`).
- [ ] `ksif.exe --describe bogus_domain` prints "Semantic graph not available." (NULL graph branch in `sem_graph_print`, `semantic_graph.c:168`).
- [ ] CI workflow `c-build.yml` is green on `main` for both the Linux matrix and the Windows job.

### 2.3 Manual verification
From the repo root after building:
```powershell
.\ksif.exe                                        # usage, exit 1
.\ksif.exe --describe eprocess                    # 3 nodes + 3 edges
.\ksif.exe --describe ethread                     # 3 nodes + 2 edges
.\ksif.exe --describe object_header               # 3 nodes + 3 edges
.\ksif.exe --describe handle_table_entry          # 3 nodes + 3 edges
.\ksif.exe --describe access_state                # 2 nodes + 2 edges
.\ksif.exe --describe security_descriptor         # 2 nodes + 2 edges
.\ksif.exe --metrics                              # SDS=0.000, DD=0.000, SE=1.000 + 4 channels
.\ksif.exe --profile                              # lab/telemetry/metrics + 3 modules
.\ksif.exe --describe                             # error: requires domain arg, exit 1
.\ksif.exe --describe nonsense                    # "Semantic graph not available."
```
Counts above are derived directly from `src/semantic_graph.c` and `src/main.c` and serve as a regression checklist.

### 2.4 Automated verification
`.github/workflows/c-build.yml` runs on every push and PR to `main`/`master`:
- Builds the source on `ubuntu-latest` with both `gcc` and `clang` (matrix).
- Builds the source on `windows-latest` with MSVC (`ilammy/msvc-dev-cmd@v1`).
- Smoke-tests the CLI on both platforms by invoking `--describe eprocess`, `--metrics`, and `--profile`. CI fails if any of these returns a non-zero exit code.
- ~~⚠️ The smoke test only asserts exit codes; it does not diff stdout against an expected golden file. A regression that changed the graph contents but kept the program running would pass CI.~~ **RESOLVED 2026-06-10** — `tests/test_cli_golden.py` (pytest) asserts the actual output content (EPROCESS graph nodes/edges, the `[PLACEHOLDER]` provenance banner, the SDS/DD/SE baseline lines, the profile modules), and runs in CI after the Linux build; a graph-content regression now fails CI even if the program still exits 0. `tests/test_structure.py` adds a source-tree check. Run locally: `pip install -r tests/requirements.txt && python -m pytest tests/ -v`.

## 3. Alternatives & improvements

### 3.1 Known fragilities
- **No declarative build file.** `cl /I include src\*.c /Fe:ksif.exe` and the GCC equivalent are the entire build system. This is fine today (4 C files, 3 headers, zero deps) but will not scale once telemetry adapters land. A `CMakeLists.txt` (or `Makefile`) becomes necessary the moment a second translation-unit set (tests, adapter libs) is introduced. Documented in README but not codified — duplicated commands in README and CI workflow can drift.
- **No tests.** There is no `tests/`, `test/`, `*_test.c`, or framework integration (CMocka, Unity, Criterion). CI runs the binary but does not validate output content.
- **Metrics are hardcoded placeholders — now runtime-disclosed.** `src/main.c` initializes `sem_metrics_t` with `.provenance = SEM_METRIC_PROVENANCE_PLACEHOLDER` (designated initializer at the `--metrics` branch). `metrics_print()` (`src/observation.c`) emits a bordered `[PLACEHOLDER]` banner and appends `(placeholder)` to every metric line whenever provenance is `PLACEHOLDER`. The `sem_metric_provenance_t` enum lives in `include/observation.h` alongside the `provenance` field on `sem_metrics_t`. The values themselves (SDS=0.00, DD=0.00, SE=1.00) are still compile-time constants — *the fundamental "no real telemetry binding" gap remains*; the fix is honesty-of-disclosure, not measurement. Acceptance criteria for §2.2 still reflect those constants exactly, and the README continues to call them "dummy metrics" (line 81). When real telemetry is wired in, callers will set `.provenance = SEM_METRIC_PROVENANCE_COMPUTED`, the banner and suffix will disappear automatically, and §2.2 must be rewritten.
- **No version pin for the toolchain.** README says "MSVC or clang-cl"; CI uses whatever `windows-latest` ships and `ilammy/msvc-dev-cmd@v1` defaults to. A future MSVC release tightening warnings could break `/W3` without warning escalation today, but `-Wall -Wextra` on the Linux side is also non-fatal.
- **MIT LICENSE dated 2026** — matches the May-2026 commit dates in the working tree, internally consistent for this portfolio, but worth a note.
- **Cross-platform claim is implicit.** The project models Windows kernel concepts yet the source compiles on Linux because nothing actually touches Windows APIs. That is intentional (it is a "specification substrate") but a reader could mis-expect kernel functionality.

### 3.2 Fallbacks
- If MSVC is unavailable, install LLVM and substitute `clang-cl` (README path) or build under WSL/Linux with `gcc`/`clang` (CI path) — the binary is identical in behavior.
- If `src\*.c` glob expansion misbehaves in a non-standard `cmd`/PowerShell setup, enumerate explicitly:
  ```powershell
  cl /W3 /I include src\main.c src\framework.c src\observation.c src\semantic_graph.c /Fe:ksif.exe
  ```
- If the CI smoke tests pass but local output looks wrong, compare against the counts in §2.3 above; mismatches localize to `src/semantic_graph.c`.

### 3.3 Roadmap
- **Short-term (≤1 day)**:
  - ~~Make the placeholder nature of `--metrics` runtime-visible (banner + per-line suffix) rather than relying on README disclosure.~~ **Done (2026-05-14):** `sem_metric_provenance_t` on `sem_metrics_t`, banner + `(placeholder)` suffix in `metrics_print()`, designated initializer in `src/main.c`.
  - Add a `Makefile` (and/or trivial `CMakeLists.txt`) so the build command is no longer duplicated between README, CI, and reader memory.
  - Extend the CI smoke test to diff stdout against committed golden files (`tests/golden/*.txt`) so graph regressions actually fail CI. Note: golden files for `--metrics` must now include the `[PLACEHOLDER]` banner lines.
  - Add a `--help` flag aliased to the usage block in `main.c` so `ksif --help` does not exit non-zero.
- **Medium-term (≤1 week)**:
  - Introduce a `tests/` directory with a minimal harness (Unity or hand-rolled) covering `sem_graph_get` for every domain plus the NULL/unknown-domain paths.
  - Add `--format json` to `--describe`/`--metrics`/`--profile` (Roadmap item 5 in README) so downstream IR tooling can consume output.
  - Wire `clang-format` and `cppcheck`/`scan-build` jobs into the workflow.
- **Long-term**: Deliver Roadmap items 1–4 from README (Volatility/Rekall ingestion adapter, ETW binding, formal SDS as graph-edit distance, coverage for TOKEN / PRIVILEGE_SET / file & section objects). Each of those will need its own build target, dependency declaration, and acceptance criteria — at which point a real build system is mandatory, not optional.

## 4. Sanity check

| Check | Status | Notes |
|-------|--------|-------|
| README documents build | ✅ | README §"Building" gives both `cl` and `clang-cl` invocations; matches CI. |
| Build files present | ⚠️ | No `Makefile`/`CMakeLists.txt`/`.sln`/`.vcxproj`. Build is a single command line in README + `.github/workflows/c-build.yml`. Acceptable for this size, called out in §3.1. |
| Build files internally consistent | ✅ | README command (`cl /I include src\*.c /Fe:ksif.exe`) and CI command (`cl /W3 /I include src\*.c /Fe:ksif.exe`) differ only by the `/W3` warning level; Linux CI uses `-Wall -Wextra -std=c11`. No conflicting include paths or output names. |
| Source structure matches README | ✅ | README §"Repository Layout" lists `include/{semantic_graph,observation,framework}.h` and `src/{semantic_graph,observation,framework,main}.c` — all seven files exist and the responsibilities described match the code. |
| Tests exist | ✅ | `tests/` (pytest): `test_structure.py` (source tree) + `test_cli_golden.py` (output-content assertions on `--describe`/`--metrics`/`--profile`, incl. placeholder-provenance disclosure). 7 passed / 9 skipped locally (golden rows skip without a build). |
| Test invocation documented | ✅ | §2.4 + this row document `python -m pytest tests/ -v`; CI (`c-build.yml`) builds on the Linux matrix then runs the golden-output suite, plus the cross-platform CLI smoke. |
| Output artifacts named in build files | ✅ | `ksif.exe` (Windows, `/Fe:`) and `ksif` (Linux, `-o`) are explicitly named in both README and CI workflow, and both names are listed in `.gitignore`. |
| Metrics honestly disclose provenance | ✅ | `sem_metrics_t.provenance` (`include/observation.h`) is set to `SEM_METRIC_PROVENANCE_PLACEHOLDER` in `src/main.c`; `metrics_print()` (`src/observation.c`) emits a `[PLACEHOLDER]` banner and `(placeholder)` per-line suffix. Runtime output cannot be mistaken for measured values. Underlying telemetry binding is still future work — see §3.1. |
