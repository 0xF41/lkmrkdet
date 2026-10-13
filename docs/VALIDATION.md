# Validation ledger

## Target inventory

- Ubuntu x86-64 `6.8.0-146-generic`; matching headers available.
- Module signing enabled in configuration; enforcement not observed in the
  inventory. Lockdown reports `[none] integrity confidentiality`.
- `modules_disabled=0`; `kptr_restrict=1`.
- GCC 13.3.0. Same package version as kernel compiler; executable-name warning.
- Privileged experiments were explicitly launched by the VM operator.
- Matching headers: module memory uses `mem[MOD_TEXT]`, `file_operations` has
  `iterate_shared` but no legacy `iterate`, x86 syscall table is trace metadata.

## Recorded validation

| Item | Status |
| --- | --- |
| Local C entry-decoder tests, x86 and AArch64 encodings | Passed |
| Local Python evidence/identity/error tests | Passed |
| Local header-feature tests (split headers, backport and ARM distinction) | Passed |
| Entry decoder with AddressSanitizer and UndefinedBehaviorSanitizer | Passed |
| x86-64 Ubuntu kernel module compilation and modpost | Passed |
| Final warning-enabled rebuild (`W=1 KCFLAGS=-Werror`) | Passed |
| VM unit tests, validated v0.2.1 tooling | Passed — C decoder and 50 Python tests, including the observed HID-BPF regression |
| Validation runner cleanup/report tests | Passed with mocked privileged commands; no module loading |
| Controlled-case evidence/order/cleanup unit tests | Passed with mocked module lifecycle on Mac and VM |
| Caraxes build/configuration preflight | Passed — reviewed checkout and both modules match 6.8.0-146-generic |
| Module load / status / scan / unload | Passed — report `20261011T153554Z-5194cc86` |
| Runtime interface smoke tests | Passed — malformed requests, concurrency, partial reads, process and repeated scans |
| Fresh-boot lab baseline | Passed — report `20261011T155711Z-acd50ca6`, `expect_clean=true` |
| Controlled Caraxes process-hiding detection, v0.1 | Passed for the specific hidden PID; report `20261011T162243Z-controlled-c87b6398` |
| Caraxes filename hiding, v0.1 case | Not observed — not a detector miss |
| v0.2 warnings-as-errors build | Passed; vermagic 6.8.0-146-generic, srcversion 4161958FE69201B4100A500 |
| v0.2 privileged baseline | Failed — tracefs parsing and standalone smoke import (reports below) |
| v0.2 controlled regression | Correctly aborted before sample load due to incomplete baseline |
| v0.2.1 warnings-as-errors build | Passed; matching vermagic, srcversion C82C596877ECB231903D9AF |
| v0.2.1 privileged baseline and interface smoke | Passed — report 20261012T035617Z-57737c6b |
| v0.2.1 controlled Caraxes case, detector loaded afterward | Passed — report 20261012T035617Z-controlled-817282a6 |
| Additional sample-runner local regression checks | Passed — C decoder and 69 Python tests, with the Linux-only canary integration skipped on macOS |
| Updated sample-runner native VM checks | Passed — C decoder and all 69 Python tests, including benign detached-canary IPC/pidfd cleanup |
| Diamorphine/Singularity read-only preflights | Passed — pinned tracked source, matching kernel/module metadata, no visible sample/detector |
| v0.2.1 Diamorphine module concealment and table anomalies | Passed — report 20261012T145006Z-controlled-63239bf3; detector loaded afterward |
| Diamorphine file/process hiding on this kernel | Not observed — those features are unexercised, not detector misses |
| Diamorphine reboot recovery | Verified pass — retrieved 20261012T151344Z-fedef34f, including interface tests and log delta |
| Initial Singularity behaviour and detection, v0.2.1 | Retrieved artifacts verified — network/tracefs detected; module check misses; process incomplete |
| Singularity saved artifacts | Retrieved after reboot; live rsync failure disappears; captured log output loses old lines |
| Post-Singularity clean runtime recovery | Passed — 20261012T161211Z-6970e68f, new boot, interface tests and negative scan |
| Client v0.3.0 local regression suite | Passed — 80 Python tests with one Linux-only skip, plus C decoder |
| Client v0.3.0 native regression suite | Passed — all 80 Python tests and C decoder on the recovered VM |
| Client v0.3.0 privileged baseline | Passed — 20261012T161114Z-74cbf01c |
| Client v0.3.0 Singularity process and network retry | Passed for process/network — 20261012T161114Z-controlled-2a2be8f7; module-check miss preserved |
| Client v0.3.1 grouped/colour output, local checks | Passed — 96 Python tests, one Linux-only skip, C decoder; real PTY and JSON/plain-output tests |
| Client v0.3.1 native VM presentation checks | Passed — all 96 Python tests, no skips, C decoder, including real PTY and JSON tests |
| Dedicated directory runner local checks | Passed — final 120 Python tests, one Linux-only skip, C decoder; no sample loaded |
| Dedicated directory runner native checks/preflights | Passed — final 120 Python tests, C decoder, three read-only sample preflights |
| Dedicated Caraxes directory case | Verified — 20261013T040600Z-controlled-1e5acc5a; GID directory hidden, matching hook evidence, recovery pass |
| Dedicated Diamorphine directory case | Verified — 20261013T042409Z-controlled-cc6ae964; hiding unobserved, table/module anomalies detected |
| Dedicated Singularity directory case | Verified — 20261013T043003Z-controlled-797c0148; hiding confirmed, chdir ENOENT, matching hook evidence |
| Directory series final reboot recovery | Passed — 20261013T043051Z-5e30d678, new boot, clean full/interface scans |
| AArch64 module compilation/runtime | Deferred to a future phase at user request |

Do not promote an item to passed without its output. Keep compile tests and
runtime tests distinct. Unavailable `vmlinux` can skip module BTF generation; it
is not a runtime result.

The first build reported a format-attribute suggestion and possible owner-label
truncation. Both were fixed. After SSH access recovered, the final source was
synchronised and rebuilt with `W=1 KCFLAGS=-Werror`; compilation, modpost and
linking succeeded without source warnings. The kernel's compiler-name warning
and skipped BTF generation remain environmental messages. `modinfo` confirms
version `0.1.0`, no module dependencies, and matching `6.8.0-146-generic` vermagic.
The user ran the privileged runner. No module was loaded directly by the agent;
subsequent privileged runs still require the user to supply sudo authentication.

The one-command runner is installed on the VM:

```bash
sudo python3 /home/felix/STANDCON/lkmrkdet-dev/scripts/validate_vm.py --expect-clean
```

It records status, scan, interface-test output and kernel logs under the VM
project's `reports/` folder, and unloads only a detector it loaded itself. The
first runtime result is recorded below. The architecture-detection tests also cover ARM
targets whose common-header package includes x86 files, to avoid incorrectly
applying the x86 metadata-only dispatch claim to AArch64.

## First runtime report: 20261011T153554Z-5194cc86

- Environment: x86-64 `6.8.0-146-generic`; `expect_clean=false`.
- All recorded commands returned 0: load, status, scan, interface smoke tests,
  unload and both kernel-log captures.
- Resolver succeeded; module registry snapshot observed 96 LIVE modules.
- Full scan: **27 OK, 3 INFO, 0 SUSPICIOUS, 0 UNSUPPORTED, 0 ERROR**.
- No report truncation; process snapshot and client cross-view comparison complete.
- Named directory callbacks matched `ext4_readdir`, `proc_root_readdir`, and
  `kernfs_fop_readdir`; network show callbacks matched the expected TCP/UDP names.
- Kernel collection took 0.331457 ms in this single scan. This excludes the
  client-side comparison and is not a performance benchmark.
- Exact before/after log diff adds only detector ready/unloaded messages. No new
  warning, oops, panic, lockdep, KASAN or UBSAN message was observed in that interval.
- Runtime interface tests passed: rejected malformed/oversized/NUL requests,
  partial reads/EOF, one scan per descriptor, concurrent status requests, known
  child presence, and repeated kernel scans.

### Baseline provenance and ftrace gap

The **before** log already contains caraxes loading and
`installed hook on __x64_sys_getdents64` at boot-relative 432.284667 seconds.
The detector run is around 3803.9 seconds. This establishes earlier rootkit
exposure, not whether that hook remained active during this scan.

A later read-only inspection found no visible caraxes module row or direct
`/sys/module/caraxes` entry; the detector interface was also gone, corroborating
its successful unload. These later observations cannot reconstruct the earlier
hook state. Kernel taint remained 12288 (out-of-tree plus unsigned module), which
persists after unload and does not establish current rootkit presence.

The inventoried caraxes source uses an ftrace IPMODIFY callback and leaves its
optional `hide_module()` call commented out. v0.1 does not enumerate ftrace
registrations: intact callback/table pointers and an in-core tracing call can
coexist with ftrace-based redirection. **Do not record this run as successful
caraxes detection, or as a verified clean-system test.** If the hook was active
and its hiding effect demonstrated at scan time, this would be a coverage miss.

The fresh-boot lab baseline below supersedes this run as the negative control.
Keep this first report as an operational smoke result with ambiguous sample
state, not a measured detection miss.

## Fresh-boot baseline: 20261011T155711Z-acd50ca6

- The user rebooted before running validation. Current-boot metadata queried
  immediately afterward identifies boot time `2026-10-11T15:56:32Z` and boot ID
  `6b6cf2bd-d10a-46ea-ad94-7cc21dcaab25` (queried separately; the original runner
  did not yet save boot ID in environment.json).
- Validation ran at about 39.5 seconds after boot, on x86-64 `6.8.0-146-generic`.
- `expect_clean=true`; load, status, full scan, `runtime_smoke.py --expect-clean`,
  unload and both log captures all returned 0.
- Full scan: **27 OK, 3 INFO, 0 SUSPICIOUS, 0 UNSUPPORTED, 0 ERROR**; 96 LIVE
  modules; no truncation; process snapshot and client comparison complete.
- Kernel collection in the saved scan: 0.223784 ms (one observation, excluding
  client work; not a benchmark).
- No sample-installation messages appear in the captured boot log. Its exact
  before/after delta consists of four detector lines: out-of-tree/unsigned module
  taint notices, successful initialization and unload. No new oops, panic or
  runtime fault diagnostic was observed.
- The observed handlers and coverage classifications agree with the earlier
  report. Absolute addresses differ after reboot, as expected with KASLR.

This establishes the first negative-control lab run under the user's stated
fresh-boot procedure, not an independent attestation of kernel integrity.
Next: exercise known file/process hiding in a labelled sample run with pre/post
identity evidence, keeping module hiding separate from ftrace-only filtering.

## Prepared follow-up

`scripts/validate_caraxes.py` implemented the first controlled case. Unit tests
verify that a disabled hiding feature is not called a detector miss, unrelated
alerts do not count as canary detection, process exits/reuse remain inconclusive,
and collection failures clean up in sample-then-detector order. An unprivileged
preflight succeeded with the default name/UID/GID filters and matching vermagic.
That prepared v0.1 runner was subsequently executed; its measured result is below.

The v0.1 detector binary was unchanged for that comparison. Its runner captured
boot ID directly to remove ambiguity about which reboot a scan belongs to.

The prepared v0.1 case was subsequently executed; see the measured result below.
The v0.2 regression uses the same unmodified sample with extra canary variants.

## Controlled Caraxes run: 20261011T162243Z-controlled-c87b6398 (v0.1)

- Reviewed sample revision and binary/configuration recorded in environment.json.
- Detector order `after`: baseline scan, detector unload, sample load, detector
  reload, active scan, sample unload, restored scan, detector unload.
- Canary PID **4849** absent in both active numeric proc enumerations, still
  alive, with unchanged direct `/proc/4849/stat` start time.
- Detector: **SUSPICIOUS / missing_from_proc_enumeration** for exactly PID 4849.
  Process hiding was confirmed and detected; recovery scan returned 0.
- The root-owned `probe_caraxes.txt` file remained enumerable with matching
  inode and content in both active observations. Filename hiding was not
  exercised, rather than missed by an inode detector.
- Handler entry and table alias each reported the same `x86_call_rel32`
  candidate. Both resolve the same CALL destination at a tracing trampoline,
  illustrating duplicate code sampling in v0.1 rather than two separate hooks.
- Tracefs independently reported within the same kernel:
  `__x64_sys_getdents64 (1) R I M tramp: ... (fh_ftrace_thunk ... [caraxes])`.
  This corroborates the entry-call observation; it is not independent trust.
- Overall experiment exit 2 reflects the unexercised file feature. Active
  detector scan exit 1 denotes suspicious evidence, NOT a failed scan.
- All module lifecycle commands returned 0, visibility returned, and cleanup
  errors were empty. Log delta contains detector lifecycle plus sample hook
  installation, with no new kernel fault diagnostic observed.

## Changes driven by that report (v0.2)

- Sample function-entry bytes once per code address, preserving separate pointer
  checks. This removes duplicate alias findings.
- Add a `ftrace` client check: bounded bracketing reads of already-mounted
  tracefs, selected IPMODIFY evidence, and exact single-callback CALL attribution.
  Normal known tracing can be INFO; IPMODIFY remains a candidate. Missing,
  changing or unknown output is explicit incompleteness.
- Separate root-owned name canary, UID-owned file and untargeted control in the
  runner. Record both pathname and descriptor enumeration to diagnose which
  file-filter path is actually exercised. Do not modify the rootkit.
- New tests cover the actual tracefs format, historical M, direct BPF, ordinary
  tracing, IPMODIFY, malformed/bounded input, acquisition changes, target mismatch
  and AArch64 naming. 43 Python tests pass on the VM.
- v0.2 compiled and linked with `W=1 KCFLAGS=-Werror`. Runtime validation is still
  pending and must not inherit the earlier version's runtime result.

## v0.2 runtime regression and v0.2.1 fix

Baseline report `20261012T033824Z-0de57e42`:

- Kernel checks produced their normal observations. Full scan exit 2 was caused
  by both bracketing tracefs reads rejecting a trampoline representation with
  `Unrecognised tracefs trampoline description`.
- Runtime smoke exited before tests: `ModuleNotFoundError: trace_evidence` when
  importlib loaded the client from a script launched outside the project root.
- Detector loading/status/unloading and log collection all returned 0. No new
  kernel fault diagnostic observed in the captured interval.
- Previous reports did not preserve the offending unfiltered row. The Linux
  6.8 `t_show()` formatter uses `%pS` for trampoline and callback descriptions,
  which allows symbolic output as well as numeric fallback; the numeric-only
  parser was too restrictive. The patch supports those documented formats,
  without treating arbitrary malformed data as valid.

Controlled report `20261012T033833Z-controlled-149bcd31`:

- Baseline scan exited 2 for the same parser problem.
- The runner aborted before sample loading, unloaded its detector and cleaned
  up its canaries. This is not a rootkit-detection result or a detector miss.

v0.2.1 changes and verification:

- Parse numeric/symbolic `%pS`, multiple trampolines, ops references and direct
  continuation rows. Preserve callback ambiguity and symbolic identity; only
  explicit numeric addresses can corroborate entry CALL destinations.
- Unknown syntax, kernel `ERROR!`, capacity exhaustion and changed registrations
  still produce explicit failed/incomplete checks.
- Fix import paths for standalone smoke and CLI entrypoints. Subprocess
  regression runs `--help` from a temporary directory without PYTHONPATH and
  with PYTHONSAFEPATH, avoiding misleading success from in-process unit imports.
- Preserve byte-exact raw tracefs snapshots with bounded size and restricted
  report permissions, including while the detector is loaded.
- Include `client_version` in new client reports; bundle version is `0.2.1`.
- VM rebuild with `W=1 KCFLAGS=-Werror`, C decoder and 49 Python tests pass.
  Runtime regression was subsequently executed, as recorded below.

## v0.2.1 verified baseline: 20261012T035617Z-57737c6b

- Kernel `6.8.0-146-generic`, x86-64; `expect_clean=true`; boot ID
  `34718f80-130a-4759-9b75-46950ef151da`.
- All commands return 0, including the standalone runtime smoke with
  `--expect-clean`. The module loads, scans and unloads successfully.
- Full scan and smoke summary: **28 OK, 4 INFO, no SUSPICIOUS/ERROR/UNSUPPORTED**.
- Raw tracefs captures show an unrelated HID-BPF direct instrumentation row:
  `__hid_bpf_tail_call (1) R D M tramp: ftrace_regs_caller+0x0/0x78
  (call_direct_funcs+0x0/0x20)`, followed by a `direct-->bpf_trampoline...` row.
  Both the symbolic trampoline and continuation now parse correctly. This row
  is outside the selected watchlist and is not scored as a rootkit candidate.
- Exact kernel-log delta adds only detector ready/unloaded messages. No new
  kernel fault diagnostic observed in that interval.
- Kernel taint 12288 was already present from earlier unsigned/out-of-tree loads;
  taint alone is not evidence of a currently active rootkit.

## v0.2.1 verified Caraxes case: 20261012T035617Z-controlled-817282a6

- Same kernel/boot ID as the immediate baseline. Detector srcversion
  `C82C596877ECB231903D9AF`, SHA-256
  `b3ec711846456641b325747759dfb0a8805ded8c6ead992c0afd5f2bf346b178`.
- Caraxes revision/configuration and binary are unchanged from the earlier
  controlled run. Its optional module hiding is disabled; no module-registration
  anomaly is expected or claimed.
- Detector order **after** the sample: baseline scan 0, detector unload, sample
  load, detector reload, active scan 1, sample unload, restored scan 0.
- Both root-owned filename and UID-owned files disappear from pathname and
  descriptor-based enumeration before AND after the active scan. Direct opens
  retain the same device/inode and expected contents; retained descriptors agree.
- UID-owned child PID **27087** absent from both numeric enumerations, still
  alive, with unchanged start ticks. Client produces the exact-PID
  `SUSPICIOUS / missing_from_proc_enumeration` finding.
- The untargeted control file remains visible and intact.
- Handler-entry CALL candidate appears once, not duplicated for its table alias.
  Its destination matches a stable tracefs trampoline registration with callback
  `fh_ftrace_thunk [caraxes]`, count 1 and flags RIM.
- `ftrace / ipmodify_on_selected_function` attributes that registration to
  Caraxes. The kernel ownership field remains unresolved for the allocated
  trampoline; client attribution is explicitly a second same-kernel observation.
- Active scan: **26 OK, 4 INFO, 3 SUSPICIOUS, no ERROR/UNSUPPORTED**. The three
  findings represent process discrepancy, entry-call evidence and ftrace
  registration evidence—not three separate rootkits.
- All canary visibility returns after sample unload; recovery scan 0; cleanup
  errors empty; overall experiment exit 0. Active client exit 1 is expected for
  positive evidence, not an execution failure.
- Kernel-log delta adds only detector lifecycle and sample hook-installation
  messages; no new fault diagnostic observed.
- `inodeyou-cpp` is not invoked, so this confirms file **hiding behaviour**, not
  file-content detector effectiveness. Full malicious-intent classification and
  broader sample coverage are not established by this single case.

The exact HID-BPF baseline rows have been added to the automated parser regression
suite. Later documentation/report wording changes do not alter this validated
detector binary. AArch64 runtime remains deferred; subsequent sample cases below
extend the validation.

## Known sample revisions on VM

| Checkout | Revision at inventory |
| --- | --- |
| Diamorphine | `af494fad213654aae16cfdbbb50e7dc26383e4b2` |
| Singularity | `87875157c4dda767709eb2538708510b8bf7ef00` |
| caraxes | `899e8be6b5f6c7236bd23b52aa65051de757e0b3` |

These are observations of checkout identity, not endorsement of compatibility.
The inventoried Diamorphine source selects a table-pointer implementation for
6.8; the Ubuntu headers describe tracing-only use of that table. Verify actual
file/process behaviour, rather than assuming a successful build/load means the
hook controls live execution.

### Prepared reboot-isolated sample runners

`scripts/validate_samples.py` and `scripts/canary_worker.py` add pinned
Diamorphine/Singularity cases with retained-descriptor file identity, detached
PID-1-adopted process IPC/pidfd corroboration and owned TCP IPv4 controls. Each
sample load attempt writes a pending-reboot marker before `insmod`; clean
validation and another sample run refuse the same boot. Samples are left loaded
for reboot recovery rather than removed through self-hidden registrations.

Local automated checks cover targeted versus unrelated findings, inactive hiding,
blocked identity lookup, failed controls, ambiguous module reporting, bad socket
baselines, before/after detector order, failed initialization/collection, cleanup
and malformed recovery state. The suite has 69 Python tests; one benign Linux
pidfd integration test is skipped on macOS. C decoder tests also pass.

The detector binary/kernel source remains v0.2.1. After SSH connectivity returned,
the additions were synchronized and native VM checks passed: C decoder plus all
69 Python tests, including the detached-canary IPC/pidfd test that is skipped on
macOS. Both read-only sample preflights passed on `6.8.0-146-generic`, x86-64,
at `2026-10-12T14:23:58Z`, boot ID `34718f80-130a-4759-9b75-46950ef151da`.
The detector srcversion/hash match the previously validated v0.2.1 binary.

Sample binary hashes recorded by preflight:

- Diamorphine: `37410e9a17c43a581f32a07078c1e2d8ec1b52966f80b6304af1297f5595343e`.
- Singularity: `c5e5384e487f46d98fe2141fbc37dabb7abe24f8efa7775bd62dc34c5ef24fb7`.

The boot above has prior Caraxes validation exposure; it is not a fresh-boot
negative-control claim. The subsequent Diamorphine case below uses a different,
fresh boot. Subsequent Singularity cases and reboot recovery are recorded below.
See `SAMPLE_TESTS.md` for commands and per-feature scoring.

## v0.2.1 Diamorphine case: 20261012T145006Z-controlled-63239bf3

- Ubuntu x86-64 `6.8.0-146-generic`; fresh boot ID
  `6664402e-5aa4-4bad-ab34-5c8bc5c80448`, boot UTC `2026-10-12T14:46:57Z`.
  Environment captured 188.61 seconds after boot with kernel taint 0.
- Reviewed sample commit and binary match the preflight inventory. Detector
  srcversion `C82C596877ECB231903D9AF` and SHA-256 match validated v0.2.1.
- Baseline scan exit 0: **28 OK, 4 INFO, no suspicious/error/unsupported records**.
  After-order sequence unloads this detector, loads Diamorphine and reloads it.
- Both active observations show the sample missing from `/proc/modules`, but its
  direct `/sys/module/diamorphine` path present. The detector identifies the LIVE
  module kobject/list discrepancy as `live_kobject_missing_module`, target
  `diamorphine`, owner `diamorphine (unlisted)`.
- Three syscall-table pointer anomalies: `getdents64[217]`, `kill[62]`,
  `getdents[78]`; each is `unexpected_handler`, attributed to the same unlisted
  module and named `hacked_*` function. The native `handler:*` entries remain
  unchanged. Header-backed coverage is `table_is_tracing_metadata`; table
  mutation is observed, not evidence of live dispatch interception.
- The name canary retains visibility, content and held/direct inode identity.
  PID **2397** remains enumerable, alive through IPC/pidfd corroboration, adopted
  by PID 1, and direct-start-identity stable before and after the active scan.
  Signal 31 was issued from the child, but hiding was not observed. File/process
  behaviours are unexercised; no process-detection success or miss is claimed.
- Active scan exit 1: **24 OK, 4 INFO, 4 SUSPICIOUS, no ERROR/UNSUPPORTED**;
  no truncation, complete process and ftrace collection. The four records denote
  one registry discrepancy and three table changes, not four separate rootkits.
- Ftrace bracketing captures agree; no selected registration/candidate. Pointer
  inspection and registration evidence remain separate mechanisms.
- Untargeted control intact; detector load/unload commands all return 0;
  cleanup errors empty; experiment exit 0. Sample removal was not attempted;
  the pending-reboot marker records this boot ID.
- Exact kernel-log delta adds out-of-tree/unsigned module taint notices and
  detector lifecycle messages only; no new kernel fault diagnostic observed.
  Taint becomes 12288 after unsigned/out-of-tree loading, as expected.
- Reports have been retrieved locally with restricted permissions. Subsequent
  reboot recovery and Singularity validation are recorded below.
- A read-only Singularity preflight on the same sample boot correctly refuses
  execution with `Sample recovery requires a reboot before this test`.

## Initial Singularity run and client v0.3.0 preparation

User-provided execution output:

- Diamorphine recovery `20261012T151344Z-fedef34f`: load, status, scan, interface
  smoke, unload and log commands all exit 0 with `--expect-clean`.
- Singularity `20261012T151345Z-controlled-dbda24a9`: baseline exit 0, sample and
  after-order detector load succeed, active scan exit 3, detector unload succeeds.
  File, process and TCP IPv4 hiding confirmed; control intact; cleanup errors empty.
- Sample is absent from both module interfaces, but the module check has no
  matching finding. Network callback check detects evidence. Process check is
  incomplete. Overall experiment exit 3 preserves the miss and incompleteness.

An SSH invocation of the existing client's `show` on the saved active scan reports:

- **26 OK, 25 SUSPICIOUS, 5 INFO, no ERROR/UNSUPPORTED**.
- Four network entry CALL candidates and six native-syscall entry CALL candidates.
- Fifteen selected ftrace IPMODIFY registrations, numeric callback
  `0xffffffffc0ccb8b0`, with no named module attribution after symbol concealment.
- PID **2415** is `lifecycle_inconclusive`: missing from both enumerations and
  direct lookup. Retained canary IPC alone is deliberately not injected into the
  production detector to declare this a process detection.

Live report retrieval fails at rsync protocol tag `0x20202020`, including a
single-directory retry. The sample's reviewed pipe/log write filters provide a
plausible explanation, not independent proof of causality. Full saved artifact
and kernel-log verification are pending post-reboot retrieval. No claim about an
unfiltered fault-free Singularity log is made. These artifacts were subsequently
retrieved and verified as recorded below.

Changes prepared from these observations:

1. Client v0.3.0 performs one later process-only transaction after failed direct
   proc lookups. It requires a complete, strictly later snapshot, identical PID
   namespace and exact PID/nanosecond birth identity. Persistent discrepancies
   use `missing_from_proc_enumeration` with `identity_source=kernel_task_revalidation`
   and recorded confirmation times. Exit/reuse, stale/partial/failed confirmation
   remain incomplete/error, with no sample-specific PID or oracle input.
2. Extend exact single-trampoline CALL attribution to known proc-network show
   callbacks. Verify the actual callback equals the named expected origin first;
   keep substituted pointers suspicious and numeric callback ownership unknown.
3. Show the recorded client version separately from kernel-module version. The
   kernel remains the unchanged, previously validated v0.2.1 binary.

Local checks: 80 Python tests, one Linux-only skip, C decoder passed. New tests
cover persistent hidden lookup, real exit, nanosecond PID reuse, malformed/stale/
wrong-namespace/partial/changed-version confirmation, failed second transaction, single batched
revalidation, bounded non-recursive descriptor use, numeric network callbacks and
substituted/uncorroborated network origins. Native checks, reboot recovery and a
positive v0.3.0 retry remained pending at preparation; subsequent native checks
passed as recorded below. Tests do not establish measured detection.

### Post-reboot artifact verification and v0.3.0 native checks

- Changed boot ID `6ca5e215-9032-4912-985b-b10f71ceb338` confirmed over SSH;
  previous sample boot was `ba4d9af6-bb3e-4d94-b10f-fe1901547a0f`. No sample/detector
  is listed and `/proc/lkmrkdet` is absent in the read-only observation.
- The same combined rsync command now succeeds, retrieving both reports to the
  restricted local `reports/` directory. That temporal contrast supports transport
  interference during the active sample; it is not independent causality proof.
- Diamorphine recovery report verifies all exit codes 0, standalone interface
  tests pass, full scan 28 OK / 4 INFO / no candidates or incomplete checks.
  Exact log delta is four expected signing/taint and detector lifecycle lines.
- Both Singularity active observations confirm PID **2415** absent from numeric
  proc enumeration and direct stat (ENOENT), while IPC/pidfd liveness persists.
  Named file enumeration omits the canary with held/direct content/inode intact.
  Both module interfaces omit the sample.
- TCP IPv4 target port **8081**, inode **29211**, is missing from reporting but
  retains descriptor identity and successful loopback payload exchange. Control
  port **39885**, inode **29212**, remains reported, identity-stable and active.
- Raw tracefs and parsed report agree with the 25 hook/registration candidates.
  Network callback pointers still equal their expected named core handlers;
  entry CALLs target the reported numeric trampolines. This supplies the origin
  evidence required by the new network correlation rule.
- Singularity's saved after-log omits the earlier signing/taint lines and one
  AppArmor audit line; new detector lifecycle lines remain. The capture cannot
  support an unfiltered no-fault claim, despite both dmesg commands returning 0.
- v0.3.0 client and tests deployed on the recovered VM. Full native regression:
  **80 Python tests, no skips, C decoder passed**. Additional guard review requires
  equal kernel/architecture/module versions in revalidation and an OK known
  network pointer origin before correlation.
- The kernel binary is unchanged v0.2.1. Subsequent privileged v0.3.0 verification
  is recorded below.

## Client v0.3.0 verified baseline, Singularity retry and recovery

### Baseline: 20261012T161114Z-74cbf01c

- Kernel module v0.2.1, client v0.3.0, Ubuntu x86-64 `6.8.0-146-generic`.
  Boot ID `6ca5e215-9032-4912-985b-b10f71ceb338`; pre-load taint 0.
- `--expect-clean`; load, status, full scan, standalone interface smoke, unload
  and kernel-log commands all exit 0.
- Scan: **28 OK, 4 INFO, no suspicious/error/unsupported records**. No truncation;
  PID comparison and ftrace collection complete.
- Log delta is four expected signing/taint and detector lifecycle lines. No new
  kernel fault diagnostic observed in this negative-control interval.

### Positive retry: 20261012T161114Z-controlled-2a2be8f7

- Same boot and unchanged reviewed Singularity source/binary. Detector order
  **after**; kernel binary srcversion/hash remain those of validated v0.2.1.
- Both active observations corroborate hidden PID **3388**: absent numeric proc
  listing and direct stat ENOENT, but retained IPC/pidfd liveness remains intact.
- Client reports exact-PID `missing_from_proc_enumeration`,
  `identity_source=kernel_task_revalidation`: **DETECTED**. Confirmation records
  PID namespace `4026531836`, birth identity `1885250214064` ns, collection start
  `1892580210785` ns and finish `1892580352553` ns. This is strictly later than
  the initial snapshot; no canary oracle is supplied to the production rule.
- Named file remains omitted from enumeration while held/direct inode/content
  agree. Ordinary control remains visible and intact. File-content detection is
  not scored because inodeyou-cpp is separate.
- TCP IPv4 target port **8081**, inode **34703**, remains absent from reporting but
  descriptor identity and loopback exchange succeed. Control port **50237**,
  inode **34704**, remains visible and active. Network evidence **DETECTED**.
- All four proc-network entry CALLs now carry exact tracefs callback correlation,
  flags RIM and numeric callback `0xffffffffc0b888b0`. Original owner remains
  unresolved and callback module owner null; no hidden-module name is guessed.
- Full active scan: **26 OK, 26 SUSPICIOUS, 4 INFO, no ERROR/UNSUPPORTED**, no
  truncation, complete PID/ftrace checks; client exit 1. The additional candidate
  replaces the former lifecycle-inconclusive canary record. These are related
  observations, not 26 independent rootkits or trust sources.
- Both module registrations disappear; `module_detection=NO_MATCHING_FINDING`
  remains a measured gap. Experiment exit **1** preserves that miss without an
  incomplete-process bit. Detector unload succeeds; cleanup errors empty.
- The sample is left loaded for reboot recovery. Logs captured under the active
  sample are not treated as unfiltered integrity evidence.

### Final recovery: 20261012T161211Z-6970e68f

- New boot ID `b49115f3-457d-4489-97ba-9df7ef923c1f`, boot UTC
  `2026-10-12T16:11:40Z`, pre-load taint 0, collection 30.72 seconds after boot.
- Client v0.3.0 with unchanged kernel v0.2.1; `--expect-clean`.
- All commands, including standalone interface smoke and unload, exit 0. Full
  scan: **28 OK, 4 INFO, no suspicious or incomplete checks**.
- Exact log delta contains expected out-of-tree/unsigned notices and detector
  lifecycle lines only; no new kernel fault diagnostic observed in the interval.
- All three saved report directories retrieved after reboot. Subsequent SSH
  observation confirms the changed boot and absent detector endpoint.

The process improvement and network attribution are measured; doubly-unlinked
module discovery is not fixed. Negative controls and recovery remain scoped
guest observations, not independently trusted kernel attestation.

## Client v0.3.1 presentation-only update

- Add summary-first output grouped by processes, modules, network, filesystem,
  system calls and tracing. Status labels use a restrained palette; secondary
  evidence is dimmed, and original details remain available with `--verbose`.
- `--color auto|always|never`; automatic mode checks the output terminal and
  honours `NO_COLOR`/`TERM=dumb`. An explicit choice overrides automatic policy.
  JSON is plain even with `--color always`, and exit-status semantics are unchanged.
- Saved-report rendering explicitly identifies replay rather than a live scan.
  Missing/partial comparison remains incomplete; status inventory is not a scan.
- Local verification: **96 Python tests, one Linux-only skip, C decoder passed**.
  New cases cover grouping, summary severity, preservation of original report
  data, terminal control escaping, verbose evidence, JSON/error streams, and real
  pseudo-terminal execution. The PTY capture retains a slave descriptor until
  reading to avoid Darwin's last-slave-close discard behaviour.
- Re-rendered negative control `20261012T161211Z-6970e68f` and Singularity case
  `20261012T161114Z-controlled-2a2be8f7` retain their recorded client version and
  original exit codes 0/1. README examples are labelled shortened recorded output;
  detection counts and known module-check limitations are not changed.
- The README's inode column is **Not tested** for all samples. File-hiding
  behaviour does not establish inode cross-view detection. Diamorphine's reviewed
  sample installs only getdents/getdents64/kill hooks and has no network-hiding
  implementation; Caraxes's reviewed module hiding is disabled. Unknown or
  unexercised features are not relabelled unsupported.
- After SSH access returned, client v0.3.1 and its output regression tests were
  deployed to the Ubuntu VM. Native `make test` passed: **all 96 Python tests, no
  skips, C decoder**, including real pseudo-terminal colour policy and JSON tests.
- No kernel or detector logic change, and no new live rootkit experiment is
  claimed for this presentation update. Earlier detection evidence remains
  versioned separately. The local technical wiki draft is outside the repository.
- README rootkit names link to the original upstream projects, verified against
  checkout remotes and upstream documentation. Separate wikis are disabled for
  Diamorphine/Singularity; the Caraxes wiki route redirects to its project README.

## Prepared dedicated directory cases

`scripts/validate_directories.py` adds name-selected canaries for all three
reviewed samples, UID-only/GID-only directory canaries for Caraxes and an ordinary
control. Baseline and bracketing observations compare parent pathname/held-FD
enumeration, direct open, a child-process chdir probe, held directory/marker
identity and content, and relative child access. The manager's cwd is unchanged.

Tests verify identity/control failures, mixed enumeration, blocked direct access,
independent ownership/name scoring, incomplete scans, unrelated alerts, no hiding,
baseline abort, failed initialization, active/recovery failure, marker-before-load
ordering and non-recursive cleanup. Local regression: 119 Python tests with one
Linux-only skip and C decoder passed. Native VM regression: all 119 Python tests,
no skips, and C decoder passed. No sample is loaded by unit tests.

Read-only preflights for Caraxes, Diamorphine and Singularity pass on
`6.8.0-146-generic`, boot `b49115f3-457d-4489-97ba-9df7ef923c1f`, at
`2026-10-13T03:59:53Z`, with unchanged reviewed sample/module identities. This boot
has prior detector exposure; new privileged sample cases require separate fresh
boots. Subsequent configuration-specific directory cases are recorded below.

The case explicitly reports directory-hiding behaviour separately from matching
getdents/ftrace hook evidence. Directory-object detection remains unimplemented;
the fixture oracle is not supplied to the production detector. Caraxes recovery
must restore every directory's visibility/access. All attempted sample loads,
including Caraxes, mark the boot for reboot before the next sample. See
`DIRECTORY_TESTS.md` for commands and interpretation.

Final publication review adds one cleanup-retry regression: a failed deletion
followed by closed owned descriptors must defer work rather than interpret a
relative name in the manager's cwd. No successful-case behaviour or detector
logic changes. Final checks pass locally (120 tests, one Linux-only skip) and on
the VM (all 120 tests, no skips), with C decoder passed. Earlier 119-test counts
below describe the runner validation at those measured experiments.

### Caraxes: 20261013T040600Z-controlled-1e5acc5a

- Fresh boot ID `f930f014-67d1-427e-8cbc-21ddbc477baf`, initial taint 0, collector
  58.31 seconds after boot. Reviewed Caraxes binary SHA-256
  `0adf762c73360258cabda0f1eeb592612bde62dc08a83c863977e286c12f47dc`,
  srcversion `92BABC7A3EFE68C5CCA5843`; unchanged kernel v0.2.1/client v0.3.1.
- UID-only and GID-only fixture ownership is recorded as 1001/0 and 0/21. Name
  and ordinary control directories are 0/0.
- GID-selected directory device/inode `2050/272`, marker `2050/273`: absent from
  both parent views in both active observations, held identity/content intact,
  direct open/chdir and relative marker access succeed. Directory hiding confirmed.
- Name directory and UID directory remain visible in both parent listings,
  identity-stable and accessible: not observed/unexercised for parent hiding.
- Marker enumeration inside UID/GID directories is false during activation while
  held/relative reads succeed; it returns on unload. Repeatability in a benign
  fixture is tested to avoid mistaking a retained-FD iterator offset for hiding.
  No cause for the sample's differing selector behaviour is asserted.
- Enumeration evidence: one native handler-entry CALL plus one stable IPMODIFY
  registration for getdents64, callback attributed to Caraxes, flags RIM.
  Active scan **27 OK, 2 SUSPICIOUS, 4 INFO**, exit 1, complete collection.
- Before/restored scans **28 OK, 4 INFO**, exit 0. Every directory/marker view and
  access check restores after sample unload; control intact; cleanup succeeds;
  experiment exit 0. Object-specific directory detection remains unimplemented.
- The log delta adds expected signing/taint, detector lifecycle and sample
  hook-installation messages only. No new kernel fault diagnostic observed.
- Report retrieved locally; current-boot marker still requires reboot before
  further samples. Control-marker visibility is now required by the directory
  baseline/control rule; original recorded control meets that condition. Updated
  native tests pass all 119 tests plus C decoder. Further cases follow below.

### Diamorphine: 20261013T042409Z-controlled-cc6ae964

- Fresh boot `e15dd3e2-d8b7-4718-894d-3173bdf67b5c`, boot UTC
  `2026-10-13T04:19:33Z`, collection 276.18 seconds after boot, initial taint 0.
  Reviewed sample commit and SHA/srcversion match the earlier inventory;
  kernel v0.2.1/client v0.3.1 unchanged.
- The name-selected directory and ordinary control remain visible in both parent
  views in both active observations. Held directory/marker identity/content,
  direct open, relative marker read/listing and child chdir all succeed.
- `directory_hiding=NOT_OBSERVED`, `enumeration_hook_evidence=NOT_EXERCISED`.
  Getdents/getdents64 table-pointer anomalies are preserved, not counted as
  evidence of a demonstrated directory-hiding effect.
- Active scan **24 OK, 4 SUSPICIOUS, 4 INFO**, exit 1, no errors/unsupported.
  Findings are the LIVE kobject/list discrepancy and three altered table pointers
  (getdents, getdents64, kill) attributed to `diamorphine (unlisted)`. Native
  handler observations remain unchanged; table metadata coverage caveat applies.
- Baseline scan exit 0; fixture cleanup and detector unload succeed. Experiment
  exit 2 is the unexercised case classification, not collection failure or miss.
  Sample removal is not attempted; current boot remains marked for reboot.
- Exact log delta adds expected signing/taint, detector lifecycle and one unrelated
  UFW line. No new kernel fault diagnostic observed. Report retrieved locally;
  subsequent post-reboot recovery and Singularity directory test follow below.

### Singularity: 20261013T043003Z-controlled-797c0148

- Pre-case recovery `20261013T043003Z-50a90b4f`: fresh boot
  `9b6e5c1d-ef5e-4de5-95e7-a4a259fd2620`, initial taint 0, `--expect-clean`.
  All commands including standalone interface smoke exit 0; full scan
  **28 OK, 4 INFO, no suspicious/incomplete checks**.
- Directory case runs immediately afterward on the same boot, matching reviewed
  Singularity commit/binary hashes and unchanged kernel v0.2.1, client v0.3.1.
- Target directory `2050/378`, marker `2050/379`: absent from both parent views in
  both active observations, held/relative identity/content stable; marker listing
  via held directory succeeds. Directory enumeration hiding **CONFIRMED**.
- Direct open succeeds with the same directory identity. Child chdir fails
  ENOENT (2) on both observations. These facts are recorded without assuming all
  direct access paths are blocked. Ordinary control `2050/380`, marker `2050/381`,
  remains visible and accessible with stable identity/content and successful chdir.
- Enumeration evidence: native getdents/getdents64 CALLs and their stable IPMODIFY
  registrations, callback numeric `0xffffffffc0c4c8b0`, flags RIM. No module owner
  name is guessed after concealment. The controlled enumeration-hook field is
  **DETECTED**; object-level directory detection remains unimplemented.
- Active full scan **27 OK, 25 SUSPICIOUS, 4 INFO**, exit 1, complete, no errors or
  unsupported checks. No process-hiding trigger or network listener is used in
  this directory-only experiment. Experiment exit 0; cleanup errors empty;
  detector unload succeeds, sample left for reboot. Module-concealment coverage
  is not scored by this narrower experiment.
- The saved after-log loses earlier audit and signing/taint lines; detector
  lifecycle lines remain. Do not claim an unfiltered fault-free active interval.

### Final directory-series recovery: 20261013T043051Z-5e30d678

- New boot `000fdb32-8bb3-4acb-8cce-7273da234771`, boot UTC
  `2026-10-13T04:30:33Z`, capture 17.94 seconds after boot with taint 0.
- All status/full scan/interface/unload/log commands exit 0; **28 OK, 4 INFO**,
  no suspicious or incomplete checks. Detector endpoint absent afterward.
- Both pre-Singularity and final recovery exact log deltas contain the four
  expected signing/taint and detector lifecycle lines only; no new kernel fault
  diagnostic observed in either negative-control interval.
- All saved report sets retrieved after reboot; raw working artifacts remain
  outside the source publication. Caraxes/Diamorphine/Singularity directory
  behaviours are now measured individually; no universal hiding/detection claim
  or independent kernel-integrity attestation follows from these results.

## Runtime sequence

1. Revert to a clean lab snapshot and record kernel and sample revisions.
2. Load the detector and run `status`, selected scans, and runtime smoke tests.
3. Review kernel logs. Repeat load/scan/unload with no lingering descriptors.
4. Validate legitimate modular filesystem ownership and optional tracing.
5. Record a known object's identity and activity before activating a sample.
6. Verify that the sample actually changes the expected observation.
7. Scan with detector before/after load orders where feasible.
8. Record candidates, collection failures, unsupported checks and missed hiding.
9. Restore the snapshot between samples; don't combine samples for initial tests.

## Feature-level report template

| Sample/commit | Kernel/arch | Activated behaviour | Ground truth | Check | Result | Explanation |
| --- | --- | --- | --- | --- | --- | --- |
| Caraxes 899e8be... | 6.8.0-146 x86-64 | UID-based process enumeration hiding | PID 4849 alive, direct identity matches | processes (v0.1) | Detected | Visibility restored after unload |
| Caraxes 899e8be... | 6.8.0-146 x86-64 | Filename filter | Named marker stayed enumerable | File-content detector | Not exercised | inodeyou-cpp not invoked |
| Caraxes 899e8be... | 6.8.0-146 x86-64 | ftrace IPMODIFY | enabled_functions and entry CALL agree | entry patterns (v0.1) | Candidate flagged | Duplicate alias finding; v0.2 adds explicit attribution |
| Caraxes 899e8be... | 6.8.0-146 x86-64 | UID-based process hiding | PID 27087 alive, identity stable | processes (v0.2.1) | Detected | Detector loaded after sample; recovery passes |
| Caraxes 899e8be... | 6.8.0-146 x86-64 | Name/UID file hiding | Direct content/inode stable, enumeration omits both | File-content detector | Not tested | Hiding confirmed; inodeyou-cpp separate |
| Caraxes 899e8be... | 6.8.0-146 x86-64 | ftrace IPMODIFY | Entry CALL target and callback registration agree | syscalls/ftrace (v0.2.1) | Candidate attributed | Single code observation plus explicit tracefs attribution |
| Diamorphine af494fad... | 6.8.0-146 x86-64 | Module-list unlinking | Known load; absent list row, direct sysfs path retained | modules (v0.2.1) | Detected | LIVE kobject missing from module list |
| Diamorphine af494fad... | 6.8.0-146 x86-64 | Three syscall-table changes | Table pointers name hacked functions in unlisted module; native handlers unchanged | syscalls (v0.2.1) | Anomalies detected | Tracing metadata on this backport; live interception not established |
| Diamorphine af494fad... | 6.8.0-146 x86-64 | Name/PID hiding requested | File and PID 2397 remain visible and identity-stable | file/process behaviours | Not exercised | No hiding observed; not scored as a detector miss |
| Singularity 87875157... | 6.8.0-146 x86-64 | File/PID/TCP hiding | Held objects and IPC active; direct PID stat absent | processes (client v0.2.1) | Incomplete | ENOENT indistinguishable from exit without later kernel confirmation |
| Singularity 87875157... | 6.8.0-146 x86-64 | PID enumeration and lookup hiding | PID 3388 birth identity persists in later kernel snapshot; fixture IPC agrees | processes (client v0.3.0) | Detected | Exact-PID finding; production rule uses no fixture oracle |
| Singularity 87875157... | 6.8.0-146 x86-64 | TCP IPv4 reporting hiding | Port 8081 listener active, inode retained, absent proc reporting; control visible | network/ftrace (client v0.3.0) | Detected/correlated | Exact entry CALL/trampoline correlation; owner remains unknown |
| Singularity 87875157... | 6.8.0-146 x86-64 | Both module registrations removed | Known load, both reported views absent | modules (kernel v0.2.1) | Missed | Consistent removal evades the two-view rule; hook/PID evidence remains |
| Caraxes 899e8be... | 6.8.0-146 x86-64 | GID-selected directory hiding | Both parent views omit it; held objects/direct open/chdir intact | directory case / enumeration hooks | Behaviour confirmed; hook evidence detected | Name/UID parent hiding not observed; recovery succeeds |
| Diamorphine af494fad... | 6.8.0-146 x86-64 | Prefix directory hiding requested | Both listing views and all access retain the directory | directory case | Not exercised | Table mutations observed, live hiding not demonstrated |
| Singularity 87875157... | 6.8.0-146 x86-64 | Named directory hiding and access filtering | Both parent views omit it; held/relative/direct open intact; chdir ENOENT | directory case / enumeration hooks | Behaviour confirmed; hook evidence detected | Numeric callback owner preserved; clean reboot recovery |

Required categories include missing module registration, directory filtering,
process enumeration filtering, proc network reporting, and inline/ftrace
redirection. This implementation does not promise coverage of every category;
document misses. ftrace registrations and deep dispatcher callsite patching are
not explicitly enumerated in v0.1.
