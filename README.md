# lkmrkdet

An inspection-oriented Linux LKM rootkit detection proof of concept for **When
Linux Lies — STANDCON**. One source tree targets x86-64 and AArch64, compiled
against each target's own headers. It combines callback ownership, selected
entry-pattern observations, module-registration cross-view checks, and a
process-list/procfs comparison and client-side tracefs attribution. `inodeyou-cpp` handles filesystem
content cross-view detection separately.

**Validated versions:** Python client **v0.3.0**, kernel module **v0.2.1**,
Ubuntu x86-64 **6.8.0-146-generic**. The module builds with
`W=1 KCFLAGS=-Werror`; all **80 Python tests and C decoder tests** pass on the VM.
Privileged load/scan/interface/unload checks and reboot recovery pass. The latest
negative controls report 28 OK, 4 INFO and no suspicious or incomplete findings.

| Controlled sample | Measured result | Remaining limitation |
| --- | --- | --- |
| Caraxes | Hidden process detected; entry CALL/ftrace callback attributed; name/UID file hiding confirmed; visibility restored on unload | Module hiding disabled in this configuration; inodeyou-cpp not invoked |
| Diamorphine | Module-list concealment and three changed syscall-table pointers detected with detector loaded afterward | File/PID hiding not observed on the metadata-only dispatch backport; not scored as a miss |
| Singularity, client v0.3.0 | Hidden PID detected through later kernel birth-identity revalidation; network entry CALLs correlated with IPMODIFY registrations; file/PID/TCP hiding confirmed | Removing both module registrations evades the module check; callback owner remains numeric/unattributed |

Client v0.3.0 addresses the initial Singularity run's incomplete process identity
and missing network CALL attribution. The controlled retry and both negative
controls are verified; experiment exit 1 explicitly preserves the remaining
module-check miss, while the complete positive client scan also returns 1.

Findings are scoped evidence, **not independent kernel-integrity attestation**.
All guest-side views can be subverted. AArch64 support remains source-level;
module compilation/runtime is deferred. See `docs/VALIDATION.md` for the versioned
ledger, `docs/SAMPLE_TESTS.md` for sample procedures, and `docs/DEMO.md` for the
presentation sequence. Raw reports, rootkit checkouts and build artifacts are
excluded from this repository.

## What is inspected

| Check | Observation | Important exclusions |
| --- | --- | --- |
| `modules` | LIVE module list versus typed module kobjects; records executable text ownership | Built-ins and transitional objects excluded. Removing both registrations can evade it. |
| `filesystem` | `iterate_shared` (or older `iterate`) for `/`, `/proc`, `/sys`; selected named targets and text owners | Caller mount namespace only; no full VFS walk or enumeration of all mount points. Registered module ownership alone is not benignness. |
| `network` | Open `/proc/net/{tcp,tcp6,udp,udp6}` and inspect their actual `seq_file` show callbacks | No socket inventory, packet scan, netlink/sock_diag or hidden-port scan. |
| `syscalls` | Selected native table entries AND independently resolved native handler entries | Not every syscall, no compat ABI, no complete dispatch/code-integrity attestation. Distro backports matter. |
| `processes` | `for_each_process` leaders versus bracketing numeric proc enumeration; direct start-time identity, or a later matching kernel birth-identity snapshot when direct lookup is absent | Initial PID namespace only. Exit/reuse/failed revalidation remain incomplete. Both snapshots share kernel trust; task-list DKOM and thread-only hiding not covered. |
| `ftrace` | Client reads existing tracefs `enabled_functions` around the scan; identifies selected IPMODIFY registrations and correlates single-callback entry CALL destinations | Same-kernel reporting; selected functions only. No internal ftrace-list walk, trace enabling or mounts. Missing/changed/unknown output is explicit incompleteness. |

Selected syscalls: `read`, `getdents64`, `kill`, `openat`, `init_module`,
`finit_module`, `delete_module`, `bpf`, and `getdents` where that ABI has it.

### Ubuntu 6.8 dispatch backport

This VM's matching x86 headers explicitly say `sys_call_table` is used purely
for tracing metadata and declare `x64_sys_call`. The configure step detects
that **header feature**, rather than assuming 6.8 uses the older table dispatch.
The report includes `table_is_tracing_metadata`. A changed table pointer is an
anomaly in that table, **not evidence that live syscalls pass through it**.
Entry sampling does not decode the dispatcher or all downstream callsites.

### Symbol resolution

Modern kernels do not export several relevant symbols to modules. This PoC
uses an explicitly documented **temporary disabled kprobe** on
`kallsyms_lookup_name` to discover its address. It installs no pre/post handler,
never redirects execution, and unregisters the probe during initialization.
It then uses kernel symbol lookup to obtain core registry addresses and
expected handler identities.

This depends on kernel internals and tracing policy, not a stable module ABI.
Failures do not prevent module load: affected checks report `UNSUPPORTED` or
`ERROR`. To disable this mechanism entirely:

```bash
sudo insmod lkmrkdet.ko resolve_symbols=0
```

This does not create an independent trust source. A compromised symbol resolver
or registry may lie to the detector. There is no memory-protection bypass,
kernel-code write, rootkit functionality, or automatic local "clean baseline".

### Entry-pattern evidence

The bounded decoder recognises only function-entry patterns, optionally after
x86 ENDBR64 or an AArch64 BTI landing pad:

- x86-64: relative JMP/CALL, MOVABS RAX + JMP RAX, RIP-indirect JMP, INT3.
- AArch64: immediate B/BL, literal LDR + BR with matching register, BRK.

It does not scan arbitrary instruction bytes for false opcode matches, and it
uses nofault reads for branch literals. A cross-owner destination is a
`SUSPICIOUS` candidate; a breakpoint or same-owner branch is `INFO`, not
automatically malicious. This can miss ftrace redirection, other encodings,
non-entry patches and changes remaining inside a trusted owner's text.
Authorised livepatch or tracing can also produce candidate findings.

v0.2 samples each code address once so a symbol and table pointing to the same
function do not duplicate a single patch finding. Pointer checks remain separate.
The client correlates only a stable, single-callback tracefs registration with an
exact selected-handler CALL destination. It records the trampoline's reported
callback/module without overwriting the kernel's original owner field. A known
ordinary tracing CALL can become INFO; IPMODIFY, JMPs, pointer anomalies and
unmatched destinations are not silently suppressed.

Client v0.3.0 extends this correlation to the four proc-network show handlers.
The collected callback must equal its named expected handler and the entry CALL
must match one stable numeric trampoline. A substituted pointer is never
legitimised by sharing a trampoline. A numeric-only callback is preserved without
guessing a module owner.

### Process identity revalidation

If both numeric enumerations omit a snapshot PID and direct stat lookup returns
ENOENT/ESRCH, the client requests **one** fresh process-only snapshot after all
failed lookups. The same PID, PID namespace and exact nanosecond birth identity
must persist in this later complete snapshot. Only then is a persistent task/proc
discrepancy a candidate. The finding records `identity_source` and revalidation
timestamps. No canary PID, IPC oracle or sample name is supplied to this rule.

An absent later task stays lifecycle-inconclusive; a different birth time denotes
reuse. Kernel, architecture and module-version identity must also agree. Stale,
incomplete, wrong-namespace, malformed or failed confirmation is an
error, never a clean result. Normal direct-identity matches need no extra scan.
This improves same-kernel corroboration; it cannot defeat task-list DKOM or make
either snapshot independently trustworthy.

### Tracefs attribution

The extra `ftrace` check is delegated to the Python client; a module-only report
is incomplete for that check. It reads already-mounted tracefs without changing
tracing state. `I` denotes IPMODIFY and can indicate execution redirection;
`D` denotes direct instrumentation and is not automatically malicious;
`M` is historical and is not treated as proof of an active hook. Authorised
livepatch can legitimately use IPMODIFY, so findings remain candidates.

Kernel `%pS` output can be a numeric fallback or a symbolic `name+offset/size`
description. Both are parsed; symbolic addresses are not guessed for CALL
correlation. Multiple trampoline callbacks, `ops:` descriptors and direct-call
continuations are preserved. Kernel-reported `ERROR!` and unknown data still
cause explicit incompleteness rather than being ignored.

Read size, lines, entries and result records are bounded. Unknown formats,
permission failures, missing endpoints or registration changes produce explicit
ERROR/UNSUPPORTED results. Collection uses the same guest kernel and can be
subverted; it is not an independent integrity reference.

Reference: https://docs.kernel.org/trace/ftrace.html (`enabled_functions`).

## Build on the target VM

```bash
sudo apt install build-essential linux-headers-$(uname -r) python3
make module W=1
make test
modinfo ./lkmrkdet.ko
```

For a non-running installed kernel use `make module KDIR=/path/to/matching/build`.
The configure script handles Ubuntu's split headers. Modern procfs APIs are
required; this is not a direct build of the original 4.15 detector.

Build on the target with its matching headers. Generated configuration and
kernel/compiler-specific binaries are ignored by Git; build them locally.

## Load and inspect

Take a known-clean lab snapshot before runtime validation. Loading is explicit;
the client and build do not load any module automatically.

```bash
sudo insmod ./lkmrkdet.ko
sudo python3 client.py status
sudo python3 client.py scan --verbose
sudo python3 client.py scan --checks modules,filesystem,network
sudo python3 client.py scan --checks processes
sudo python3 client.py scan --checks syscalls,ftrace
sudo python3 client.py scan --format json
sudo rmmod lkmrkdet
```

Module signature enforcement can reject an unsigned out-of-tree module. The
tool does not disable signatures or lockdown; use the VM's approved signing
workflow if required. `kernel.modules_disabled=1` prevents later loading.

The `/proc/lkmrkdet` interface is mode `0600` and additionally requires
`CAP_SYS_ADMIN` in the initial user namespace on open, read and write. A bounded
request is parsed before inspection. Each open descriptor has a private report;
the client writes its request and reads **the same descriptor**, avoiding global
"last scan" races. A descriptor accepts only one scan. Module references prevent
ordinary unloading while a descriptor is open. Directly writing with one
process and reading with another will not retrieve the first process's report.

The report contains addresses: keep it restricted as kernel diagnostic data.
Interpret filesystem and network observations in the caller's namespaces.

### Status and exit codes

- `OK`: no anomaly in the specific observation, not "clean kernel".
- `SUSPICIOUS`: evidence to corroborate, not confirmed malware.
- `UNSUPPORTED`: required observation unavailable.
- `ERROR`: collection failed or capacity exhausted.
- `INFO`: coverage, instrumentation or lifecycle evidence.

Client scan exit codes are bit flags:

| Code | Meaning |
| --- | --- |
| 0 | Selected checks completed without suspicious evidence; no kernel-integrity guarantee |
| 1 | Suspicious evidence |
| 2 | Incomplete, unsupported, failed, truncated or inconclusive inspection |
| 3 | Both suspicious evidence and incomplete inspection |

`status` is an inventory command, not a scan. Successful collection returns 0
even if it documents an unavailable resolver. The `show` command renders a saved
JSON report without loading a module. A raw kernel task snapshot that has not
undergone the client's proc comparison is incomplete for process detection.

## Validation

Host/VM unit tests:

```bash
make test
```

Runtime interface tests (after loading the module yourself):

```bash
sudo python3 tests/runtime_smoke.py
sudo journalctl -k -n 100 --no-pager
```

On a known-clean snapshot, `--expect-clean` also requires the kernel checks to
complete without candidate findings. Tests cover malformed and oversized
requests, embedded NULs, partial reads, EOF, per-descriptor transactions,
concurrent status requests, a known process and repeated scans. They do not
install a rootkit or change kernel hooks. Preserve runtime output and inspect
logs for warnings before declaring this milestone passed.

For one-command validation after building, explicitly run:

```bash
sudo python3 scripts/validate_vm.py --expect-clean
```

This checks kernel vermagic, loads **only `lkmrkdet.ko`**, runs status, scan and
interface tests, captures kernel logs, and attempts to unload the detector in
`finally`. If the detector was already loaded, it is reused and left loaded.
No rootkit is installed. Reports are saved under `reports/<timestamp>-<id>/`,
restricted to the project owner so the development SSH user can review them.
Omit `--expect-clean` when collecting evidence on a deliberately manipulated
snapshot; candidate findings remain in the JSON. Exit status preserves scan
findings/incompleteness. Review logs separately; a VM crash cannot be cleaned up
by a userspace runner.

The runner now records boot ID, boot time, uptime and kernel taint before/after
validation so reports from separate boots can be distinguished.
It also stores bounded, byte-preserving raw `enabled_functions` snapshots before
loading, after loading, after scanning and after cleanup. These aid parser
diagnosis even if no selected function matched or structured parsing failed.

### Controlled Caraxes test

This controlled test uses the existing reviewed Caraxes checkout, with its default
`getdents64` ftrace hook and module unlinking disabled. It checks actual hiding
of an owned file and a disposable UID-1001 child process before scoring process
detection. Source and module hashes, sample revision, boot ID, pre/post object
identities, detector JSON, optional tracefs observations and kernel logs are saved.

Read-only build/configuration check (no sudo or loading):

```bash
python3 scripts/validate_caraxes.py --preflight
```

Explicit experiment on the lab VM:

```bash
sudo python3 scripts/validate_caraxes.py --detector-order after
```

Unlike `validate_vm.py`, **this command loads the existing Caraxes sample**.
It first checks the baseline with lkmrkdet, unloads the detector,
loads Caraxes, reloads the detector, verifies hiding around the scan, then
unloads Caraxes and checks restoration. Cleanup attempts to unload only modules
the runner loaded, terminates its own child and removes only its own canary files.
It creates a root-owned filename canary, a separate UID-owned file, an ordinary
control file, and a disposable UID-owned child. Direct identities/contents are
checked separately from pathname and descriptor-based enumeration results.
It does not add a user account, modify the sample, install persistence or change
the SSH user's identity. Existing loaded samples/detector are rejected to keep
this experiment's state and cleanup ownership unambiguous.

`--detector-order before` leaves the detector loaded when activating the sample.
The sample is pinned to the reviewed revision/configuration; a changed checkout
requires a fresh review of test expectations. Keep a VM snapshot and console
available for kernel failures that userspace cleanup cannot handle.

This runner's exits describe the **experiment**, unlike client scan exits:
0 = process-hiding case passed and visibility restored;
1 = confirmed process hiding was missed;
2 = incomplete/unexercised case or cleanup failure;
3 = both a miss and an incomplete case. A normal positive client scan returns 1
inside a successful experiment. File hiding is recorded, but `inodeyou-cpp` is
not invoked. Process cross-view detection and attribution of the underlying
hook remain separate results, even with v0.2 tracefs inspection.

Details and the report layout are in `docs/CONTROLLED_TESTS.md`, including the
measured v0.1 and passing v0.2.1 cases.

### Diamorphine and Singularity tests

The additional runner uses the existing, reviewed checkouts and binaries. It
records module, file, process and (for Singularity) owned TCP IPv4 observations.
The measured Diamorphine case detects module concealment and three changed
syscall-table pointers. File/PID hiding was not observed on this dispatch backport,
so those behaviours are unexercised. The initial Singularity case reports confirmed
file/PID/TCP hiding, network/tracefs findings, an unreported doubly-unlinked module,
and incomplete process attribution. The v0.3.0 retry detects the hidden PID and
correlates network CALLs, with complete collection. The module-registration miss
remains. All saved reports and final reboot recovery have been verified.
The updated tooling passes all 80 Python tests and the C decoder tests on the
Ubuntu VM; both read-only sample preflights pass.

```bash
python3 scripts/validate_samples.py diamorphine --preflight
python3 scripts/validate_samples.py singularity --preflight
```

On a fresh lab snapshot/boot, explicitly run **one** case:

```bash
sudo python3 scripts/validate_samples.py diamorphine --detector-order after
```

Review/preserve reports and **reboot before** running Singularity:

```bash
sudo python3 scripts/validate_samples.py singularity --detector-order after
```

Both cases leave the sample loaded and require reboot recovery. A boot-ID marker
is written before loading; another sample or `--expect-clean` run is refused on
that boot. Cleanup terminates owned workers, closes sockets/files and attempts to
unload the detector. It does not remove a self-hidden rootkit. See
`docs/SAMPLE_TESTS.md` for isolation, evidence, per-feature scoring and recovery.

Suggested detection matrix and sample revisions are in `docs/VALIDATION.md`.
Start with clean scans. Then validate each hiding behaviour separately, with
ground truth recorded before hiding. Rootkit load success does not demonstrate
functional hiding, particularly when dispatch implementations have changed.

## Safety and limitations of inspection

- There is no trusted baseline generated from the current system.
- Module list snapshot uses `module_mutex`; typed kobjects are referenced under
  their kset lock and released after unlocking. LIVE state is required.
- Kernel reads of inspected callbacks, module metadata and code use nofault
  helpers. Opened files are closed on all collection paths.
- Traversals, snapshots, records, requests and JSON are bounded. Exhaustion is
  never silently converted into a clean result.
- Locks and references protect ordinary kernel lifecycle changes. **They cannot
  make arbitrary adversarial kernel corruption safe or guarantee consistent
  views when malware ignores locking.**
- A detector loaded after a rootkit can still observe a discrepancy, but its
  memory, resolver, APIs and output share the compromised kernel trust domain.
- AArch64 support is source-level until built and tested on the ARM VM.

## Attribution

Conceptually informed by DetectionTool (Joshua Lim and Fai Yew/Felix Kwan),
particularly callback inspection and module cross-view analysis. This is a new
implementation, not the original source with a renamed module. Hidden-inode
detection remains in Felix's `inodeyou-cpp`; PID cross-view techniques also have
precedent in unhide-forensics.

## License

GPL-2.0-only; see `LICENSE` and the SPDX headers. Third-party samples are external
reviewed inputs and are not redistributed in this repository.
