# lkmrkdet — Technical Wiki

An inspection-oriented Linux LKM rootkit detection proof of concept. It is tested on Ubuntu x86-64 and compiled against the target kernel's own headers. It combines callback ownership, selected entry-pattern observations, module-registration cross-view checks, a process-list/procfs comparison, and client-side tracefs attribution.

| Component | Validated version |
| --- | --- |
| Kernel module | 0.2.1 |
| Python client | 0.3.1 |
| Report schema | 1 |
| Tested kernel | Ubuntu 24.04.4 LTS, x86-64, `6.8.0-146-generic` |

Last validated: 2026-10-25 | code commit: `f77aac2` | report schema: 1. The current source tree builds with `make module W=1`. At the recorded validation point, the local lab suite contained **135 Python tests** plus the C decoder test; one Linux-only fixture test skips on macOS.

Tests and privileged lab scripts are kept in the private validation checkout. A published clone supports `make module`; `make test-lab` requires the local `tests/` directory.

Privileged load/scan/interface/unload checks and reboot recovery were also validated.

## Controlled sample results

| Controlled sample | Measured result | Remaining limitation |
| --- | --- | --- |
| [Caraxes](https://github.com/ait-aecid/caraxes) | Hidden process detected; entry CALL/ftrace callback attributed; name/UID file hiding confirmed; visibility restored on unload | Module hiding disabled in this configuration |
| [Diamorphine](https://github.com/m0nad/Diamorphine) | Module-list concealment and three changed syscall-table pointers detected with the detector loaded afterward | File/PID hiding not observed on the metadata-only dispatch backport; not scored as a miss |
| [Singularity](https://github.com/MatheuZSecurity/Singularity) (v0.3.0 measurement) | Hidden PID detected through later kernel birth-identity revalidation; network entry CALLs correlated with IPMODIFY registrations; file/PID/TCP hiding confirmed | Removing both module registrations evades the module check; callback owner remains numeric/unattributed |

Client v0.3.0 introduced process identity revalidation and proc-network CALL correlation. Client v0.3.1 changed grouped, colour-coded output only; detection logic is unchanged. The Singularity measurement above retains its original v0.3.0 attribution.

The controlled retry and both negative controls are verified. Experiment exit `1` explicitly preserves the remaining module-check miss, while the complete positive client scan also returns `1`.

> **Note:** Findings are scoped evidence, not independent kernel-integrity attestation.

## Checks

| Check | Observation | Important exclusions |
| --- | --- | --- |
| `modules` | LIVE module list versus typed module kobjects; records executable text ownership | Built-ins and transitional objects excluded. Removing both registrations can evade it. |
| `filesystem` | `iterate_shared` (or older `iterate`) for `/`, `/proc`, `/sys`; selected named targets and text owners | Caller mount namespace only. No full VFS walk or enumeration of all mount points. Registered module ownership alone is not benignness. |
| `network` | Opens `/proc/net/{tcp,tcp6,udp,udp6}` and inspects their actual `seq_file` show callbacks | No socket inventory, packet scan, netlink/sock_diag, or hidden-port scan. |
| `syscalls` | Selected native table entries **and** independently resolved native handler entries | Not every syscall, no compat ABI, no complete dispatch/code-integrity attestation. Distribution backports matter. |
| `processes` | `for_each_process` leaders versus bracketing numeric proc enumeration; direct start-time identity, or a later matching kernel birth-identity snapshot when direct lookup is absent | Initial PID namespace only. Exit/reuse/failed revalidation remain incomplete. Both snapshots share kernel trust; task-list DKOM and thread-only hiding are not covered. |
| `ftrace` | Client reads existing tracefs `enabled_functions` around the scan; identifies selected IPMODIFY registrations and correlates single-callback entry CALL destinations | Same-kernel reporting; selected functions only. No internal ftrace-list walk, trace enabling, or mounts. Missing/changed/unknown output is explicit incompleteness. |

Selected syscalls: `read`, `getdents64`, `kill`, `openat`, `init_module`, `finit_module`, `delete_module`, `bpf`, and `getdents` where that ABI has it.

## Symbol resolution

Modern kernels do not export several relevant symbols to modules. This PoC uses an explicitly documented temporary disabled kprobe on `kallsyms_lookup_name` to discover its address. It installs no pre/post handler, never redirects execution, and unregisters the probe during initialization. It then uses kernel symbol lookup to obtain core registry addresses and expected handler identities.

This depends on kernel internals and tracing policy, not a stable module ABI. Failures do not prevent module load: affected checks report `UNSUPPORTED` or `ERROR`. To disable this mechanism entirely:

```sh
sudo insmod lkmrkdet.ko resolve_symbols=0
```

This does not create an independent trust source. A compromised symbol resolver or registry may lie to the detector. There is no memory-protection bypass, kernel-code write, rootkit functionality, or automatic local "clean baseline".

## Entry-pattern evidence

The bounded decoder recognises selected x86-64 function-entry patterns, optionally after an `ENDBR64` landing pad:

- relative `JMP`/`CALL`
- `MOVABS RAX` + `JMP RAX`
- RIP-indirect `JMP`
- `INT3`

It does not scan arbitrary instruction bytes for false opcode matches, and it uses nofault reads for branch literals. A cross-owner destination is a `SUSPICIOUS` candidate; a breakpoint or same-owner branch is `INFO`, not automatically malicious. This can miss ftrace redirection, other encodings, non-entry patches, and changes remaining inside a trusted owner's text. Authorised livepatch or tracing can also produce candidate findings.

Module v0.2.x samples each code address once so a symbol and table pointing to the same function do not duplicate a single patch finding. Pointer checks remain separate.

The client correlates only a stable, single-callback tracefs registration with an exact selected-handler CALL destination. It records the trampoline's reported callback/module without overwriting the kernel's original owner field. A known ordinary tracing CALL can become `INFO`; IPMODIFY, JMPs, pointer anomalies and unmatched destinations are not silently suppressed.

Client v0.3.0 extended this correlation to the four proc-network show handlers. The collected callback must equal its named expected handler and the entry CALL must match one stable numeric trampoline. A substituted pointer is never legitimised by sharing a trampoline. A numeric-only callback is preserved without guessing a module owner.

## Process identity revalidation

If both numeric enumerations omit a snapshot PID and direct stat lookup returns `ENOENT`/`ESRCH`, the client requests one fresh process-only snapshot after all failed lookups. The same PID, PID namespace and exact nanosecond birth identity must persist in this later complete snapshot. Only then is a persistent task/proc discrepancy a candidate. The finding records `identity_source` and revalidation timestamps. No canary PID, IPC oracle or sample name is supplied to this rule.

An absent later task stays lifecycle-inconclusive; a different birth time denotes reuse. Kernel, architecture and module-version identity must also agree. Stale, incomplete, wrong-namespace, malformed or failed confirmation is an error, never a clean result. Normal direct-identity matches need no extra scan.

This improves same-kernel corroboration; it cannot defeat task-list DKOM or make either snapshot independently trustworthy.

## Tracefs attribution

The extra ftrace check is delegated to the Python client; a module-only report is incomplete for that check. It reads already-mounted tracefs without changing tracing state.

- `I` denotes IPMODIFY and can indicate execution redirection.
- `D` denotes direct instrumentation and is not automatically malicious.
- `M` is historical and is not treated as proof of an active hook.

Authorised livepatch can legitimately use IPMODIFY, so findings remain candidates.

Kernel `%pS` output can be a numeric fallback or a symbolic name+offset/size description. Both are parsed; symbolic addresses are not guessed for CALL correlation. Multiple trampoline callbacks, `ops:` descriptors and direct-call continuations are preserved. Kernel-reported `ERROR!` and unknown data still cause explicit incompleteness rather than being ignored.

Read size, lines, entries and result records are bounded. Unknown formats, permission failures, missing endpoints or registration changes produce explicit `ERROR`/`UNSUPPORTED` results. Collection uses the same guest kernel and can be subverted; it is not an independent integrity reference.

Reference: <https://docs.kernel.org/trace/ftrace.html> (`enabled_functions`).

## Build on the target system

```sh
sudo apt install build-essential "linux-headers-$(uname -r)" python3
make module W=1
modinfo ./lkmrkdet.ko
```

For a non-running installed kernel, use `make module KDIR=/path/to/matching/build`. The configure script handles Ubuntu's split headers. Modern procfs APIs are required; this is not a direct build of the original 4.15 detector.

Local lab checkout only:

```sh
make test-lab
```

The published repository does not contain `tests/`. Build generated configuration and kernel/compiler-specific binaries locally; Git ignores them.

## Load and inspect

Take a known-clean lab snapshot before runtime validation. Loading is explicit; the client and build do not load any module automatically.

```sh
sudo insmod ./lkmrkdet.ko
sudo python3 -I client.py status
sudo python3 -I client.py scan --verbose
sudo python3 -I client.py scan --checks modules,filesystem,network
sudo python3 -I client.py scan --checks processes
sudo python3 -I client.py scan --checks syscalls,ftrace
sudo python3 -I client.py scan --format json
sudo rmmod lkmrkdet
```

`-I` isolates Python from `PYTHONPATH` and user site-packages. `client.py` adds its own package directory explicitly.

Module signature enforcement can reject an unsigned out-of-tree module. The tool does not disable signatures or lockdown; use the VM's approved signing workflow if required. `kernel.modules_disabled=1` prevents later loading.

The `/proc/lkmrkdet` interface is mode `0600` and additionally requires `CAP_SYS_ADMIN` in the initial user namespace on open, read and write. A bounded request is parsed before inspection. Each open descriptor has a private report; the client writes its request and reads the same descriptor, avoiding global "last scan" races. A descriptor accepts only one scan. Module references prevent ordinary unloading while a descriptor is open. Directly writing with one process and reading with another will not retrieve the first process's report.

The report contains addresses: keep it restricted as kernel diagnostic data. Interpret filesystem and network observations in the caller's namespaces.

## Status and exit codes

- `OK`: no anomaly in the specific observation, not "clean kernel".
- `SUSPICIOUS`: evidence to corroborate, not confirmed malware.
- `UNSUPPORTED`: required observation unavailable.
- `ERROR`: collection failed or capacity exhausted.
- `INFO`: coverage, instrumentation or lifecycle evidence.

Client scan exit codes are bit flags:

| Code | Meaning |
| --- | --- |
| `0` | Selected checks completed without suspicious evidence; no kernel-integrity guarantee |
| `1` | Suspicious evidence |
| `2` | Incomplete, unsupported, failed, truncated or inconclusive inspection |
| `3` | Both suspicious evidence and incomplete inspection |

`status` is an inventory command, not a scan. Successful collection returns `0` even if it documents an unavailable resolver. The `show` command renders a saved JSON report without loading a module. A raw kernel task snapshot that has not undergone the client's proc comparison is incomplete for process detection.

## Safety and limitations of inspection

- There is no trusted baseline generated from the current system.
- The module-list snapshot uses `module_mutex`; typed kobjects are referenced under their kset lock and released after unlocking. LIVE state is required.
- Kernel reads of inspected callbacks, module metadata and code use nofault helpers. Opened files are closed on all collection paths.
- Traversals, snapshots, records, requests and JSON are bounded. Exhaustion is never silently converted into a clean result.
- Locks and references protect ordinary kernel lifecycle changes. They cannot make arbitrary adversarial kernel corruption safe or guarantee consistent views when malware ignores locking.
- A detector loaded after a rootkit can still observe a discrepancy, but its memory, resolver, APIs and output share the compromised kernel trust domain.

## License

GPL-2.0-only; see [LICENSE](../LICENSE) and the SPDX headers. Third-party samples are external reviewed inputs and are not redistributed in this repository.
