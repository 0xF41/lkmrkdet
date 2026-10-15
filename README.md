# lkmrkdet

A Linux kernel rootkit detection tool that helps spot hidden processes and
suspicious changes in the kernel. It uses a kernel module and a Python
command-line client.

Tested on Ubuntu 24.04, x86-64, kernel `6.8.0-146-generic`.

## Quick start

### 1. Download and build

Run these commands on the Linux machine you want to inspect:

```bash
sudo apt update
sudo apt install git build-essential python3 "linux-headers-$(uname -r)"
git clone https://github.com/0xF41/lkmrkdet.git
cd lkmrkdet
make module
```

The build creates `lkmrkdet.ko` for your running kernel. Rebuild it after a kernel
update. Other kernel versions have not been validated.

### 2. Load the detector and scan

```bash
sudo insmod ./lkmrkdet.ko
sudo python3 client.py scan
```

The default scan checks kernel modules, hidden processes, filesystem and network
reporting, system-call handlers, and tracing hooks.

### 3. Unload when finished

```bash
sudo rmmod lkmrkdet
```

## What each check compares

| Check | Comparison |
| --- | --- |
| Processes | Kernel task snapshot ↔ `/proc` enumeration, with process-identity validation |
| Modules | Kernel module list ↔ typed module kobjects |
| Network | Observed reporting callback and handler-entry evidence ↔ expected handler and available tracing evidence |
| Filesystem | Selected directory-iteration callback ↔ expected handler |
| Syscalls | Selected table pointer and handler entry ↔ expected symbol and recognised instruction patterns |
| Tracing | Entry CALL ↔ stable tracing registration with an exactly matching trampoline address |

Tracing checks also flag selected active `IPMODIFY` registrations independently
of entry-CALL correlation. These comparisons identify evidence for investigation;
they do not establish whole-kernel integrity.

## Understand the results

| Result | Meaning |
| --- | --- |
| `OK` | No anomaly found in that check. |
| `SUSPICIOUS` | A possible hiding or hooking indicator. Investigate before concluding it is malware. |
| `INFO` | Extra information about the scan. |
| `UNSUPPORTED` | The check is unavailable on this system. |
| `ERROR` | The check could not complete. |

Scan exit codes: **0** = checks completed without suspicious findings;
**1** = suspicious findings; **2** = incomplete or failed checks;
**3** = suspicious findings and incomplete checks.

Treat `ERROR` and `UNSUPPORTED` as missing coverage, not a clean result.

## Example output

The CLI groups findings by check and puts the summary first. In a terminal,
headings are cyan, `OK` is green, suspicious findings are red, and failed or
unavailable checks are amber. Addresses and supporting details are muted.

These plain-text examples are excerpts of recorded lab scans rendered by the new
CLI. The versions shown are those recorded in each report; PIDs, addresses and
timings vary between runs. Saved reports are explicitly labelled as replays.

### Clean test VM

```text
lkmrkdet
Kernel module 0.2.1 | Client 0.3.0
6.8.0-146-generic | x86_64
Saved report - not a live scan

NO SUSPICIOUS FINDINGS
0 suspicious | 28 OK | 0 errors | 0 unsupported | 4 info
Inspection complete | Exit code: 0
Kernel collection: 0.33 ms | Observed LIVE modules: 101

PROCESSES
  [OK] 1 observation without an anomaly
  [INFO] task snapshot - Kernel task snapshot collected

MODULES
  [OK] 1 observation without an anomaly

NETWORK
  [OK] 4 observations without an anomaly
  [INFO] coverage - Proc network reporting callbacks only

... remaining check groups omitted ...
```

This is a negative-control result, not a guarantee of kernel integrity.

### Rootkit-present test VM — Singularity

```text
lkmrkdet
Kernel module 0.2.1 | Client 0.3.0
6.8.0-146-generic | x86_64
Saved report - not a live scan

SUSPICIOUS EVIDENCE FOUND
26 suspicious | 26 OK | 0 errors | 0 unsupported | 4 info
Inspection complete | Exit code: 1
Kernel collection: 0.36 ms | Observed LIVE modules: 101

PROCESSES
  [INFO] task snapshot - Kernel task snapshot collected
  [SUSPICIOUS] PID 3388 - Missing from proc enumeration
    A later kernel snapshot matches the PID and birth identity; direct proc lookup is
    unavailable.

MODULES
  [OK] 1 observation without an anomaly

NETWORK
  [SUSPICIOUS] /proc/net/tcp - Function-entry CALL
    Entry CALL matches a stable IPMODIFY tracing trampoline.
    Address: 0xffffffffc0c39000 | Owner: unresolved
    Tracefs callback: 0xffffffffc0b888b0 | Flags: RIM

... remaining findings omitted ...
```

The consistent module views illustrate the known module-check miss. The other
findings detect evidence despite it. Counts are observations, not a count of
independent rootkits.

## Useful commands

Check the loaded detector:

```bash
sudo python3 client.py status
```

Show all scan details:

```bash
sudo python3 client.py scan --verbose
```

Colour is automatic for terminals and disabled for redirected output. Use
`--color always` to force it or `--color never` to disable it. Automatic mode also
respects `NO_COLOR` and `TERM=dumb`; an explicit choice overrides them. JSON output
always stays plain.

```bash
sudo python3 client.py scan --color never
```

Check only processes:

```bash
sudo python3 client.py scan --checks processes
```

Save and view a report:

```bash
umask 077
sudo python3 client.py scan --format json > scan.json
python3 client.py show scan.json
```

Reports contain kernel addresses. Keep them private. Viewing a saved report does
not run a new scan.

## Troubleshooting

- **`/proc/lkmrkdet` is missing:** load the module with `sudo insmod ./lkmrkdet.ko`.
  If it is already loaded, access may be blocked; the client reports a failed scan.
- **`Invalid module format`:** rebuild with headers matching `uname -r`.
- **`Key was rejected by service`:** module signing is required. Use your system's
  approved signing process.
- **Checks return `ERROR` or `UNSUPPORTED`:** review the scan details and kernel
  messages with `sudo dmesg`.

## Tested rootkits

Results below are from the reviewed sample versions on Ubuntu 24.04,
kernel `6.8.0-146-generic`. A result applies to the tested configuration, not every
version of that rootkit.

| Sample | Controlled behaviour observed | `lkmrkdet` evidence | Important limitation |
| --- | --- | --- | --- |
| [Caraxes](https://github.com/ait-aecid/caraxes) | Process and filesystem enumeration hiding | Hidden-PID candidate; enumeration-handler and tracing findings | Module hiding disabled in tested configuration |
| [Diamorphine](https://github.com/m0nad/Diamorphine) | Module-list concealment; syscall-table changes | Module registration discrepancy; three table-pointer mismatches | File/process hiding not observed in tested environment |
| [Singularity](https://github.com/MatheuZSecurity/Singularity) | Process, filesystem, and TCP IPv4 reporting hiding | Hidden-PID candidate; network and enumeration-hook evidence | Module registration comparison missed the concealed module |

- **Hook evidence versus object discovery:** network and enumeration findings
  identify suspicious reporting paths, not independently discovered hidden
  connections or filenames. Controlled fixtures establish the hiding behaviour.
- **Module-check miss:** Singularity's module hiding was demonstrated, but the
  module registration comparison did not find it.
- **Unobserved behaviour:** Diamorphine's file/process hiding was not observed on
  this kernel, even though the sample implements it. Its table-pointer mismatches
  establish tampering, not successful live syscall interception.
- **Hiding confirmed:** known files or directories disappeared from listings
  while retained access proved their identity and contents. This confirms hiding
  behaviour, not a separately scored file/directory-object detection result.
  Caraxes hid the GID-selected directory in the dedicated test; its name- and
  UID-selected directories stayed visible. Diamorphine's directory stayed visible.
  Singularity hid the named directory from listings and blocked `chdir`, while
  direct open and retained access still worked. See the
  [dedicated directory results](docs/DIRECTORY_TESTS.md) for the measured cases.

Singularity removes both module registrations, which evades the module check;
its process and network findings still expose suspicious activity. Sample
revisions and evidence are recorded in [the validation ledger](docs/VALIDATION.md).
Each rootkit name links to its original project documentation.

## License

[GPL-2.0-only](LICENSE).
