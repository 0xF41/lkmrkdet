# Reboot-isolated Diamorphine and Singularity cases

## Status and inputs

All 80 Python tests and the C decoder tests pass on the Ubuntu VM, including the
benign detached-canary IPC/pidfd test. Both read-only sample preflights pass.
The measured Diamorphine case detects module concealment and three changed table
pointers; file/process hiding was not observed. The initial Singularity case
reports confirmed file/PID/TCP hiding and network findings, a module-check miss and
incomplete process attribution. Full reports have been retrieved after reboot.
The client v0.3.0 retry detects the lookup-hidden PID and correlates network CALLs;
both negative controls and final reboot/interface recovery pass. The remaining
module-check miss is preserved. See `VALIDATION.md` for versioned evidence.

| Sample | Reviewed commit | Existing module srcversion |
| --- | --- | --- |
| Diamorphine | `af494fad213654aae16cfdbbb50e7dc26383e4b2` | `A8B106EC4891F0AD6B303D8` |
| Singularity | `87875157c4dda767709eb2538708510b8bf7ef00` | `3384DF5F5A53B3FAD34214D` |

The inventoried binaries match Ubuntu x86-64 `6.8.0-146-generic` vermagic.
Preflight rejects changed tracked sample source or mismatched vermagic, records
source hashes and the binary hash/srcversion, and checks visible sample/detector
state. Matching build metadata does not establish functional hiding or binary
provenance from that source revision. No sample is rebuilt or modified here.

### Compatibility and expected coverage

- Diamorphine selects syscall-table replacement on this 6.8 build. The matching
  Ubuntu headers describe that table as tracing metadata. A changed table can be
  detected even when the live dispatcher never calls those pointers. Name/PID
  hiding must be observed before scoring those behaviours.
- Singularity uses ftrace hooks, conceals both module registrations after five
  seconds, and clears module name/symbol information. Removing both views can
  evade registry cross-view detection. Its inspection/output hooks can subvert
  memory reads, direct proc lookup, tracefs and logs.
- Only TCP IPv4 reporting for the owned target listener is behaviourally scored;
  UDP, IPv6, packet capture, sock_diag, remote-shell and persistence behaviour are
  not exercised. `inodeyou-cpp` is separate and is not scored by this runner.

## Run one sample per boot

Use the VM console to establish a fresh lab snapshot/boot. Keep console access
for reboot recovery and preserve reports before reverting a snapshot.

Read-only checks, from the built project:

```bash
python3 scripts/validate_samples.py diamorphine --preflight
python3 scripts/validate_samples.py singularity --preflight
```

First case:

```bash
sudo python3 scripts/validate_samples.py diamorphine --detector-order after
```

Read `result.json`, detector JSON, canary observations and kernel-log delta from
the printed report directory. Then reboot:

```bash
sudo reboot
```

After reconnecting, `validate_vm.py --expect-clean` can record the recovery boot
and exercise the detector interface. The new boot ID must differ from the sample
report/marker. A negative scan remains scoped evidence, not kernel attestation.

Second case, on the recovered boot:

```bash
sudo python3 scripts/validate_samples.py singularity --detector-order after
```

Preserve this case's reports and reboot again before recovery validation or
another sample. `--sample-dir /path/to/checkout` supports an explicit checkout
location. `--detector-order before` retains the detector through sample loading;
each order requires its own fresh boot and report.

## What the runner does

1. Pin reviewed source/configuration and record boot, source and module identities.
2. Create targeted/control files, retaining descriptors, inode identity and
   payload. Start a bounded disposable child and retain a pidfd before loading.
3. Require visible, identity-stable, active baseline canaries and a complete
   non-anomalous full detector scan. TCP target/control listeners must also be
   present and exchange the expected payload before a Singularity load.
4. For `after`, unload the detector. Write/fsync the pending-reboot marker before
   attempting `insmod`; a failed sample initialization still requires reboot.
5. Load only the existing sample binary, wait for its concealment delay, and
   reload the detector for `after`. Record any detector-load/collection failure.
6. Activate process hiding from the disposable child only, observe canaries,
   collect a full scan, then observe the canaries again.
7. Terminate the owned child through the retained pidfd, close sockets/descriptors,
   remove exact owned fixtures, and attempt to unload only the detector.

**The sample remains loaded.** Ordinary or forced sample removal is not attempted.
No installation script, automatic persistence or remote-shell trigger is used.

## Canary identity and controls

The process is forked, detached, adopted by PID 1 and given a bounded lifetime of
120 seconds. If adoption is not confirmed, the case stops before sample loading.
Pipe messages carry an unguessable per-worker token and PID. A retained pidfd and
heartbeat IPC corroborate liveness even when direct `/proc/<pid>/stat` is hidden.

Diamorphine's signal 31 targets the child itself. Singularity's signal 59 can
hide a caller's parent lineage, so activation occurs only after PID-1 adoption.
This disposable child already runs as root; the test does not attempt privilege
escalation from an unprivileged account. The signal is blocked in the child so
an inactive hook does not kill the canary. An `activated` event alone does not
prove that the hook intercepted it: actual hiding is scored independently.

File invisibility is corroborated using unchanged content/inode from held
descriptors. Direct-open success/failure is recorded separately. The untargeted
file must remain visible, directly accessible and identity/content-stable.

Singularity listeners bind to `127.0.0.2`: the target uses port 8081 and the
control an ephemeral port. This avoids the sample's address filter for
`127.0.0.1`. Socket inode, held descriptor and owned loopback round-trip activity
are compared with `/proc/net/tcp`; the control must remain visible and active.
The exchange carries only a generated canary payload.

## Per-feature interpretation

| Classification | Meaning |
| --- | --- |
| `CONFIRMED` | Both active observations omit a corroborated live/identity-stable object |
| `NOT_OBSERVED` | Both observations retain the object; hiding not exercised |
| `DETECTED` | Matching check finding for the demonstrated feature/canary |
| `NO_MATCHING_FINDING` | Feature demonstrated, check collected, matching finding absent |
| `NOT_EXERCISED` | No demonstrated hiding to score for that feature |
| `INCOMPLETE` / `INCONCLUSIVE` | Collection, identity, activity or control evidence insufficient |
| `NOT_TESTED` | Outside this case's behavioural scope |

Only the exact canary PID's `missing_from_proc_enumeration` finding counts for
process detection. In v0.2.1, missing direct proc identity remains incomplete,
even if the runner's retained IPC corroborates that the canary exists. Client
v0.3.0 instead attempts later kernel birth-identity revalidation; failed
confirmation still remains incomplete. The runner
does not inject its canary oracle into detector results. Module and network
findings are scored separately; ftrace candidates and overall candidate presence
are retained without calling them proof of module-registry detection.

Runner exit bits: **0** observations completed; **1** a scored feature has no
matching finding; **2** incomplete/inconclusive case or cleanup failure; **3**
both. A feature marked `NOT_EXERCISED`/`NOT_TESTED` is never a coverage pass.
Client scan exits retain their own suspicious/incomplete bit semantics.

## Reports and recovery marker

`reports/<UTC>-controlled-<id>/` contains `environment.json`, `canaries.json`,
baseline/active observations, parsed scans or collection errors, raw tracefs,
numbered command stdout/stderr, kernel logs, `boot-after.json` and `result.json`.
Permissions are restricted to the project owner. Reports and binaries are working
artifacts and are excluded from the source repository.

`reports/pending-sample-reboot.json` records the boot ID, sample and report path.
The sample/Caraxes runners and clean validation reject that same boot. A different
boot ID permits a new run; do not delete/edit the marker to bypass recovery.
The marker is procedural state, not a tamper-proof measurement.

All observations still depend on the guest kernel. IPC and held descriptors
corroborate owned canaries; they do not attest the integrity of the whole kernel.

## Measured Diamorphine case

Report `20261012T145006Z-controlled-63239bf3`, detector loaded **after** the sample:

- Fresh boot ID `6664402e-5aa4-4bad-ab34-5c8bc5c80448`, kernel taint 0 before
  loading, matching `6.8.0-146-generic` binaries and reviewed sample revision.
- Baseline scan: 28 OK, 4 INFO, no suspicious/error/unsupported records; exit 0.
- Both active observations omit Diamorphine from the module list while retaining
  its direct sysfs path. The detector reports
  `modules / diamorphine / live_kobject_missing_module`: **DETECTED**.
- Three `unexpected_handler` records identify changed `getdents64`, `kill` and
  `getdents` table entries, attributed to `diamorphine (unlisted)`. Native handlers
  remain unchanged. The table is tracing metadata on this backported dispatcher;
  these findings do not establish live syscall interception.
- Filename canary and PID 2397 remain visible in both active observations, with
  stable held/direct identities, contents and IPC liveness. File/process hiding
  is **NOT_OBSERVED** and process detection **NOT_EXERCISED**, not a measured miss.
- Active scan: 24 OK, 4 INFO, 4 SUSPICIOUS, no errors/unsupported/truncation;
  client exit 1. Selected ftrace registrations are absent in both bracketing
  reads; no ftrace candidate is reported.
- Untargeted control remains intact; detector unload and fixture cleanup succeed.
  Experiment exit 0 means the scored observations completed, not that every
  hiding feature passed. The sample remains loaded and reboot is required.
- Kernel-log delta contains only expected out-of-tree/unsigned module notices
  and detector ready/unloaded messages. No new kernel fault diagnostic observed.

The reports have been retrieved to the restricted local working-report directory.
Diamorphine recovery was subsequently verified successful from the retrieved
`20261012T151344Z-fedef34f` report, including interface tests and the log delta.
Raw reports remain excluded from Git.

## Initial Singularity case and follow-up

The user's completed runner output for `20261012T151345Z-controlled-dbda24a9`
reports file/PID/TCP hiding **CONFIRMED**, controls intact, network callback
detection **DETECTED**, module detection **NO_MATCHING_FINDING**, process detection
**INCOMPLETE**, and experiment/client exits 3. Both module registrations disappear;
this is a known limit of the current two-registry comparison.

An SSH rendering of the saved active scan reports 26 OK, 25 SUSPICIOUS and 5 INFO,
with no ERROR/UNSUPPORTED records but a lifecycle-inconclusive PID **2415**. Four
network and six native-syscall entry CALL candidates accompany fifteen selected
IPMODIFY registrations. Cleared module symbols leave numeric callback addresses;
these must not be relabelled with a guessed module owner.

Live rsync transfer of these reports fails with an all-space protocol tag
(`0x20202020`), on both combined and single-directory attempts. The reviewed sample
filters writes to pipes/log output; transport interference is plausible. The same
transfer succeeds after reboot, and the saved artifacts are now local. Comparing
the log captures shows earlier signing/taint lines and an audit line disappearing
from the later output. An exit-0 log command under this sample is not assurance of
an unfiltered log.

Client v0.3.0 adds identity-matched post-lookup kernel revalidation and network
trampoline correlation. Local checks and all 80 native VM Python tests plus C
decoder tests pass; clean runtime, controlled positive retry and final recovery
subsequently pass for the scoped checks as recorded below.
It does not claim to fix doubly-unlinked
module discovery or introduce an independently trusted kernel reference.

The first recovered VM boot is `6ca5e215-9032-4912-985b-b10f71ceb338`, different from
the initial sample boot. The subsequent negative control confirms recovery.

## Verified client v0.3.0 retry

- Baseline `20261012T161114Z-74cbf01c`: full scan and interface tests exit 0,
  28 OK / 4 INFO, no suspicious or incomplete records.
- Controlled case `20261012T161114Z-controlled-2a2be8f7`: file/PID/TCP hiding
  confirmed, controls intact, hidden PID **3388** **DETECTED** using
  `identity_source=kernel_task_revalidation` and matching later birth identity.
- All four proc-network entry CALLs correlate to stable numeric IPMODIFY
  trampolines. The original owner remains unresolved; no module name is guessed.
- Active scan: 26 OK / 26 SUSPICIOUS / 4 INFO, complete collection; client exit 1.
  Module detection remains **NO_MATCHING_FINDING** after both registrations are
  removed, so experiment exit 1 honestly preserves that coverage miss.
- Detector unload and fixture cleanup succeed. Following reboot, recovery
  `20261012T161211Z-6970e68f` on boot `b49115f3-457d-4489-97ba-9df7ef923c1f`
  passes full negative scan, interface tests and unload. The negative-control log
  delta contains only expected signing/taint and detector lifecycle messages.
- Saved artifacts are retrieved locally and excluded from the source repository.
