# Dedicated directory-hiding experiments

## Current status

`scripts/validate_directories.py` is prepared for the existing reviewed Caraxes,
Diamorphine and Singularity samples. The Caraxes GID-selected directory case is
verified; its name/UID directory hiding was not observed. Diamorphine's directory
hiding was not observed on this kernel. Singularity's named directory hiding and
matching enumeration-hook evidence are verified, with clean reboot recovery.
Final local checks pass: 120 Python tests (one Linux-only skip on macOS)
and C decoder tests; all 120 Python tests and C decoder tests also pass on the VM.
Read-only preflights pass for all three reviewed samples. Harmless fixture tests create directories without loading
any module; these are not measured rootkit-hiding results.

This case measures **directory enumeration hiding and access behaviour**, plus
the detector's matching enumeration-hook evidence. It does not turn the canary
oracle into production directory-object detection.

## Fixtures

All fixtures live in a newly created private temporary parent. The runner retains
the parent descriptor, each directory descriptor and a descriptor for an ordinary
`marker.txt` child. Baseline records contain device/inode, ownership and marker
payload hash. The paths, contents and owners are otherwise kept constant.

| Sample | Target directories | Untargeted control |
| --- | --- | --- |
| Caraxes | Name containing the magic word; UID-only selected directory; GID-only selected directory | Ordinary directory with neither selected ownership nor magic name |
| Diamorphine | Name beginning with `diamorphine_secret` | Ordinary directory |
| Singularity | Name containing `singularity` | Ordinary directory |

Caraxes ownership changes apply only to the newly owned fixtures. No accounts or
existing filesystem ownership are changed. Directory tests do not send process
hiding/root signals, open network listeners or execute sample installation scripts.

## Observations

Before activation and on both sides of the detector scan, collect:

1. Parent enumeration by pathname and by the descriptor retained before loading.
2. Held directory and marker descriptor type/device/inode identity and payload.
3. Marker enumeration and relative open through the held directory descriptor.
4. Direct pathname directory open and identity, including error/errno on denial.
5. `chdir` in a short-lived disposable child, with identity/errno. The manager's
   cwd is never changed, and the child does not print sensitive pathnames.

Directory hiding is **CONFIRMED** only if both parent enumeration views omit the
target in both active observations while its retained directory/marker identities
and content remain stable. Direct-open/chdir denial is recorded as access hiding,
not destruction of a corroborated held object. Missing listings or changed held
identity/content are inconclusive. The ordinary control must remain enumerable,
directly accessible, identity-stable and readable.

The name, UID and GID fixtures are scored individually. A feature remaining
visible is **NOT_OBSERVED**, not a measured detector miss.

## Detector interpretation

`enumeration_hook_evidence` accepts only suspicious native getdents/getdents64
handler/table findings or native ftrace registrations for those functions. An
unrelated network/module alert does not count for this field.

- Confirmed hiding + matching finding: **DETECTED** enumeration-hook evidence.
- Confirmed hiding + complete relevant scan without a match: **NO_MATCHING_FINDING**.
- No demonstrated hiding: **NOT_EXERCISED**.
- Failed collection/controls/identity: **INCOMPLETE** or **INCONCLUSIVE**.

`object_level_directory_detection` explicitly remains **NOT_IMPLEMENTED**. The
normal detector does not compare these arbitrary directory objects with an
independent filesystem inventory. Held descriptors corroborate the experiment's
canaries; they are not supplied to the production detector's decision rules.

## Run one sample per boot

Read-only checks from the built VM project:

```bash
python3 scripts/validate_directories.py caraxes --preflight
python3 scripts/validate_directories.py diamorphine --preflight
python3 scripts/validate_directories.py singularity --preflight
```

On a fresh VM boot, run the first case:

```bash
sudo python3 scripts/validate_directories.py caraxes --detector-order after
```

Caraxes is unloaded normally, and the runner verifies restored directory
visibility/access and a negative recovery scan. Reports must be preserved before
snapshot rollback. Reboot before the next sample, even after successful Caraxes
unloading, to keep sample exposure separate:

```bash
sudo reboot
```

On subsequent separate boots:

```bash
sudo python3 scripts/validate_directories.py diamorphine --detector-order after
```

```bash
sudo python3 scripts/validate_directories.py singularity --detector-order after
```

Diamorphine/Singularity are left loaded for reboot recovery. Reboot after each
case; run `validate_vm.py --expect-clean` on the recovered boot. `--sample-dir`
supports explicit checkout paths. `--detector-order before` retains the detector
through activation and requires its own fresh-boot case.

Each attempted sample load writes the pending-reboot marker before `insmod`,
including Caraxes and failed initialization. Same-boot subsequent tests are
refused. This procedural marker is not an independently trusted measurement.

## Cleanup and reports

Cleanup unloads only owned modules that can be ordinarily removed, unlinks only
the owned marker names, removes only the exact owned directories, and closes all
retained descriptors. It never deletes directories recursively. Unexpected
contents and cleanup errors are preserved rather than silently removed.
If a cleanup attempt has already closed an owned descriptor, a retry defers the
relative deletion instead of falling back to the manager's working directory.

Reports under `reports/<UTC>-controlled-<id>/` include:

- `environment.json`: reviewed source/module hashes, boot and directory selection.
- `directory-identities.json`: original object identities and marker hash.
- `before-directories.json`, `active-before-scan-directories.json`,
  `active-after-scan-directories.json`; also `restored-directories.json` for Caraxes.
- Baseline/active/recovery detector JSON or explicit collection errors.
- Raw tracefs, command stdout/stderr, kernel logs, boot-after and `result.json`.

Exit bits: **0** observed directory hiding and matching enumeration-hook evidence;
**1** confirmed hiding without a matching hook finding; **2** incomplete or
unexercised case/failed recovery; **3** both. A successful feature observation is
not a whole-kernel integrity claim. Sample output and logs can still be filtered;
after Singularity, report transport may require reboot before retrieval.

## Verified Caraxes directory case

Report `20261013T040600Z-controlled-1e5acc5a`, detector order **after**:

- Fresh boot `f930f014-67d1-427e-8cbc-21ddbc477baf`, initial taint 0, unchanged
  reviewed source and matching `6.8.0-146-generic` module binaries.
- Ownership identities verified before activation: name/control directories
  UID/GID 0/0; UID fixture 1001/0; GID fixture 0/21.
- Both parent pathname and retained-FD listings omit the GID-selected directory
  in both active observations. Its directory/marker identities and contents stay
  stable. Direct open and child chdir succeed: **CONFIRMED** enumeration hiding.
- Name- and UID-selected directories remain in both parent views:
  **NOT_OBSERVED**, not detector misses. Their identities and direct access remain
  intact. The marker entry inside UID/GID fixtures is omitted from held-directory
  enumeration but remains readable through held/relative descriptors. This
  additional observation is recorded without attributing an unverified cause.
- Matching `handler:getdents64` CALL and `__x64_sys_getdents64` IPMODIFY evidence
  correlate to one trampoline and `fh_ftrace_thunk [caraxes]`, flags RIM.
  Enumeration-hook evidence **DETECTED**; no directory-object finding is claimed.
- Active scan: 27 OK, 2 SUSPICIOUS, 4 INFO, no errors/unsupported/truncation;
  exit 1. Baseline/recovery: 28 OK, 4 INFO, no suspicious/incomplete records; exit 0.
- All directory and marker enumeration/access returns after ordinary sample
  unload. Control intact, cleanup errors empty, experiment exit 0. Reboot is still
  required before the next sample to maintain separate boot exposure.
- Exact log delta contains signing/taint notices, detector lifecycle and the
  sample hook-installation message only; no new kernel fault diagnostic observed.
- Reports retrieved locally with restricted permissions. Marker-enumeration
  repeatability and control-marker visibility are additionally regression-tested;
  the updated native suite still passes all 119 tests.

## Verified Diamorphine directory case

Report `20261013T042409Z-controlled-cc6ae964`, detector order **after**:

- Fresh boot `e15dd3e2-d8b7-4718-894d-3173bdf67b5c`, initial taint 0, unchanged
  reviewed source and matching detector/sample binary identities.
- `diamorphine_secret_directory` remains in both parent pathname/held-FD
  listings before and after the active scan. Directory/marker identity and
  content remain stable, and direct open, relative reads and child chdir succeed.
  The ordinary control has the same complete observations.
- Directory hiding **NOT_OBSERVED**; enumeration-hook behaviour **NOT_EXERCISED**.
  Two changed enumeration table pointers remain recorded as candidates, but they
  do not establish live hiding on this metadata-only dispatcher backport.
- Full active detector scan: 24 OK, 4 SUSPICIOUS, 4 INFO, no failed/unsupported
  observations; exit 1. It detects module-list/kobject inconsistency plus changed
  getdents/getdents64/kill table pointers attributed to the unlisted sample.
- Experiment exit 2 represents an unexercised directory behaviour, not a failed
  client scan or confirmed directory-detection miss. Cleanup succeeds; sample is
  left loaded and reboot remains required.
- Log delta contains expected signing/taint and detector lifecycle messages plus
  an unrelated firewall line; no new kernel fault diagnostic observed.
- Saved report retrieved locally with restricted permissions. Subsequent recovery
  and the Singularity directory case are recorded below.

## Verified Singularity directory case and recovery

- Pre-case recovery `20261013T043003Z-50a90b4f` runs on fresh boot
  `9b6e5c1d-ef5e-4de5-95e7-a4a259fd2620`, initial taint 0. All load/status/scan/
  interface/unload commands exit 0; scan 28 OK / 4 INFO, complete.
- Directory case `20261013T043003Z-controlled-797c0148` uses the unchanged reviewed
  sample and detector binaries, client v0.3.1, detector order **after**.
- Named target directory device/inode **2050/378**, marker **2050/379**, is omitted
  from both parent pathname and retained-FD listings in both active observations.
  Held directory/marker identities and contents remain stable: hiding **CONFIRMED**.
- Direct pathname open still succeeds with the same identity. Relative marker
  listing/read via the held directory also succeeds. The disposable child chdir
  probe fails with **ENOENT (2)** both times. This is recorded access behaviour;
  pathname open success and chdir failure are not conflated.
- Ordinary control directory **2050/380**, marker **2050/381**, remains listed,
  readable, identity-stable and accessible, including chdir.
- Native getdents/getdents64 entry CALLs and their two selected IPMODIFY rows
  correlate to numeric callback `0xffffffffc0c4c8b0`, flags RIM. Enumeration-hook
  evidence **DETECTED**; callback module name stays unattributed.
- Full active scan: 27 OK / 25 SUSPICIOUS / 4 INFO, complete, no errors/unsupported,
  exit 1. Experiment exit 0 describes observed hiding and matching hook evidence;
  it does not grade unrelated module-check limits or claim directory-object detection.
- Fixture and detector cleanup succeeds, errors empty. The sample remains loaded
  until reboot. Captured after-log omits old audit and signing/taint lines; no
  unfiltered no-fault claim is made for the active-sample interval.
- Final recovery `20261013T043051Z-5e30d678` uses new boot
  `000fdb32-8bb3-4acb-8cce-7273da234771`, initial taint 0. All commands and interface
  tests pass, scan 28 OK / 4 INFO, complete; detector unloaded. Both negative-control
  log deltas contain expected signing/taint and lifecycle lines only, with no new
  kernel fault diagnostic observed.
- All three directories of saved evidence are retrieved after reboot. Raw reports
  remain local working artifacts excluded from Git.

## Directory results summary

| Sample | Parent-directory hiding | Direct access | Enumeration-hook evidence | Recovery |
| --- | --- | --- | --- | --- |
| Caraxes | GID-selected confirmed; name/UID not observed | Open/chdir/held marker work | Detected, attributed to Caraxes | Restored on unload; clean scan |
| Diamorphine | Not observed on this backported dispatcher | All access and listings work | Unexercised for behaviour; altered table candidates retained | Clean validation after reboot |
| Singularity | Named directory confirmed | Direct open/held marker work; chdir ENOENT | Detected, numeric callback preserved | Clean validation after reboot |

These are measured configuration-specific results. The directory-specific oracle
belongs to the controlled experiment, not the production detector.
