# Controlled Caraxes detection case

## Reviewed inputs

- Checkout: `../rootkits/caraxes`, or an explicit `--sample-dir`.
- Commit: `899e8be6b5f6c7236bd23b52aa65051de757e0b3`; no tracked changes at review.
- Module name: `caraxes`; built for `6.8.0-146-generic`.
- Default hook: `__x64_sys_getdents64` via ftrace IPMODIFY.
- Name filter: `caraxes`; owner filter: UID 1001 or GID 21.
- Optional `hide_module()` call remains commented out. This is not a module-list
  unlinking test and ordinary unloading must remain possible.

`--preflight` passed on the x86 VM. The runner records both current source hashes
and the `.ko` hash/srcversion; a Git revision alone is not proof of binary provenance.
No source modification or automatic build of the sample is performed by the test.

## Execute

From the built project directory on the VM after a fresh lab baseline:

```bash
sudo python3 scripts/validate_caraxes.py --detector-order after
```

The script owns its temporary directory, three files, retained descriptors and
child process. A filename canary is root-owned; a separate newly created file
is owned by numeric UID/GID 1001; an ordinary root-owned file is the untargeted
control. Only the disposable child is started with UID/GID 1001 and empty
supplementary groups. No account is created; no ownership of existing files is
changed. The managing SSH user is excluded from the configured UID selection.

The sequence is:

1. Check exact reviewed source/configuration and both module vermagic values.
2. Verify the sample/detector are not already visible in the module interfaces.
3. Create the three files and a ready-signalled child; record inode/device,
   content hash, PID, credentials and process start ticks.
4. Confirm all canaries are enumerable and directly accessible before loading
   the sample; load lkmrkdet and require a complete non-anomalous baseline scan.
5. For `after` order, unload lkmrkdet, load Caraxes, then reload lkmrkdet.
   For `before` order, retain the detector while loading Caraxes.
6. Observe the objects, run a full detector scan, then observe the objects again.
7. Unload Caraxes; require restored visibility and collect another detector scan.
8. In cleanup, unload only modules loaded by this script, terminate its child,
   close the file descriptors and unlink only the exact owned paths/directory.

If module unloading fails, the error is preserved and no forced unload is
attempted. Kernel crashes or corrupted cleanup need console/snapshot recovery.

## Evidence, not assumptions

Each targeted file is scored separately. File hiding is confirmed only when
BOTH active observations:
- omit the known filename from enumeration;
- resolve the same device/inode through direct open;
- read the expected contents through direct open AND the retained descriptor.

Process hiding is confirmed only when BOTH active observations:
- omit the known PID from numeric `/proc` enumeration;
- resolve the same direct `/proc/<pid>/stat` start time;
- find the owned child still alive.

For the process result, only a `SUSPICIOUS/missing_from_proc_enumeration` record
attributing the **specific canary PID** counts as a detection. An unrelated
alert does not count. Unavailable observations, PID reuse, exited processes or
incomplete scans are inconclusive rather than detections or confirmed misses.

The fixture and observer still rely on the guest kernel. These are controlled
lab corroborations, not independently trusted acquisition.

v0.2 also saves descriptor-based enumeration and the actual canary-directory
listings as diagnostics. The pathname-based result remains the scored view. At
least one targeted file must demonstrate hiding for the combined file case to
complete; name/owner results are preserved separately. The ordinary control must
remain present. A file not actually hidden is not counted as a detector miss.

## Expected interpretation

| Observation | Interpretation |
| --- | --- |
| Process hiding confirmed + exact PID finding | Process cross-view rule detected the demonstrated hiding |
| Process hiding confirmed + complete scan with no PID finding | Measured miss for this case |
| Sample loaded but hiding not observed | Feature not exercised; no detector score |
| File hiding confirmed | Valid file-enumeration demonstration; inodeyou-cpp not scored here |
| No module inconsistency | Expected when the sample leaves both registrations intact |
| Trampoline CALL candidate without attribution (v0.1) | Candidate evidence; tracefs separately corroborated the registration |
| ftrace IPMODIFY candidate (v0.2) | Client attribution from bracketing tracefs reads; authorisation still needs review |

The runner separately captures `enabled_functions` as corroborating evidence.
v0.2 full detector scans also request the client's ftrace check; an unavailable
endpoint or changing/unknown output makes that requested check incomplete.
Neither tool mounts tracefs, enables tracing or registers probes for collection.

## Report layout

Reports are written under `reports/<UTC timestamp>-controlled-<id>/` with
project-owner-only permissions:

- `environment.json`: boot ID, kernel, sample revision/configuration, source
  hashes and module identities.
- `canaries.json`: known object identities recorded before activation.
- `before-canaries.json`, `active-before-scan-canaries.json`,
  `active-after-scan-canaries.json`, `restored-canaries.json`.
- `before-scan.json`, `active-scan.json`, `restored-scan.json`.
- `*-tracing.json`: optional tracefs observations.
- Numbered command stdout/stderr, including kernel logs and module lifecycle.
- `result.json`: per-feature outcome, errors, exit codes and cleanup outcome.
- `boot-after.json`: final boot metadata.

Exit 0 is the process-hiding experiment's success, NOT a "clean system" result.
A positive client scan inside the experiment correctly returns 1.

## Current status

### v0.1 measured case

Report `20261011T162243Z-controlled-c87b6398`:

- Detector loaded after the sample.
- UID-owned process (PID 4849) hidden, alive and identity-stable: **DETECTED**.
- Root-owned filename canary stayed visible: **NOT_OBSERVED**, not a detector miss.
- Two alias observations flagged the same handler-entry CALL into a trampoline.
- Tracefs reported an IPMODIFY registration attributed to Caraxes.
- Recovery scan returned 0; visibility and cleanup succeeded; no new kernel
  fault diagnostic in the captured log delta.
- Overall exit 2 reflects the unexercised file case, not process-detection failure.

### v0.2 prepared regression

The updated runner separates file name/owner selection and adds a control.
The detector adds explicit tracefs attribution and samples each code address
only once. 43 Python tests and C decoder tests initially passed on the VM; the
warning-as-error kernel build also passed before the runtime regression below.

The v0.2 attempt aborted at its baseline because of the parser issue documented
in VALIDATION.md, and did not load Caraxes. The current bundle is v0.2.1 with
the parser/import fixes. Its privileged retry passed as recorded below.

Run the clean validation first, then the updated controlled case:

```bash
sudo python3 scripts/validate_vm.py --expect-clean
sudo python3 scripts/validate_caraxes.py --detector-order after
```

### v0.2.1 measured case

- Clean validation: `20261012T035617Z-57737c6b`, exit 0; standalone interface tests
  pass with no new kernel fault diagnostics.
- Controlled case: `20261012T035617Z-controlled-817282a6`, overall exit 0;
  detector order `after`.
- Filename and ownership file filters both **CONFIRMED**; direct contents/inodes
  preserved, while pathname and descriptor enumeration omit them.
- PID **27087** hidden, alive and identity-stable: **DETECTED**.
- Entry CALL candidate corroborated by a stable ftrace IPMODIFY registration,
  callback attributed to `fh_ftrace_thunk [caraxes]`.
- Untargeted control remains intact. All visibility returns on unload; restored
  scan exit 0; cleanup succeeds; no new kernel fault diagnostic in the log delta.
- The active detector exit 1 is the expected positive evidence result, not an
  execution failure. Filesystem-content detection is not scored by this runner.

See `DEMO.md` for a concise presentation sequence and claims supported by this case.
