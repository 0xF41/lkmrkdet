# STANDCON: the verified lkmrkdet demonstration

## Scope and pinned environment

- lkmrkdet **0.2.1**, Ubuntu x86-64 **6.8.0-146-generic**.
- Caraxes commit `899e8be6b5f6c7236bd23b52aa65051de757e0b3`.
- Default getdents64 ftrace hook; module unlinking disabled.
- Detector loaded **after** the rootkit in the controlled case.
- Baseline report `20261012T035617Z-57737c6b`.
- Positive case report `20261012T035617Z-controlled-817282a6`.

This is one pinned sample/configuration, not general rootkit-detection coverage.

## The result slide

### Hidden objects, inconsistent views

| Observation | Before | Caraxes active | After unload |
| --- | --- | --- | --- |
| Named marker in directory enumeration | Visible | Hidden | Visible |
| UID-owned file in directory enumeration | Visible | Hidden | Visible |
| Direct file access / retained file descriptors | Matching content | Matching content | Matching content |
| Test process in numeric `/proc` enumeration | Visible | Hidden | Visible |
| Process identity and continued existence | Confirmed | Confirmed | Confirmed |
| lkmrkdet | No anomaly | Hidden PID + entry CALL + ftrace candidate | No anomaly |

**Takeaway: hiding the listing did not remove the object or all references to it.**

## Two-minute explanation

1. **Establish the baseline.** Show all three files and the known process. Explain
   the ordinary control file is not meant to hide. Capture the object's identity,
   rather than assuming an absent PID is still the same process later.
2. **Show the lie.** The name/owner-selected files and child process disappear
   from enumeration. Direct file reads and process start identity remain intact.
3. **Load the detector afterward.** This case does not rely on an on-host clean
   pointer baseline being captured before the sample.
4. **Explain the discrepancy.** Kernel process-list observation contains the
   leader; both bracketing proc enumerations omit it; direct proc lookup agrees
   with its start identity. In this recorded run the PID is 27087, but future
   runs allocate a different PID.
5. **Explain attribution.** Entry-call sampling points into an allocated tracing
   trampoline. A separate tracefs observation reports a single IPMODIFY callback
   attributed to Caraxes. The allocated trampoline itself is not ordinary module
   text, which is why the original kernel owner field says unresolved.
6. **Show recovery.** Unload the sample, show restored visibility and the negative
   recovery scan. Candidate findings are not a claim that every hook is malicious.

## Replay actual reports without loading a module

From the project directory, or use absolute paths. Raw reports are not bundled;
use your retained report paths (the recorded lab paths below are examples):

```bash
python3 client.py show reports/20261012T035617Z-controlled-817282a6/before-scan.json
python3 client.py show reports/20261012T035617Z-controlled-817282a6/active-scan.json
python3 client.py show reports/20261012T035617Z-controlled-817282a6/restored-scan.json
```

The positive replay exits 1 because it contains suspicious findings. Do not chain
the recovery replay behind `&&` on that command. A replay is labelled recorded
evidence; it is not a fresh live scan.

## Repeat the controlled live case

This explicitly loads the existing sample and detector and owns its canary
objects; it attempts cleanup and records each stage:

```bash
sudo python3 scripts/validate_caraxes.py --detector-order after
```

Keep a recording/report replay available for presentation reliability. Retain the
snapshot/console recovery used for the lab; don't rely on SSH after a kernel fault.

## What the three findings mean

- **Process cross-view:** an object-specific inconsistency.
- **Entry CALL:** a code-site observation indicating changed execution.
- **Ftrace IPMODIFY:** registration evidence explaining a supported redirection
  mechanism and its reported callback owner.

They are corroborating signals for the same demonstration—not three independent
trust domains or three rootkits. An authorised livepatch may also use IPMODIFY.

## Claims supported by this test

> “On this Ubuntu 6.8 build, against this Caraxes revision, our detector loaded
> after the rootkit identified the demonstrated hidden process and reported
> corroborating entry-call and ftrace-registration evidence.”

Also supported: both target files were hidden but remained readable; the ordinary
control remained visible; unload restored visibility; no new kernel fault
diagnostic was observed in the captured intervals.

Not established here: inodeyou-cpp effectiveness (not run), module-unlinking
detection (disabled), hidden-socket detection, broader rootkit coverage or a
guarantee against a rootkit that subverts every observation path.

## False-positive example already in the baseline

The VM also reports an HID-BPF direct tracing registration with a symbolic
`ftrace_regs_caller` trampoline and `direct-->bpf_trampoline...` continuation.
It parses successfully and is not a selected-function rootkit finding. This
reinforces why “a branch or tracing trampoline exists” is not sufficient to
classify malicious behaviour.

## Closing line

**Kernel visibility is useful evidence. It is not independent trust.**

## Additional measured cases

| Case | Defensible presentation point |
| --- | --- |
| Diamorphine, kernel v0.2.1 | Module concealment and table mutation can be detected even when the altered table does not control live dispatch on a distro backport |
| Singularity, client v0.2.1 | Enumeration and direct lookup can both disappear; a missing stat lookup alone cannot distinguish hiding from exit |
| Singularity, client v0.3.0 | A later same-kernel birth-identity snapshot corroborates the hidden PID; network CALLs correlate to numeric IPMODIFY registrations |
| Remaining Singularity gap | Removing both module registrations evades that consistency rule, even while other checks detect evidence |

The verified v0.3.0 retry is `20261012T161114Z-controlled-2a2be8f7`; its negative
control and final recovery are `20261012T161114Z-74cbf01c` and
`20261012T161211Z-6970e68f`. Raw report files are local working artifacts, not
included in Git; use your own retained reports for replay.

Experiment exit 1 records the module-check miss. The complete positive client
scan also exits 1, with 26 candidate observations; these are not 26 rootkits.
Logs captured under the active sample lose earlier lines, illustrating why a
successful collection command is not proof of unmodified output.
