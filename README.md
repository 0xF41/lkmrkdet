# lkmrkdet

A Linux kernel rootkit detection tool that helps spot hidden processes and
suspicious changes in the kernel. It uses a kernel module and a Python
command-line client.

Developed for **When Linux Lies — STANDCON**. Tested on Ubuntu 24.04,
x86-64, kernel `6.8.0-146-generic`.

This is an experimental tool. Start with a test VM. A suspicious result needs
investigation; a scan with no findings does not guarantee a clean system.

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

## Useful commands

Check the loaded detector:

```bash
sudo python3 client.py status
```

Show all scan details:

```bash
sudo python3 client.py scan --verbose
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

## License

[GPL-2.0-only](LICENSE).
