# safely-run-repo

A host-side toolkit for cloning and running **any untrusted repository** inside
a disposable VirtualBox VM, then throwing the VM away. Language-agnostic: web
apps (Laravel/PHP, Node) and crypto/Web3 repos (Rust/Foundry/Hardhat/Solana/
Python) alike.

The model is simple:

> **Clone executes nothing. Install executes everything. So we run installs and
> the app inside a throwaway VM, as a non-sudo user, and restore a clean
> snapshot after every run.**

---

## Hard caveats — read these first

- **A scan FLAGS; it does not CLEAR.** `scan.sh` raises leads for a human to
  review. A clean run does **not** prove a repo is safe — novel or well-hidden
  malware passes static scanners every day. The VM is the real protection.
- **The VM is the real boundary.** Treat every flag as "look here," then rely on
  isolation + the clean snapshot, not on the scanner's verdict.
- **A VM is strong isolation, not absolute.** Hypervisor escape bugs exist. That
  is exactly why we disable clipboard, drag-and-drop, and shared folders, keep
  NAT-only networking, and restore a clean snapshot every single run — so a
  compromise has nothing to grab and nowhere to persist.
- **Crypto risk = key theft.** The headline danger in Web3 repos is exfiltration
  of private keys / seed phrases / keystores. **Keep all real keys, wallets, and
  seed phrases OUT of the VM. Testnet and throwaway keys only.**
- **Never run untrusted code as root.** Everything runs as the non-sudo `runner`
  user. If the repo asks for `sudo`, that is a finding, not an instruction.

---

## What's in the box

| File | Runs on | Purpose |
|------|---------|---------|
| `lib/config.sh`    | host | Shared config (VM name, port, snapshot, runner) + guard helpers. Sourced by the `vm-*` scripts. |
| `vm-harden.sh`     | host | Idempotently lock down the VM (no clipboard/dnd/shares, NAT + SSH forward, fixed RAM/CPU, audio/USB off). |
| `snapshot-base.sh` | host | Capture the `clean-base` snapshot (refuses to clobber without `--force`). |
| `vm-up.sh`         | host | Restore `clean-base`, boot headless, wait for SSH, drop you into the VM as `runner`. |
| `vm-down.sh`       | host | Power off + restore `clean-base` (wipes the run). `--destroy` deletes the VM entirely. |
| `scan.sh`          | VM or host | Language-agnostic static scanner. Read-only; self-skips missing tools. |
| `run-order.md`     | — | The safe operator sequence (clone → scan → read hooks → disarmed install → re-scan → run → wipe). |
| `rules/`           | — | Drop optional YARA `*.yar` rules here; `scan.sh` picks them up. |

All host scripts read VM state **before** any state-changing `VBoxManage` call,
print actionable errors, and centralize every magic literal in `lib/config.sh`
(override any value via the environment, e.g. `VM_NAME=other ./vm-up.sh`).

---

## One-time setup

```bash
# 1. Harden the existing 'ubuntu-vm' (powers it off first; idempotent).
./vm-harden.sh

# 2. Follow the printed NEXT STEPS: boot the VM once, install openssh-server,
#    create the non-sudo 'runner' user. (vm-harden.sh prints exact commands.)

# 3. Capture the clean baseline every run restores to.
./snapshot-base.sh
```

Defaults (change in `lib/config.sh` or via env):
`VM_NAME=ubuntu-vm`, SSH `127.0.0.1:2222 → guest:22`, snapshot `clean-base`,
user `runner`, `4096 MB` RAM, `2` CPUs.

---

## Quickstart — vet one repo

```bash
./vm-up.sh                                   # HOST: clean VM, ssh in as runner
# (host, 2nd terminal) copy the scanner in if not baked into the snapshot:
#   scp -P 2222 scan.sh runner@127.0.0.1:/home/runner/

# --- inside the VM ---
git clone https://github.com/wwwidr/hiring-challenge.git   # executes nothing
cd hiring-challenge
~/scan.sh .                                  # scan BEFORE install
#   ...read /tmp/malware-scan-*.log and composer.json scripts by hand...
composer install --no-scripts --no-plugins   # install with hooks disarmed
~/scan.sh .                                  # scan AGAIN (deps now on disk)
cp .env.example .env && php artisan key:generate && php artisan migrate
php artisan test                             # only now run it
exit

./vm-down.sh                                 # HOST: power off + wipe the run
```

The full, stack-by-stack sequence (Node/Rust/Python/Web3 install flags
included) lives in **[run-order.md](run-order.md)**.

### First target

`https://github.com/wwwidr/hiring-challenge` — a Laravel/PHP "Respaid Senior
Engineer" hiring challenge. Treat as untrusted: the live danger is
`composer install` running arbitrary lifecycle scripts, a known
"Contagious Interview" social-engineering pattern. Hence: scan first,
`--no-scripts --no-plugins`, scan again, run inside the VM only.

---

## scan.sh details

```bash
./scan.sh [TARGET_DIR]      # default: $PWD
# exit 0 = clean   1 = findings   2 = bad config / unusable target
# report: /tmp/malware-scan-<timestamp>.log
```

Steps (each self-skips if its tool is absent): ClamAV signatures · optional YARA
rules · Trivy fs (vuln/secret/misconfig, HIGH+CRITICAL) · Semgrep `--config=auto`
· IoC greps (obfuscation, reverse shells, C2/exfil endpoints, long base64) ·
committed-binary discovery · Shannon entropy on binaries · git-history forensics
· npm + Composer + Python + Rust install-hook audits · PHP dangerous sinks ·
Web3 key-theft indicators · dependency-confusion/typosquat fuzzy matching.

It **only reads** files and git history. It never installs or runs repo code,
and it presence-checks secret files without printing their contents.
