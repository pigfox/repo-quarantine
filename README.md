# repo-quarantine

A **Pigfox** tool — `github.com/pigfox/repo-quarantine`.

A tiny host-side toolkit for cloning and running an **untrusted repository**
inside a disposable VirtualBox VM, then throwing the VM away. Language-agnostic:
web apps (Laravel/PHP, Node) and crypto/Web3 repos (Rust/Foundry/Hardhat/Solana/
Python) alike.

> **What is published is the *repo* — these scripts plus this README — never a
> VM image.** The advertised artifact is the tooling that *builds* a clean
> baseline; the baseline itself stays on your machine. The repo ships **zero
> keys**: you generate your own and the scripts install *your* public keys.

> **Read the threat model below before you trust this with anything.**
> Quarantine here means **one specific** protection — a disposable
> host-filesystem boundary — and nothing more. Knowing exactly where that
> boundary stops is the whole point.

---

## Threat model — the one guarantee, and the limitations

**The single guarantee:** it isolates the **host filesystem** and gives you
**disposable rollback**. Untrusted code runs inside a throwaway VM as a non-sudo
user, and a clean snapshot is restored after every run. Whatever the repo
writes, installs, or breaks lives and dies inside the VM. That is the entire
guarantee — do not read more into it.

Everything below is a **known limitation**, stated plainly so you don't mistake
it for something the tool defends:

- **The network is NOT isolated.** The control channel (SSH) rides nic1 in NAT
  mode, and NAT gives the guest **full outbound internet**. Untrusted code can
  exfiltrate anything it can read, call home to a C2, or mine. **Snapshot
  rollback wipes the disk; it cannot un-send a packet.** We do not pretend to
  contain this — isolating the network would mean cutting the control channel,
  and an in-guest egress firewall only marginally improves an inherently leaky
  property. Treat the VM as fully networked.
- **Never bring real secrets in.** Because the network is open, assume anything
  inside the VM can leave it. **Never put real private keys, seed phrases,
  keystores, mainnet wallets, SSH keys, API tokens, or passwords inside the
  VM.** For crypto/Web3, use **testnet and throwaway keys only** — a rollback
  cannot undo a key that already left over the wire.
- **It does NOT make a repo "trustworthy."** A clean run proves *nothing* about
  the code — only that this run didn't escape the box's *filesystem*. The VM is
  the boundary, not a verdict. Never carry "it ran fine in the VM" over to
  running it on your host.
- **It does NOT defend against VM-escape bugs.** Hypervisor escapes are rare but
  real. That is why clipboard, drag-and-drop, and shared folders stay
  **disabled** (`vm-harden.sh` turns them off) — fewer escape/leak channels —
  and why you restore `clean-base` after every run so a compromise has nothing
  to persist into.
- **Untrusted code runs as the non-sudo `runner` user, never root.** If a repo
  demands `sudo`, that is a finding to investigate, not an instruction to follow.

In short: **the VM is a *filesystem* boundary with disposable rollback.** Secret
hygiene is your responsibility (bring none); network containment is not provided;
judging the code is your responsibility (the tool never does).

> A per-run egress firewall inside the guest is a possible **v2**. It is
> deliberately out of scope today: it widens `runner`'s footprint, reintroduces
> stateful in-guest config to drift, and only marginally hardens a property
> rollback already cannot make whole.

---

## What's in the box

| File | Runs on | Purpose |
| --- | --- | --- |
| `lib/config.sh` | host | Shared config (VM name, snapshot, the `runner`/`admin` accounts + their keys, SSH NAT port-forward) + guard helpers. Sourced by both scripts. |
| `vm-harden.sh` | host | One-time: idempotently lock the VM down — no clipboard/drag-drop/shares, nic1 NAT + a single host->guest SSH port-forward, fixed RAM/CPU, audio/USB off. |
| `vm-cycle.sh` | host | Every run: restore `clean-base`, boot headless, wait for SSH, drop you into the VM as `runner` (key auth); on exit/Ctrl-C, power off and roll back. `--snapshot` captures the baseline. |

Both host scripts read VM state **before** any state-changing `VBoxManage` call,
print actionable errors, and centralize every magic literal in `lib/config.sh`
(override any value via the environment, e.g. `VM_NAME=other ./vm-cycle.sh`).

Defaults: `VM_NAME=ubuntu-vm`, SSH `127.0.0.1:2222 -> guest:22`, snapshot
`clean-base`, `4096 MB` RAM, `2` CPUs, and two guest accounts —
`runner` (non-sudo, key `~/.ssh/vm_runner`) for untrusted code, and
`admin` (passwordless sudo, key `~/.ssh/vm_admin`) for provisioning only.

---

## Accounts, keys, and what gets published — by design

Three choices below are deliberate. They are design, not oversight:

- **The published artifact is the *scripts*, not a VM image.** This repo ships
  the tooling that *builds* a `clean-base` baseline on your machine; it never
  ships the baseline. So your local snapshot may contain *your* public keys
  (harmless — it stays local), while the **repo itself contains no keys, no
  personal usernames, and no hardcoded home paths** (everything resolves from
  `$HOME` and overridable config vars).
- **You bring your own keys.** The repo ships **zero** keys. During one-time
  setup *you* generate `~/.ssh/vm_admin` and `~/.ssh/vm_runner`, and the scripts
  install *your* public halves into the guest. Nobody else's key is ever baked
  in. `.gitignore` blocks key material belt-and-suspenders so a stray key can't
  be committed by accident.
- **`admin` has passwordless (NOPASSWD) sudo — intentionally.** `admin` is a
  *disposable provisioning account* used only to install toolchains and shape
  the baseline; it is wiped with every rollback. The **SSH key is the real
  gate** — without `~/.ssh/vm_admin` you cannot log in as `admin` at all, so a
  sudo password would only guard an account you already had to hold a private
  key to reach. Untrusted code never runs as `admin`; it runs **only** as the
  non-sudo `runner`. If a repo demands `sudo` while running as `runner`, that is
  a finding to investigate, not an instruction to follow.

---

## One-time setup

```bash
# 1. Harden the existing 'ubuntu-vm' (powers it off first; idempotent).
#    Sets nic1 NAT + the SSH port-forward, detaches nic2.
./vm-harden.sh

# 2. Follow the printed NEXT STEPS: boot the VM once, install openssh-server,
#    create the disposable 'admin' (passwordless sudo) and NON-sudo 'runner'
#    accounts, generate your own vm_admin + vm_runner keys, then (from the host)
#    ssh-copy-id YOUR public keys into each account. (vm-harden.sh prints exact
#    commands.)

# 3. Capture the clean baseline every run restores to.
./vm-cycle.sh --snapshot          # add --force to replace an existing one
```

After that, `vm-cycle.sh` (no args) drives every disposable run.

---

## The workflow — vet one repo

```bash
./vm-cycle.sh                     # HOST: restore clean-base, boot, ssh in as runner

# --- inside the VM ---
git clone https://github.com/some/unknown-repo.git    # cloning executes nothing
cd unknown-repo
# install + run the work here, as 'runner', never sudo
exit                              # leave the guest shell

# back on the HOST: the teardown trap fires automatically —
#   acpi power-off -> forced poweroff if needed -> restore 'clean-base'.
# Everything the repo did to the disk is gone. (Anything it sent over the
# network is NOT — see the threat model.)
```

Ctrl-C instead of `exit` triggers the same teardown. The only time the VM is
**not** rolled back is if SSH never comes up: it's left running so you can boot
it with `--type gui` and inspect what's wrong with the `clean-base` snapshot.
