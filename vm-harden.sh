#!/usr/bin/env bash
#
# vm-harden.sh (HOST) — idempotent lockdown of the disposable VM.
#
# Powers the VM off (graceful, then forced) and applies a hardened config:
#   * clipboard + drag-and-drop disabled
#   * ALL shared folders removed
#   * networking: nic1 NAT with a single host->guest SSH port-forward
#   * fixed RAM / CPU count
#   * audio + USB controllers disabled (attack-surface reduction)
#
# Safe to re-run: every change is declarative and reapplied each time.
#
# NOTE on scope: this hardens the host<->guest data channels and pins the SSH
# control path. It does NOT isolate the network — nic1 NAT gives the guest full
# outbound internet by design (that's how the control channel works without any
# guest-side config). The single guarantee is host-filesystem isolation +
# disposable rollback. See the README threat model.
#
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/config.sh
source "${SCRIPT_DIR}/lib/config.sh"

require_vboxmanage
require_vm_exists

log "Current VM state: $(vm_state)"
ensure_powered_off   # modifyvm requires the VM to be powered off

log "Applying hardened configuration to '${VM_NAME}'..."

# --- Host <-> guest data channels: off ---
VBoxManage modifyvm "${VM_NAME}" --clipboard-mode disabled
VBoxManage modifyvm "${VM_NAME}" --draganddrop disabled
ok "Clipboard + drag-and-drop disabled."

# --- Remove ALL shared folders (read state first, then act) ---
mapfile -t _shares < <(
  VBoxManage showvminfo "${VM_NAME}" --machinereadable \
    | sed -n 's/^SharedFolderNameMachineMapping[0-9]*="\(.*\)"$/\1/p'
)
if [ "${#_shares[@]}" -eq 0 ]; then
  ok "No shared folders present."
else
  for _sf in "${_shares[@]}"; do
    [ -n "${_sf}" ] || continue
    log "Removing shared folder: ${_sf}"
    VBoxManage sharedfolder remove "${VM_NAME}" --name "${_sf}" 2>/dev/null || true
  done
  ok "Shared folders removed."
fi

# --- Networking: nic1 NAT + a single SSH port-forward (idempotent) ---
# NAT needs no guest-side network config (Ubuntu DHCPs the NAT NIC on its own),
# so the host->guest SSH path survives reboots and snapshot restores without any
# in-guest static IP / netplan. nic2 is left detached: a single NIC is all the
# control channel needs, and fewer NICs is less surface.
VBoxManage modifyvm "${VM_NAME}" --nic1 nat
VBoxManage modifyvm "${VM_NAME}" --nic2 none

# Clear ANY existing nic1 forward occupying the host SSH port, regardless of its
# rule name (read the current rules first, then act), so we never collide on the
# host port when we re-add ours.
mapfile -t _portfwds < <(nic1_ssh_forwards)
for _fwd in "${_portfwds[@]}"; do
  [ -n "${_fwd}" ] || continue
  log "Removing conflicting NAT forward '${_fwd}' (host port ${HOST_SSH_PORT})"
  VBoxManage modifyvm "${VM_NAME}" --natpf1 delete "${_fwd}" 2>/dev/null || true
done

VBoxManage modifyvm "${VM_NAME}" \
  --natpf1 "${SSH_RULE_NAME},tcp,${HOST_SSH_ADDR},${HOST_SSH_PORT},,${GUEST_SSH_PORT}"
ok "nic1=nat, forward ${HOST_SSH_ADDR}:${HOST_SSH_PORT} -> guest:${GUEST_SSH_PORT} (rule '${SSH_RULE_NAME}')."

# --- Resources ---
VBoxManage modifyvm "${VM_NAME}" --memory "${VM_MEMORY_MB}" --cpus "${VM_CPUS}"
ok "memory=${VM_MEMORY_MB}MB, cpus=${VM_CPUS}."

# --- Attack-surface reduction: audio + USB off (flag name varies by VBox ver) ---
VBoxManage modifyvm "${VM_NAME}" --audio-enabled off 2>/dev/null \
  || VBoxManage modifyvm "${VM_NAME}" --audio none 2>/dev/null \
  || warn "Could not disable audio (non-fatal)."
VBoxManage modifyvm "${VM_NAME}" --usb-ehci off 2>/dev/null || true
VBoxManage modifyvm "${VM_NAME}" --usb-xhci off 2>/dev/null || true
VBoxManage modifyvm "${VM_NAME}" --usb-ohci off 2>/dev/null || true
ok "Audio + USB controllers disabled."

ok "Hardening complete for '${VM_NAME}'."

cat >&2 <<EOF

----------------------------------------------------------------------
NEXT STEPS (one-time guest setup, then snapshot)
----------------------------------------------------------------------
The guest still needs an SSH server and an UNPRIVILEGED 'runner' user
before the snapshot. Do this once:

  1. Boot the VM with a console so you can log in:
         VBoxManage startvm "${VM_NAME}" --type gui
     (or --type separate / --type headless + the VirtualBox UI)

  2. Inside the guest, as your existing admin user, run:
         sudo apt-get update
         sudo apt-get install -y openssh-server
         sudo systemctl enable --now ssh

         # Create a NON-sudo user to run untrusted code as:
         sudo adduser --disabled-password --gecos "" ${RUNNER_USER}
         sudo passwd ${RUNNER_USER}        # set a password for the one-time key install
         # IMPORTANT: do NOT add '${RUNNER_USER}' to the sudo/admin group.

  3. From the HOST, install your VM key for passwordless SSH (one-time; uses the
     password you just set). Generate the key first if you don't have it:
         [ -f ${SSH_KEY} ] || ssh-keygen -t ed25519 -N "" -f ${SSH_KEY}
         ssh-copy-id -i ${SSH_KEY}.pub -p ${HOST_SSH_PORT} \\
             -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
             ${RUNNER_USER}@${HOST_SSH_ADDR}

  4. Verify passwordless, non-interactive SSH from the HOST:
         ssh -i ${SSH_KEY} -p ${HOST_SSH_PORT} -o BatchMode=yes \\
             -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \\
             ${RUNNER_USER}@${HOST_SSH_ADDR} 'echo OK'

  5. Power the guest off cleanly, then capture the clean baseline:
         ./vm-cycle.sh --snapshot

After that, ./vm-cycle.sh (no args) drives each disposable run.
----------------------------------------------------------------------
EOF
