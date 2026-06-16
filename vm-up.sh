#!/usr/bin/env bash
#
# vm-up.sh (HOST) — start a fresh disposable run.
#
# Restores the clean-base snapshot, boots headless, waits for the guest SSH
# daemon, then drops you into an interactive shell as the unprivileged runner.
#
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/config.sh
source "${SCRIPT_DIR}/lib/config.sh"

require_vboxmanage
require_cmd ssh "Install the openssh-client package on the host."
require_vm_exists
require_snapshot   # fail clearly if 'clean-base' is missing

log "Current VM state: $(vm_state)"
ensure_powered_off   # restoring a snapshot requires the VM to be off

log "Restoring snapshot '${SNAPSHOT_NAME}' (discarding any prior run)..."
VBoxManage snapshot "${VM_NAME}" restore "${SNAPSHOT_NAME}"
ok "Snapshot restored."

log "Starting '${VM_NAME}' headless..."
VBoxManage startvm "${VM_NAME}" --type headless

log "Waiting up to ${SSH_WAIT_SECONDS}s for SSH on ${HOST_SSH_ADDR}:${HOST_SSH_PORT}..."
if ! wait_for_ssh; then
  err "SSH never became reachable. The guest may lack openssh-server, or the"
  err "port-forward/runner user is misconfigured. Inspect the console with:"
  err "    VBoxManage startvm ${VM_NAME} --type gui   (after ./vm-down.sh)"
  die "Aborting; VM left running for inspection."
fi
ok "SSH reachable. Opening interactive shell as '${RUNNER_USER}'."
echo >&2

# Hand the terminal to ssh. Host keys are intentionally not persisted: the
# guest identity changes every snapshot restore, so verification is moot here.
exec ssh -p "${HOST_SSH_PORT}" \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  "${RUNNER_USER}@${HOST_SSH_ADDR}"
