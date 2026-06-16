#!/usr/bin/env bash
#
# snapshot-base.sh (HOST) — capture the clean baseline.
#
# Powers the VM off cleanly and takes the 'clean-base' snapshot that every run
# is restored to. Refuses to clobber an existing baseline unless --force.
#
#   --force   Delete an existing 'clean-base' snapshot and retake it.
#
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/config.sh
source "${SCRIPT_DIR}/lib/config.sh"

FORCE=0
usage() { sed -n '2,11p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

for arg in "$@"; do
  case "${arg}" in
    --force)   FORCE=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: ${arg} (try --help)" ;;
  esac
done

require_vboxmanage
require_vm_exists

# Read-only guard BEFORE any state change.
if snapshot_exists && [ "${FORCE}" -eq 0 ]; then
  die "Snapshot '${SNAPSHOT_NAME}' already exists. Re-run with --force to replace it."
fi

log "Current VM state: $(vm_state)"
ensure_powered_off

if snapshot_exists && [ "${FORCE}" -eq 1 ]; then
  warn "Deleting existing snapshot '${SNAPSHOT_NAME}' (--force)..."
  VBoxManage snapshot "${VM_NAME}" delete "${SNAPSHOT_NAME}"
fi

log "Taking snapshot '${SNAPSHOT_NAME}'..."
VBoxManage snapshot "${VM_NAME}" take "${SNAPSHOT_NAME}" \
  --description "Clean baseline for safely-run-repo: hardened, openssh-server, non-sudo ${RUNNER_USER}."
ok "Snapshot '${SNAPSHOT_NAME}' captured. Use ./vm-up.sh to start a disposable run."
