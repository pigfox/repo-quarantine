#!/usr/bin/env bash
#
# vm-down.sh (HOST) — end a run and wipe it.
#
# Powers the VM off (graceful ACPI, then forced) and restores the clean-base
# snapshot, discarding everything the untrusted repo did this session.
#
#   --destroy   Instead of restoring, UNREGISTER and DELETE the VM and all its
#               disks. Irreversible. Use only when you are done with this VM.
#
set -euo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/config.sh
source "${SCRIPT_DIR}/lib/config.sh"

DESTROY=0
usage() { sed -n '2,14p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

for arg in "$@"; do
  case "${arg}" in
    --destroy) DESTROY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: ${arg} (try --help)" ;;
  esac
done

require_vboxmanage
require_vm_exists

log "Current VM state: $(vm_state)"
ensure_powered_off

if [ "${DESTROY}" -eq 1 ]; then
  warn "About to UNREGISTER and DELETE '${VM_NAME}' and all of its disks."
  warn "This is irreversible."
  printf 'Type the VM name to confirm: ' >&2
  read -r _confirm
  [ "${_confirm}" = "${VM_NAME}" ] || die "Confirmation did not match; aborting."
  VBoxManage unregistervm "${VM_NAME}" --delete
  ok "VM '${VM_NAME}' destroyed."
  exit 0
fi

# Default: restore clean-base, wiping this run.
if ! snapshot_exists; then
  warn "Snapshot '${SNAPSHOT_NAME}' is missing; cannot restore."
  warn "VM is powered off but its current disk state is UNCHANGED (not wiped)."
  die "Create the baseline with ./snapshot-base.sh, or re-run with --destroy."
fi

log "Restoring '${SNAPSHOT_NAME}' (wiping this run)..."
VBoxManage snapshot "${VM_NAME}" restore "${SNAPSHOT_NAME}"
ok "Run wiped. '${VM_NAME}' is back at '${SNAPSHOT_NAME}' and powered off."
