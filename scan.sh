#!/usr/bin/env bash
#
# scan.sh — language-agnostic static malware/risk scanner for an untrusted repo.
#
# Runs equally on the HOST or INSIDE the disposable VM. It only READS files and
# git history; it never installs dependencies or executes repo code.
#
# Usage:   ./scan.sh [TARGET_DIR]        (default: current directory)
# Report:  /tmp/malware-scan-<timestamp>.log
# Exit:    0 = clean    1 = findings    2 = bad config / unusable target
#
# Self-skips any scanner that is not installed. A FLAG means "look here by
# hand" — this tool flags, it does not clear. See README.md.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Config block — thresholds and tunables (override via environment).
# ---------------------------------------------------------------------------
ENTROPY_THRESHOLD="${ENTROPY_THRESHOLD:-7.0}"   # bits/byte; >= flags a binary
MAX_HITS_PER_RULE="${MAX_HITS_PER_RULE:-40}"    # lines of context per finding
MAX_BINARIES="${MAX_BINARIES:-200}"             # cap entropy/file work
RULES_DIR="${RULES_DIR:-}"                       # YARA rules dir (auto-detected)
TRIVY_SEVERITY="${TRIVY_SEVERITY:-HIGH,CRITICAL}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[ -n "${RULES_DIR}" ] || RULES_DIR="${SCRIPT_DIR}/rules"

TARGET="${1:-$PWD}"
TS="$(date +%Y%m%d-%H%M%S)"
REPORT="/tmp/malware-scan-${TS}.log"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_B=$'\033[1;34m'; C_G=$'\033[1;32m'; C_Y=$'\033[1;33m'; C_R=$'\033[1;31m'; C_X=$'\033[0m'
else
  C_B=''; C_G=''; C_Y=''; C_R=''; C_X=''
fi
FINDINGS=0

say()     { printf '%s\n' "$*" >&2; }
section() { printf '\n=== %s ===\n' "$1" >>"${REPORT}"; printf '%s[*]%s %s\n' "$C_B" "$C_X" "$1" >&2; }
note()    { printf '    %s\n' "$*" >>"${REPORT}"; }
skip()    { printf '    [SKIP] %s\n' "$*" >>"${REPORT}"; printf '%s[skip]%s %s\n' "$C_Y" "$C_X" "$*" >&2; }
flag()    { printf '    [FLAG] %s\n' "$*" >>"${REPORT}"; printf '%s[FLAG]%s %s\n' "$C_R" "$C_X" "$*" >&2; FINDINGS=$((FINDINGS+1)); }
emit()    { sed "s/^/        /" >>"${REPORT}"; }   # indent captured detail

have()       { command -v "$1" >/dev/null 2>&1; }
is_git_repo(){ git -C "${TARGET}" rev-parse --is-inside-work-tree >/dev/null 2>&1; }

# Recursive grep that never trips `set -e` and skips .git + binaries.
rgrep() {
  grep -rInE --binary-files=without-match \
    --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=vendor \
    "$@" "${TARGET}" 2>/dev/null || true
}

# grep_rule LABEL PATTERN — flag if the pattern appears anywhere in the tree.
grep_rule() {
  local label="$1" pattern="$2" hits
  hits="$(rgrep "${pattern}")"
  if [ -n "${hits}" ]; then
    flag "${label}"
    printf '%s\n' "${hits}" | head -n "${MAX_HITS_PER_RULE}" | emit
  else
    note "${label}: none"
  fi
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
if [ ! -d "${TARGET}" ]; then
  printf '%s[x]%s TARGET is not a directory: %s\n' "$C_R" "$C_X" "${TARGET}" >&2
  exit 2
fi
TARGET="$(cd -- "${TARGET}" && pwd)"   # normalize to absolute

{
  printf 'safely-run-repo scan report\n'
  printf 'target : %s\n' "${TARGET}"
  printf 'host   : %s\n' "$(uname -a 2>/dev/null || echo unknown)"
  printf 'date   : %s\n' "${TS}"
} >"${REPORT}"

say "${C_B}==>${C_X} Scanning ${TARGET}"
say "${C_B}==>${C_X} Report: ${REPORT}"

# ===========================================================================
# 1. ClamAV signature scan
# ===========================================================================
section "ClamAV signature scan"
if have clamdscan || have clamscan; then
  _cs="$(command -v clamdscan || command -v clamscan)"
  if "${_cs}" -ri --no-summary "${TARGET}" >/tmp/clam.$$ 2>&1; then
    note "ClamAV: clean"
  else
    rc=$?
    if [ "${rc}" -eq 1 ]; then
      flag "ClamAV detected known-malware signatures"
      grep -i 'FOUND' /tmp/clam.$$ | head -n "${MAX_HITS_PER_RULE}" | emit
    else
      skip "ClamAV returned error rc=${rc} (db missing / permissions); see report"
      head -n 20 /tmp/clam.$$ | emit
    fi
  fi
  rm -f /tmp/clam.$$
else
  skip "clamscan/clamdscan not installed"
fi

# ===========================================================================
# 2. YARA custom rules (optional)
# ===========================================================================
section "YARA custom rules"
if have yara; then
  mapfile -t _yar < <(find "${RULES_DIR}" -type f \( -name '*.yar' -o -name '*.yara' \) 2>/dev/null)
  if [ "${#_yar[@]}" -eq 0 ]; then
    skip "no rules in ${RULES_DIR} (drop *.yar files there to enable)"
  else
    _yhits=0
    for _r in "${_yar[@]}"; do
      _out="$(yara -r -w "${_r}" "${TARGET}" 2>/dev/null || true)"
      if [ -n "${_out}" ]; then
        _yhits=1
        printf '%s\n' "${_out}" | head -n "${MAX_HITS_PER_RULE}" | emit
      fi
    done
    if [ "${_yhits}" -eq 1 ]; then flag "YARA rules matched (see report)"; else note "YARA: no matches"; fi
  fi
else
  skip "yara not installed"
fi

# ===========================================================================
# 3. Trivy filesystem scan (vuln + secret + misconfig)
# ===========================================================================
section "Trivy fs scan (${TRIVY_SEVERITY})"
if have trivy; then
  if trivy fs --quiet --scanners vuln,secret,misconfig \
       --severity "${TRIVY_SEVERITY}" --exit-code 1 \
       "${TARGET}" >/tmp/trivy.$$ 2>/tmp/trivy.err.$$; then
    note "Trivy: no ${TRIVY_SEVERITY} findings"
  else
    rc=$?
    if [ "${rc}" -eq 1 ]; then
      flag "Trivy found ${TRIVY_SEVERITY} vulns/secrets/misconfigs"
      head -n 120 /tmp/trivy.$$ | emit
    else
      skip "Trivy error rc=${rc} (DB download needs network?); see report"
      head -n 20 /tmp/trivy.err.$$ | emit
    fi
  fi
  rm -f /tmp/trivy.$$ /tmp/trivy.err.$$
else
  skip "trivy not installed"
fi

# ===========================================================================
# 4. Semgrep --config=auto
# ===========================================================================
section "Semgrep (--config=auto)"
if have semgrep; then
  if semgrep scan --config=auto --error --quiet \
       --exclude '.git' "${TARGET}" >/tmp/semgrep.$$ 2>/tmp/semgrep.err.$$; then
    note "Semgrep: no findings"
  else
    rc=$?
    if [ "${rc}" -eq 1 ]; then
      flag "Semgrep reported findings"
      head -n 120 /tmp/semgrep.$$ | emit
    else
      skip "Semgrep error rc=${rc} (registry needs network?); see report"
      head -n 20 /tmp/semgrep.err.$$ | emit
    fi
  fi
  rm -f /tmp/semgrep.$$ /tmp/semgrep.err.$$
else
  skip "semgrep not installed"
fi

# ===========================================================================
# 5. Grep indicators of compromise
# ===========================================================================
section "Indicator grep — obfuscation & shells"
grep_rule "eval(base64_decode / eval(atob obfuscation"  'eval\s*\(\s*(base64_decode|atob|gzinflate|str_rot13)'
grep_rule "reverse-shell /dev/tcp redirection"           '/dev/(tcp|udp)/'
grep_rule "interactive bash reverse shell (bash -i)"     'bash\s+-i'
grep_rule "netcat exec backdoor (nc -e / ncat -e)"       '\bn(c|cat)\b[^\n]*-e\b'
grep_rule "named-pipe reverse shell (mkfifo)"            '\bmkfifo\b'
grep_rule "curl/wget piped to a shell"                   '\b(curl|wget)\b[^|\n]*\|\s*(ba)?sh\b'
# shellcheck disable=SC2016  # literal $HOME is the grep pattern, not a shell var
grep_rule "download into \$HOME"                          '\b(curl|wget)\b[^\n]*\$HOME'

section "Indicator grep — C2 / exfil endpoints"
grep_rule "C2/exfil endpoint (discord/slack/telegram/ngrok/pastebin)" \
  '(discord(app)?\.com/api/webhooks|hooks\.slack\.com|api\.telegram\.org|[a-z0-9-]+\.ngrok(-free)?\.(io|app)|pastebin\.com/raw)'

section "Indicator grep — long base64 blobs"
# 200+ contiguous base64 chars often hides a payload.
_b64="$(rgrep '[A-Za-z0-9+/]{200,}={0,2}')"
if [ -n "${_b64}" ]; then
  flag "Long base64-like blob(s) — possible embedded payload"
  printf '%s\n' "${_b64}" | head -n "${MAX_HITS_PER_RULE}" | emit
else
  note "Long base64 blobs: none"
fi

# ===========================================================================
# 6. Tracked-binary discovery (git ls-files + file)
# ===========================================================================
section "Tracked / committed binaries"
declare -a BIN_FILES=()
if is_git_repo; then
  mapfile -d '' -t _files < <(git -C "${TARGET}" ls-files -z 2>/dev/null || true)
  _src="git-tracked"
else
  mapfile -d '' -t _files < <(find "${TARGET}" -type f -not -path '*/.git/*' -print0 2>/dev/null || true)
  _src="filesystem (not a git repo)"
fi
note "file source: ${_src}; count=${#_files[@]}"
_count=0
for _f in "${_files[@]}"; do
  [ -n "${_f}" ] || continue
  _abs="${_f}"; case "${_f}" in /*) :;; *) _abs="${TARGET}/${_f}";; esac
  [ -f "${_abs}" ] || continue
  if ! LC_ALL=C grep -Iq . "${_abs}" 2>/dev/null; then   # -I: treat as binary if non-text
    BIN_FILES+=("${_abs}")
    note "binary: ${_f} ($(file -b "${_abs}" 2>/dev/null | cut -c1-60))"
    _count=$((_count+1))
    [ "${_count}" -ge "${MAX_BINARIES}" ] && { note "...(capped at ${MAX_BINARIES})"; break; }
  fi
done
if [ "${#BIN_FILES[@]}" -gt 0 ]; then
  flag "${#BIN_FILES[@]} committed binary file(s) — review why source repo ships binaries"
else
  note "No committed binaries detected"
fi

# ===========================================================================
# 7. Shannon entropy on binaries (> threshold => packed/encrypted)
# ===========================================================================
section "Shannon entropy of binaries (flag >= ${ENTROPY_THRESHOLD})"
if have python3; then
  if [ "${#BIN_FILES[@]}" -eq 0 ]; then
    note "no binaries to measure"
  else
    _hi=0
    for _bf in "${BIN_FILES[@]}"; do
      _H="$(python3 - "${_bf}" <<'PY' 2>/dev/null || true
import sys, math
from collections import Counter
try:
    d = open(sys.argv[1], "rb").read(1 << 20)
except Exception:
    print("0.0"); sys.exit(0)
if not d:
    print("0.0"); sys.exit(0)
n = len(d); c = Counter(d)
print(f"{-sum((v/n)*math.log2(v/n) for v in c.values()):.3f}")
PY
)"
      awk -v h="${_H}" -v t="${ENTROPY_THRESHOLD}" 'BEGIN{exit !(h+0 >= t+0)}' && {
        _hi=1; note "HIGH entropy ${_H}: ${_bf#"${TARGET}"/}"
      }
    done
    if [ "${_hi}" -eq 1 ]; then
      flag "High-entropy binaries (packed/encrypted?) — see report"
    else
      note "no binaries at/above ${ENTROPY_THRESHOLD}"
    fi
  fi
else
  skip "python3 not installed (needed for entropy)"
fi

# ===========================================================================
# 8. Git history forensics
# ===========================================================================
section "Git history forensics"
if is_git_repo; then
  _lock="$(git -C "${TARGET}" log --oneline --no-merges -- \
            '*.lock' package-lock.json composer.lock Cargo.lock yarn.lock \
            pnpm-lock.yaml poetry.lock 2>/dev/null | head -n 40 || true)"
  if [ -n "${_lock}" ]; then
    note "commits touching lockfiles (inspect for dependency swaps):"
    printf '%s\n' "${_lock}" | emit
  else
    note "no lockfile-touching commits found"
  fi
  for _needle in 'child_process' 'eval(' 'base64_decode' '/dev/tcp' 'webhook' 'private_key' 'mnemonic'; do
    _h="$(git -C "${TARGET}" log --oneline -S"${_needle}" 2>/dev/null | head -n 10 || true)"
    if [ -n "${_h}" ]; then
      flag "git history adds/removes '${_needle}' (possibly scrubbed later)"
      printf '%s\n' "${_h}" | emit
    fi
  done
else
  skip "not a git repository"
fi

# ===========================================================================
# 9. npm pre/postinstall hook audit
# ===========================================================================
section "npm install-hook audit (package.json scripts)"
mapfile -d '' -t _pkgs < <(find "${TARGET}" -name package.json -not -path '*/node_modules/*' -print0 2>/dev/null || true)
if [ "${#_pkgs[@]}" -eq 0 ]; then
  note "no package.json found"
else
  _npm=0
  for _p in "${_pkgs[@]}"; do
    _s="$(grep -nE '"(pre|post)?install"\s*:|"prepare"\s*:|"prepublish"\s*:' "${_p}" 2>/dev/null || true)"
    if [ -n "${_s}" ]; then
      _npm=1
      note "${_p#"${TARGET}"/}:"; printf '%s\n' "${_s}" | emit
    fi
  done
  if [ "${_npm}" -eq 1 ]; then
    flag "npm lifecycle hooks present — install with --ignore-scripts"
  else
    note "no install/prepare lifecycle scripts"
  fi
fi

# ===========================================================================
# 10. Composer script-hook audit
# ===========================================================================
section "Composer script-hook audit (composer.json)"
mapfile -d '' -t _comp < <(find "${TARGET}" -name composer.json -not -path '*/vendor/*' -print0 2>/dev/null || true)
if [ "${#_comp[@]}" -eq 0 ]; then
  note "no composer.json found"
else
  _ch=0
  for _c in "${_comp[@]}"; do
    _s="$(grep -nE 'post-install-cmd|post-update-cmd|post-autoload-dump|pre-install-cmd|pre-update-cmd|"scripts"' "${_c}" 2>/dev/null || true)"
    if [ -n "${_s}" ]; then
      _ch=1
      note "${_c#"${TARGET}"/}:"; printf '%s\n' "${_s}" | emit
    fi
  done
  if [ "${_ch}" -eq 1 ]; then
    flag "Composer script hooks present — install with --no-scripts --no-plugins"
  else
    note "no composer script hooks"
  fi
fi

# ===========================================================================
# 11. PHP dangerous-sink scan
# ===========================================================================
section "PHP dangerous sinks"
grep_rule "PHP code-exec sinks (eval/exec/system/proc_open/passthru/shell_exec)" \
  '\b(eval|exec|system|shell_exec|proc_open|passthru|popen|pcntl_exec)\s*\('
# shellcheck disable=SC2016  # backtick + literal $ form the grep pattern
grep_rule "PHP backtick shell execution" '`[^`]*\$'
grep_rule "PHP remote file_get_contents(http...)" 'file_get_contents\s*\(\s*["'\'']https?://'
grep_rule "PHP dynamic include of remote/variable" '\b(include|require)(_once)?\s*\(\s*\$'

# ===========================================================================
# 12. Rust / Cargo
# ===========================================================================
section "Rust / Cargo audit"
mapfile -d '' -t _buildrs < <(find "${TARGET}" -name build.rs -not -path '*/target/*' -print0 2>/dev/null || true)
if [ "${#_buildrs[@]}" -gt 0 ]; then
  flag "build.rs present — runs arbitrary code at 'cargo build'; READ before building"
  for _b in "${_buildrs[@]}"; do note "build.rs: ${_b#"${TARGET}"/}"; done
else
  note "no build.rs"
fi
mapfile -d '' -t _cargo < <(find "${TARGET}" -name Cargo.toml -not -path '*/target/*' -print0 2>/dev/null || true)
if [ "${#_cargo[@]}" -gt 0 ]; then
  note "Cargo.toml found: ${#_cargo[@]}; suggest 'cargo audit' (cargo install cargo-audit)"
  for _c in "${_cargo[@]}"; do
    # typosquats of popular web3 crates
    _t="$(grep -nE '^\s*(ethers[-_]|web3[-_]|sol(ana)?[-_]|anchor[-_]|alloy[-_])' "${_c}" 2>/dev/null || true)"
    [ -n "${_t}" ] && { note "${_c#"${TARGET}"/} crypto-crate deps (verify exact names):"; printf '%s\n' "${_t}" | emit; }
    _g="$(grep -nE 'git\s*=\s*["'\'']https?://' "${_c}" 2>/dev/null || true)"
    [ -n "${_g}" ] && { flag "Cargo.toml git-sourced dependency (not crates.io) in ${_c#"${TARGET}"/}"; printf '%s\n' "${_g}" | emit; }
  done
else
  note "no Cargo.toml"
fi

# ===========================================================================
# 13. Python build hooks
# ===========================================================================
section "Python build-hook audit"
if find "${TARGET}" -name setup.py -not -path '*/.git/*' 2>/dev/null | grep -q .; then
  flag "setup.py present — executes at 'pip install'; READ before installing"
  rgrep 'subprocess|os\.system|os\.popen|exec\(|eval\(|__import__|urllib|requests\.' \
    | grep -i 'setup.py' | head -n "${MAX_HITS_PER_RULE}" | emit || true
else
  note "no setup.py"
fi
if find "${TARGET}" -name pyproject.toml -not -path '*/.git/*' 2>/dev/null | grep -q .; then
  note "pyproject.toml present; check [build-system] / custom build backends"
  _pb="$(rgrep 'build-backend\s*=' | head -n 20)"
  [ -n "${_pb}" ] && printf '%s\n' "${_pb}" | emit
else
  note "no pyproject.toml"
fi

# ===========================================================================
# 14. Crypto / Web3 specific risks
# ===========================================================================
section "Crypto / Web3 — config & key-theft indicators"
# Foundry / Hardhat config + plugin hooks
if find "${TARGET}" \( -name foundry.toml -o -name hardhat.config.js -o -name hardhat.config.ts \) \
     -not -path '*/node_modules/*' 2>/dev/null | grep -q .; then
  note "Foundry/Hardhat config present — review plugins & network RPC settings"
  grep_rule "Hardhat/Foundry script hitting a MAINNET RPC URL" \
    '(mainnet|ethereum|polygon|arbitrum|optimism|base)[^\n]*\.(infura|alchemy(api)?|quiknode|ankr)\.(io|com|net)'
fi
grep_rule "Reads PRIVATE KEY / seed / mnemonic from code" \
  '\b(private[_-]?key|priv[_-]?key|secret[_-]?key|mnemonic|seed[_-]?phrase)\b'
grep_rule "Reference to wallet keystore / MetaMask / .env secrets" \
  '(keystore|UTC--[0-9]|MetaMask|\.config/Solana|id\.json|\.env\.local)'
grep_rule "process.env private key usage (JS/TS)" \
  'process\.env\.[A-Z_]*(PRIVATE_KEY|MNEMONIC|SECRET)'
# Presence-only check for high-value secret files anywhere in the tree.
section "Crypto / Web3 — sensitive file PRESENCE (not contents)"
_present=0
while IFS= read -r _sf; do
  [ -n "${_sf}" ] || continue
  _present=1; note "PRESENT: ${_sf#"${TARGET}"/}"
done < <(find "${TARGET}" -not -path '*/.git/*' \( \
            -name '.env' -o -name '.env.*' -o -name 'id.json' \
            -o -name '*.keystore' -o -name 'keystore' -o -iname 'wallet*.json' \
            -o -name '*.pem' -o -name '*.key' \) 2>/dev/null)
if [ "${_present}" -eq 1 ]; then
  flag "Secret-bearing files present in repo (contents NOT shown) — handle off-VM"
else
  note "no obvious secret files committed"
fi

# ===========================================================================
# 15. Dependency-confusion / typosquatting across ecosystems
# ===========================================================================
section "Dependency-confusion / typosquatting"
if have python3; then
  # Collect declared dependency names from manifests, then fuzzy-match against
  # a curated set of popular (frequently squatted) packages.
  {
    # npm
    for _p in "${_pkgs[@]:-}"; do [ -n "${_p:-}" ] && grep -oE '"@?[a-z0-9._/-]+"\s*:\s*"[^"]+"' "${_p}" 2>/dev/null | sed -E 's/"([^"]+)".*/\1/'; done
    # crates
    for _c in "${_cargo[@]:-}"; do [ -n "${_c:-}" ] && grep -oE '^\s*[a-zA-Z0-9_-]+\s*=' "${_c}" 2>/dev/null | tr -d ' ='; done
    # pip
    find "${TARGET}" \( -name 'requirements*.txt' -o -name 'Pipfile' \) -not -path '*/.git/*' -print0 2>/dev/null \
      | xargs -0 -r grep -hoE '^[a-zA-Z0-9._-]+' 2>/dev/null
  } 2>/dev/null | sort -u > /tmp/deps.$$ || true

  _sq="$(python3 - "/tmp/deps.$$" <<'PY' 2>/dev/null || true
import sys, difflib
legit = ["ethers","web3","hardhat","@openzeppelin/contracts","@solana/web3.js",
         "solana-web3","anchor","wagmi","viem","truffle","ganache","web3.js",
         "requests","numpy","pandas","cryptography","eth-account","web3py",
         "express","axios","lodash","react","dotenv","chalk","colors","left-pad"]
names = [l.strip() for l in open(sys.argv[1]) if l.strip()]
for n in names:
    base = n.split("/")[-1].lower()
    if n in legit or base in legit:
        continue
    m = difflib.get_close_matches(base, legit, n=1, cutoff=0.82)
    if m and base != m[0]:
        print(f"{n}  ~looks-like~  {m[0]}")
PY
)"
  if [ -n "${_sq}" ]; then
    flag "Possible typosquatted dependency names (verify each against the official registry)"
    printf '%s\n' "${_sq}" | head -n "${MAX_HITS_PER_RULE}" | emit
  else
    note "no obvious typosquats among declared deps"
  fi
  rm -f /tmp/deps.$$
else
  skip "python3 not installed (needed for fuzzy typosquat match)"
fi

# ===========================================================================
# Summary
# ===========================================================================
{
  printf '\n=== SUMMARY ===\n'
  printf 'FLAGS: %s\n' "${FINDINGS}"
} >>"${REPORT}"

say ""
if [ "${FINDINGS}" -eq 0 ]; then
  say "${C_G}==> CLEAN: 0 flags.${C_X} (A clean scan does not PROVE safety.)"
  say "    Report: ${REPORT}"
  exit 0
else
  say "${C_R}==> ${FINDINGS} FLAG(S) raised — review by hand before installing/running.${C_X}"
  say "    Report: ${REPORT}"
  exit 1
fi
