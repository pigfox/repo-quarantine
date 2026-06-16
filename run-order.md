# run-order.md — the safe operator sequence

The golden rule: **cloning executes nothing; installing executes everything.**
Almost all "Contagious Interview" / supply-chain traps fire during the install
step (lifecycle scripts, `build.rs`, `setup.py`). So we **scan before install,
install with hooks disarmed, then scan again** — all inside the disposable VM as
the non-sudo `runner` user.

Everything below runs **inside the VM** unless marked `(HOST)`.

---

## 0. Start a clean VM (HOST)

```bash
./vm-up.sh            # restore clean-base, boot headless, ssh in as runner
```

Copy the scanner in if it is not baked into the snapshot (HOST, another terminal):

```bash
scp -P 2222 scan.sh runner@127.0.0.1:/home/runner/
```

## 1. Clone — executes nothing

```bash
cd ~ && git clone https://github.com/<owner>/<repo>.git
cd <repo>
```

## 2. Scan BEFORE install

```bash
~/scan.sh .            # exit 0 clean / 1 flags / 2 bad config
```

Read `/tmp/malware-scan-*.log`. Flags are leads, not verdicts.

## 3. Read the install hooks BY HAND

Open these yourself before installing anything — do not trust a clean scan:

- **PHP/Laravel**: `composer.json` → `scripts` (`post-install-cmd`,
  `post-update-cmd`, `post-autoload-dump`, `pre-*`).
- **Node**: `package.json` → `scripts` (`preinstall`, `install`, `postinstall`,
  `prepare`).
- **Rust**: every `build.rs`, and `Cargo.toml` for `git =`/path deps.
- **Python**: `setup.py`, `pyproject.toml` `[build-system]`.
- **Web3**: `foundry.toml`, `hardhat.config.*` plugins; any script targeting a
  **mainnet** RPC or reading a private key / mnemonic / keystore / `.env`.

## 4. Install with scripts BLOCKED

| Stack            | Disarmed install command |
|------------------|--------------------------|
| PHP / Composer   | `composer install --no-scripts --no-plugins` |
| Node / npm       | `npm install --ignore-scripts` |
| Node / yarn      | `yarn install --ignore-scripts` |
| Node / pnpm      | `pnpm install --ignore-scripts` |
| Rust / Cargo     | **read every `build.rs` first**, then `cargo build` |
| Python / pip     | `pip install --no-build-isolation` only after reading `setup.py`; prefer wheels |

## 5. Scan AGAIN (post-install)

Dependencies just landed on disk. Re-scan the now-populated tree:

```bash
~/scan.sh .
```

This catches malicious code that lives in `vendor/`, `node_modules/`,
`target/`, or `site-packages/` rather than in the repo itself.

## 6. Only now — run the app

Example for the Laravel hiring-challenge target:

```bash
cp .env.example .env          # NEVER put real secrets/keys in the VM
php artisan key:generate
php artisan migrate            # use sqlite/local db inside the VM
php artisan test
```

For Web3 repos: **testnet only**, throwaway keys, never a funded mainnet wallet.

## 7. Tear down — wipe the run (HOST)

```bash
exit                  # leave the ssh session
./vm-down.sh          # power off + restore clean-base (discards everything)
```

The next `./vm-up.sh` is pristine again. Nothing the repo did survives.
