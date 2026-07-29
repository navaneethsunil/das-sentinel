# Secret management — SOPS + age (GO-LIVE B2)

File-based secret management with [SOPS](https://github.com/getsops/sops) + age.
Encryption rules live in the repo-root `.sops.yaml`. This plugs into the existing
env-based config: **decrypt to `.env` at deploy time**, which compose already reads
via `env_file` — no app changes. Verified end-to-end (encrypt→decrypt round-trip)
on 2026-07-29.

> **Alternatives.** SOPS+age is the air-gap-friendly default. For a federal ATO you
> may instead inject secrets from **Vault** or a **cloud KMS** at runtime — same
> contract (the app only reads env vars), different source. Pick one; don't mix.

## One-time setup

```bash
brew install sops age                      # or your distro's packages
age-keygen -o ~/.config/sops/age/keys.txt  # prints "Public key: age1..."
```

Put that `age1...` **public** key into `.sops.yaml` (replace the placeholder
recipient). Keep `keys.txt` (the **private** key) on the deploy host / in your KMS —
never in git.

## Create / edit the encrypted secrets

Start from a freshly generated plaintext bundle (GO-LIVE B1), then encrypt:

```bash
sops -e --input-type dotenv --output-type dotenv prod.env > secrets/prod.enc.env
rm prod.env                                # delete the plaintext
```

Edit later in place (decrypts to your $EDITOR, re-encrypts on save):

```bash
sops secrets/prod.enc.env
```

## Deploy

```bash
export SOPS_AGE_KEY_FILE=~/.config/sops/age/keys.txt
sops -d --output-type dotenv secrets/prod.enc.env > .env   # .env is git-ignored
chmod 600 .env
DAS_ENV=prod docker compose up -d
```

`DAS_ENV=prod` fail-closes on placeholder secrets (verified in GO-LIVE B3), so a bad
decrypt or a missing value stops the boot rather than running weak.

## Policy decision: committing the encrypted file

The root `.gitignore` ignores **all of `secrets/`** (M0-SEC2, "never commit
secrets") — a deliberate guard, left intact. So by default the encrypted
`secrets/prod.enc.env` is **not** committed; distribute it out-of-band (KMS, deploy
host). SOPS's ciphertext is safe to commit, so if you *want* it in git, relax that
one line to whitelist only encrypted files — **your call**, since a mis-named
plaintext would then be committable:

```gitignore
# replace `secrets/` with:
secrets/*
!secrets/*.enc.env
```
