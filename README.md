# termux-keyring-store

[![Build & Analyze](https://github.com/rc-chuah/termux-keyring-store/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/rc-chuah/termux-keyring-store/actions/workflows/build.yml)
[![Crates.io Version](https://img.shields.io/crates/v/termux-keyring-store.svg)](https://crates.io/crates/termux-keyring-store)
[![Crates.io Downloads](https://img.shields.io/crates/d/termux-keyring-store.svg)](https://crates.io/crates/termux-keyring-store)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

A hardened, file-based keyring backend for Termux (Android) implementing [`keyring-core`](https://crates.io/crates/keyring-core) v1.0.1 with an authenticated **v2 vault format** (Argon2id + HKDF-SHA256 + BLAKE3 + AES-256-GCM-SIV).

## Why

Komac and other Rust tools use `keyring-core` to store credentials. On Linux they rely on D-Bus Secret Service, which is not available in Termux by default. This crate provides a hardened backend that stores credentials in an **AES-256-GCM-SIV** encrypted file under Termux's app data directory.

## Security Architecture (v2 Vault Format)

- **Key Derivation (Argon2id + HKDF-SHA256):** Derives a 256-bit master secret from a 32-byte random salt (`64 MiB` memory, `3` iterations, `4` lanes), then expands two domain-separated subkeys using HKDF-SHA256—one encryption key (`Aes256GcmSiv`) and one header authentication key (`BLAKE3`).
- **Authenticated Header & Anti-Rollback Protection:** Computes a keyed BLAKE3 MAC over the format version (`v2`), Argon2 cost parameters, salt, monotonic write counter, nonce, and ciphertext, verified in constant time (`subtle::ConstantTimeEq`) before decryption. Rejects any tampered header or rolled-back vault state.
- **Per-Entry AES-256-GCM-SIV with AAD:** Encrypts each credential individually with a fresh 96-bit random nonce and binds `service\0user` as Additional Authenticated Data (AAD) to prevent entry-swapping attacks.
- **Memory Zeroization:** Wraps derived keys, passphrases, and plaintext buffers in `Zeroizing<T>` so sensitive material is scrubbed from RAM immediately on drop.
- **Hardened File Storage:** Enforces `0700` directory and `0600` file permissions on Unix/Android, rejects symlinks, and uses `sync_all()` + atomic renames (`credentials.enc.tmp`) to prevent partial writes or corruption.

> **Threat Model Note:** When `TERMUX_KEYRING_PASSPHRASE` is unset, `Store::new()` uses an empty passphrase by default for seamless non-interactive CLI usage. This protects against casual inspection of the credential file, though a rooted attacker with access to Termux's private data directory can still extract secrets unless `TERMUX_KEYRING_PASSPHRASE` or `Store::with_passphrase` is used.

## Installation

Install via Cargo:

```bash
cargo add termux-keyring-store keyring-core
```

Or add `termux-keyring-store` and `keyring-core` to your `Cargo.toml`:

```toml
[dependencies]
keyring-core = "1.0.1"
termux-keyring-store = "0.1.0"
```

## Usage

### Default Store (`TERMUX_KEYRING_PASSPHRASE` or Empty Passphrase)

`Store::new()` reads `TERMUX_KEYRING_PASSPHRASE` from the environment if set (falling back to an empty passphrase when unset) and stores credentials at `$HOME/.local/share/komac/credentials.enc`:

```rust
use keyring_core::Entry;
use termux_keyring_store::Store;

fn main() -> keyring_core::Result<()> {
    let store = Store::new()?;
    keyring_core::set_default_store(store);

    let entry = Entry::new("my-service", "my-user")?;
    entry.set_password("super-secret-token")?;
    assert_eq!(entry.get_password()?, "super-secret-token");
    entry.delete_credential()?;
    Ok(())
}
```

### Custom Passphrase and/or Custom Vault Path

```rust
use termux_keyring_store::Store;

// Explicit passphrase at default vault location
let store = Store::with_passphrase("my-strong-master-passphrase")?;

// Custom vault path (reads TERMUX_KEYRING_PASSPHRASE if set)
let custom_store = Store::with_path("/data/data/com.termux/files/home/.vault/creds.enc")?;

// Custom vault path + explicit passphrase
let full_custom = Store::with_path_and_passphrase(
    "/data/data/com.termux/files/home/.vault/creds.enc",
    "my-strong-master-passphrase",
)?;
```

## Storage Location

- **Default path:** `$HOME/.local/share/komac/credentials.enc`
- **Directory permissions:** `0700` (owner read/write/execute only)
- **Vault file permissions:** `0600` (owner read/write only)

## License

Licensed under the [Mozilla Public License v2.0](https://github.com/rc-chuah/termux-keyring-store/blob/main/LICENSE).
