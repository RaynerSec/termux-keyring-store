# termux-keyring-store

A file-based keyring backend for Termux (Android), implementing the
[`keyring-core`](https://crates.io/crates/keyring-core) API.

## Why

Komac and other Rust tools use `keyring-core` to store credentials. On Linux
they rely on D-Bus Secret Service, which is not available in Termux by default.
This crate provides a working backend that stores credentials in an
**AES-256-GCM-SIV** encrypted file under Termux's app data directory.

## Security

AES-256-GCM-SIV is a misuse-resistant authenticated cipher (RFC 8452). Unlike
plain AES-GCM, it retains confidentiality even if a nonce is accidentally
reused, and it provides stronger security bounds against forgery.

That said, the master key is derived via Argon2id from a random salt and an
empty password. This protects against casual inspection of the credential file
but is **not hardware-backed**. A rooted attacker with access to Termux's
private data can still extract secrets.

## Usage

```rust
use keyring_core::Entry;
use termux_keyring_store::Store;

fn main() -> keyring_core::Result<()> {
    let store = Store::new()?;
    let entry = store.build("service", "user", None)?;
    entry.set_password("secret")?;
    println!("{}", entry.get_password()?);
    Ok(())
}
```

## Storage location

```bash
$HOME/.local/share/komac/credentials.enc
```

## License

This project is licensed under the Mozilla Public License v2.0.
